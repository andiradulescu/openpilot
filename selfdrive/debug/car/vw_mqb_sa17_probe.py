#!/usr/bin/env python3
"""
Test SecurityAccess L17 (Bootloader) on the 5Q0909143 EPS, then re-run
the $23 / $35 canaries.

Hypothesis: $23 ReadMemoryByAddress and $35 RequestUpload are
auth-gated, not session-gated. $10 4F (Development Session) accepts but
the read services stay NRC 0x11. The icanhack precedent + standard MQB
Bootloader pattern says SA L17 (subfunctions 0x11/0x12) is the typical
unlock for memory-read services.

This script:
  1. Open extended session ($10 03)
  2. $27 0x11 → seed
  3. Compute key via SA2 bytecode (EPS_SA2_BYTECODE from eps_flash.py,
     interpreter inlined from re-vw/sa2_seed_key)
  4. $27 0x12 → key
  5. Canary: $23 22 5E00 0004
  6. Canary: $35 00 11 70 0004
  7. Print verdict

Run from comma three with openpilot stopped.
"""

import argparse
import struct
import sys
import time
from collections import deque

from opendbc.car.uds import (
    UdsClient,
    SESSION_TYPE,
    NegativeResponseError,
)
from opendbc.car.structs import CarParams
from panda import Panda


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
DEFAULT_BUS = 1

# SA2 bytecode for 5Q0909143P SW2051 — extracted from ODX SECURITY block.
# Same constant as eps_flash.py:EPS_SA2_BYTECODE.
EPS_SA2_BYTECODE = bytes.fromhex(
    "814A0787376C9A186B058781A9C6736813824A0587982122A6494C"
)

CANARY_READMEM = bytes([0x23, 0x22, 0x5E, 0x00, 0x00, 0x04])
CANARY_UPLOAD  = bytes([0x35, 0x00, 0x11, 0x70, 0x00, 0x04])


# ─── Inlined SA2 bytecode interpreter (from re-vw/sa2_seed_key) ───────────────

class Sa2SeedKey:
    def __init__(self, instruction_tape: bytes, seed: int):
        self.tape = bytes(instruction_tape)
        self.register = seed
        self.carry_flag = 0
        self.ip = 0
        self.for_pointers: deque = deque()
        self.for_iterations: deque = deque()

    def _rsl(self):
        self.carry_flag = self.register & 0x80000000
        self.register = (self.register << 1) & 0xFFFFFFFF
        if self.carry_flag:
            self.register |= 0x1
        self.ip += 1

    def _rsr(self):
        self.carry_flag = self.register & 0x1
        self.register = self.register >> 1
        if self.carry_flag:
            self.register |= 0x80000000
        self.ip += 1

    def _add(self):
        operands = self.tape[self.ip + 1:self.ip + 5]
        v = (operands[0] << 24) | (operands[1] << 16) | (operands[2] << 8) | operands[3]
        out = self.register + v
        self.carry_flag = 1 if out > 0xFFFFFFFF else 0
        self.register = out & 0xFFFFFFFF
        self.ip += 5

    def _sub(self):
        operands = self.tape[self.ip + 1:self.ip + 5]
        v = (operands[0] << 24) | (operands[1] << 16) | (operands[2] << 8) | operands[3]
        out = self.register - v
        self.carry_flag = 1 if out < 0 else 0
        self.register = out & 0xFFFFFFFF
        self.ip += 5

    def _eor(self):
        operands = self.tape[self.ip + 1:self.ip + 5]
        v = (operands[0] << 24) | (operands[1] << 16) | (operands[2] << 8) | operands[3]
        self.register ^= v
        self.ip += 5

    def _for(self):
        self.for_iterations.appendleft(self.tape[self.ip + 1] - 1)
        self.ip += 2
        self.for_pointers.appendleft(self.ip)

    def _next(self):
        if self.for_iterations[0] > 0:
            self.for_iterations[0] -= 1
            self.ip = self.for_pointers[0]
        else:
            self.for_iterations.popleft()
            self.for_pointers.popleft()
            self.ip += 1

    def _bcc(self):
        skip = self.tape[self.ip + 1] + 2
        self.ip += skip if self.carry_flag == 0 else 2

    def _bra(self):
        self.ip += self.tape[self.ip + 1] + 2

    def _finish(self):
        self.ip += 1

    def execute(self) -> int:
        ops = {
            0x81: self._rsl, 0x82: self._rsr, 0x93: self._add, 0x84: self._sub,
            0x87: self._eor, 0x68: self._for, 0x49: self._next, 0x4A: self._bcc,
            0x6B: self._bra, 0x4C: self._finish,
        }
        while self.ip < len(self.tape):
            ops[self.tape[self.ip]]()
        return self.register


# ─── Helpers ──────────────────────────────────────────────────────────────────

def nrc_name(code: int) -> str:
    return {
        0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLengthOrInvalidFormat", 0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError", 0x25: "noResponseFromSubnet",
        0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
        0x36: "exceededNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
        0x70: "uploadDownloadNotAccepted", 0x78: "responsePending",
        0x7E: "subFunctionNotSupportedInActiveSession",
        0x7F: "serviceNotSupportedInActiveSession",
    }.get(code, f"unknown(0x{code:02X})")


def can_drain(panda: Panda) -> None:
    deadline = time.time() + 0.05
    while time.time() < deadline:
        if not panda.can_recv():
            break


def raw_uds_request(panda: Panda, bus: int, payload: bytes,
                    timeout: float = 0.5) -> bytes | None:
    """Single-frame ISO-TP only. Returns response bytes (no PCI), or None on timeout."""
    if len(payload) > 7:
        raise ValueError("payload too long for single-frame")
    can_drain(panda)
    frame = bytes([len(payload)]) + payload + b"\x00" * (7 - len(payload))
    panda.can_send(MQB_EPS_TX, frame, bus)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for addr, data, src in panda.can_recv():
            if addr == MQB_EPS_RX and src == bus and len(data) >= 1:
                pci = data[0] >> 4
                if pci == 0x0:
                    n = data[0] & 0x0F
                    return bytes(data[1:1 + n])
        time.sleep(0.005)
    return None


def decode(req_sid: int, resp: bytes | None) -> tuple[str, str]:
    if resp is None:
        return "no-response", "(timeout)"
    if len(resp) >= 1 and resp[0] == req_sid + 0x40:
        return "positive", resp.hex()
    if len(resp) >= 3 and resp[0] == 0x7F and resp[1] == req_sid:
        return "nrc", f"0x{resp[2]:02X} {nrc_name(resp[2])}"
    return "nrc", f"unexpected: {resp.hex()}"


# ─── Main flow ────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--bus", type=int, default=DEFAULT_BUS, choices=(0, 1, 2))
    p.add_argument("--level", type=lambda s: int(s, 0), default=0x11,
                   help="SA request_seed level (default 0x11 = L17 Bootloader). "
                        "Try 0x05 / 0x07 / 0x13 etc to probe other levels.")
    args = p.parse_args()

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    panda.can_clear(0xFFFF)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, args.bus, timeout=0.3)

    print(f"Started: {time.strftime('%Y-%m-%dT%H:%M:%S')}")
    print(f"Using bus {args.bus}; SA level 0x{args.level:02X} (send_key=0x{args.level+1:02X})")

    print("\n──── Open extended session ($10 03) ────")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception as e:
        sys.exit(f"extended session failed: {e}")
    print("  ✓ extended session")

    print(f"\n──── SA L{(args.level - 1) // 2 + 1} request_seed (subfunction 0x{args.level:02X}) ────")
    try:
        seed = uds.security_access(args.level)
    except NegativeResponseError as e:
        print(f"  ✗ request_seed rejected: {e}")
        if "0x12" in str(e) or "subFunction" in str(e):
            print("  → SA level not supported on this firmware.")
        return 1
    except Exception as e:
        sys.exit(f"request_seed failed: {e}")
    print(f"  ✓ seed = {seed.hex()}")

    if all(b == 0 for b in seed):
        print("  seed is all zeros — already authenticated at this level.")
    else:
        seed_int = int.from_bytes(seed, "big")
        try:
            key_int = Sa2SeedKey(EPS_SA2_BYTECODE, seed_int).execute()
        except Exception as e:
            sys.exit(f"SA2 interpreter failed: {e}")
        key = key_int.to_bytes(len(seed), "big")
        print(f"  computed key = {key.hex()}")

        print(f"\n──── SA send_key (subfunction 0x{args.level + 1:02X}) ────")
        try:
            uds.security_access(args.level + 1, key)
        except NegativeResponseError as e:
            print(f"  ✗ send_key rejected: {e}")
            print("  → SA2 algorithm or key didn't match what the EPS expected.")
            return 2
        except Exception as e:
            sys.exit(f"send_key failed: {e}")
        print("  ✓ authenticated")

    print("\n──── Canary $23 22 5E00 0004 ────")
    r23 = raw_uds_request(panda, args.bus, CANARY_READMEM)
    k23, d23 = decode(0x23, r23)
    print(f"  $23 → {k23}: {d23}")

    print("\n──── Canary $35 00 11 70 0004 ────")
    r35 = raw_uds_request(panda, args.bus, CANARY_UPLOAD)
    k35, d35 = decode(0x35, r35)
    print(f"  $35 → {k35}: {d35}")

    print("\n══════════════════════════════════════════════════════════════════════")
    if k23 == "positive" or (k23 == "nrc" and d23.startswith("0x31")):
        print(f"VERDICT: $23 OPEN under SA L{(args.level - 1) // 2 + 1}")
        print("══════════════════════════════════════════════════════════════════════")
        print("  → write vw_mqb_uds_dump.py using $23 24 ADDR LEN to bulk-read.")
        print("  → priority targets: 0x5E000+0x2000 (master ZDC), 0x40004000+0x10000 (cal)")
    elif k23 == "nrc" and d23.startswith("0x33"):
        print(f"VERDICT: $23 STILL SA-DENIED — SA L{(args.level - 1) // 2 + 1} isn't the right level")
        print("══════════════════════════════════════════════════════════════════════")
        print("  → try other SA levels (--level 0x05, 0x07, 0x13, etc)")
    elif k23 == "nrc" and (d23.startswith("0x11") or d23.startswith("0x7F")):
        print("VERDICT: $23 STILL NOT SUPPORTED — service is genuinely missing or session-gated")
        print("══════════════════════════════════════════════════════════════════════")
        print("  → SA L17 doesn't help here. Try $10 02 (programming session) before $23?")
    else:
        print("VERDICT: unexpected $23 response — inspect manually")
        print("══════════════════════════════════════════════════════════════════════")

    print("\n──── Cleanup: return to default session ────")
    try:
        r01 = raw_uds_request(panda, args.bus, bytes([0x10, 0x01]))
        k01, d01 = decode(0x10, r01)
        print(f"  $10 01 → {k01}: {d01}")
    except Exception as e:
        print(f"  ⚠ cleanup failed: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
