#!/usr/bin/env python3
"""
ODIS-mirror UDS read of the VW MQB DSG TCU (DQ500 0DL, Bosch on Renesas
SH-2A R5F72549R). Reproduces the exact session-entry sequence captured
in a real ODIS flash trace (VIN TMBLJ9NS3J8068062, EPS module 0x712),
then substitutes $35 RequestUpload for ODIS's $34 RequestDownload so we
READ instead of write.

═════════════════════════════════════════════════════════════════════
SEQUENCE (matches ODIS trace lines 23-152, retargeted to TCU 0x7E1)
═════════════════════════════════════════════════════════════════════
  1.  $3E 80          functional broadcast (0x700)   — wake bus
  2.  $10 03          → TCU 0x7E1                    — extended session
  3.  $22 F190        → TCU                          — read VIN
  4.  $31 01 02 03    → TCU                          — precondition check
  5.  $10 83          functional broadcast (0x700)   — extended bus-wide
  6.  $10 03          → TCU                          — extended again
  7.  $31 01 02 03    → TCU                          — precondition again
  8.  $85 82 FF FF FF functional broadcast (0x700)   — disable DTC monitoring
  9.  $28 81 01       functional broadcast (0x700)   — silence normal Tx
  10. $10 02          → TCU                          — PROGRAMMING SESSION
  11. $27 0x11        → TCU                          — request seed
  12. SA2 VM locally  (no wire traffic)              — derive key
  -- safety wall: with --dry-run (default) we STOP HERE --
  13. $27 0x12 key    → TCU                          — send key (SA17 unlock)
  14. $35 phys/len    → TCU                          — RequestUpload (CAL)
  15. $36 loop        → TCU                          — TransferData (read)
  16. $37             → TCU                          — RequestTransferExit
  -- finally (always, even on exception): --
  17. $28 00 01       functional broadcast           — re-enable normal Tx
  18. $85 01 FF FF FF functional broadcast           — re-enable DTC
  19. $10 01          → TCU                          — back to default session
                                                       (TCU returns to ASW on
                                                        next S3 timeout anyway)

═════════════════════════════════════════════════════════════════════
SAFETY MODEL
═════════════════════════════════════════════════════════════════════
NEVER (could brick the module — flash corruption / comms loss):
  $34 RequestDownload          — gateway to flash write
  $3D WriteMemoryByAddress     — direct memory write
  $2E WriteDataByIdentifier    — DID write (can clobber critical DIDs)
  $87 LinkControl              — changes CAN baud rate, brick if wrong
  $31 RoutineControl ANY ID    — except 0x0203 (precondition check); the
                                  rest include EraseMemory (0xFF00) and
                                  ChecksumBlock (0x0202), both brickable

Allowed-but-state-changing (transient; auto-revert on S3 timeout):
  $10 (any session)            — session change
  $27 SecurityAccess           — gated on --read; wrong key bumps counter
  $28 CommunicationControl     — silences normal Tx (visual cluster glitch)
  $85 ControlDTCSetting        — disables DTC capture
  $11 ECUReset                 — clean reboot (not used here, but safe)
  $14 ClearDiagnosticInfo      — clears DTCs (not used here)

Read-only:
  $22 / $23 / $19 / $3E         — DID/memory/DTC reads, keepalive
  $35 / $36 (request-only) / $37 — read-side upload (we never call $34
                                   so $36 stays read-mode)

═════════════════════════════════════════════════════════════════════
GATES (minimal)
═════════════════════════════════════════════════════════════════════
Default (no flags):
  Runs steps 1-12 only. Computes the SA2 key from the live seed but
  does NOT submit it. Cleanup (17-19) runs. No flash touched.

  --read [N]
        Run the full sequence (steps 1-19), submit the key, read N
        bytes from CAL phys 0x00140000 (default 256, max 65536).
        Wrong key bumps the lockout counter — single attempt, then
        aborts cleanly into cleanup.

  --pt-direct
        Route bus 1 to raw PT-CAN instead of OBD-II tunnel. Default
        is OBD-II (matches ODIS).

═════════════════════════════════════════════════════════════════════
Vehicle requirements
═════════════════════════════════════════════════════════════════════
  * Selector P, parking brake, KL15 ON, engine OFF, 12V maintainer
    if available (matches DQ500 documented programming preconditions)
  * `sudo systemctl stop comma`
"""

import argparse
import hashlib
import struct
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from panda import Panda
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    ROUTINE_CONTROL_TYPE,
)
from opendbc.car.structs import CarParams


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────
TCU_TX = 0x7E1
TCU_RX = 0x7E9
BUS = 1
FUNCTIONAL_TX = 0x700              # VW tester functional broadcast ID
SA_LEVEL_DSG = 0x11                # SA17, per VW_Flash/lib/flash_uds.py:519
SA2_SCRIPT_DQ500_0DL = bytes.fromhex("6806814A05876B5F7DD5494C")

# Hard-locked: the ONLY $31 routine ID this script may invoke.
# Routine 0x0203 = "Check Programming Precondition" — read-only status.
PRECONDITION_ROUTINE_ID = 0x0203

# CAL partition 23 start (per DQ500_0DL_MEMORY_MAP.md, confirmed by YOYO).
CAL_PHYS_ADDR = 0x00140000

# Read-byte cap (--read N).
READ_BYTES_DEFAULT = 256
READ_BYTES_MAX = 65536


# ──────────────────────────────────────────────────────────────────────
# SA2 byte-code VM (inlined; same algorithm VW_Flash uses on DSG)
# ──────────────────────────────────────────────────────────────────────
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
        ops = self.tape[self.ip + 1:self.ip + 5]
        v = (ops[0] << 24) | (ops[1] << 16) | (ops[2] << 8) | ops[3]
        out = self.register + v
        self.carry_flag = 1 if out > 0xFFFFFFFF else 0
        self.register = out & 0xFFFFFFFF
        self.ip += 5

    def _sub(self):
        ops = self.tape[self.ip + 1:self.ip + 5]
        v = (ops[0] << 24) | (ops[1] << 16) | (ops[2] << 8) | ops[3]
        out = self.register - v
        self.carry_flag = 1 if out < 0 else 0
        self.register = out & 0xFFFFFFFF
        self.ip += 5

    def _eor(self):
        ops = self.tape[self.ip + 1:self.ip + 5]
        v = (ops[0] << 24) | (ops[1] << 16) | (ops[2] << 8) | ops[3]
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


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _nrc(e: NegativeResponseError) -> str:
    return f"0x{e.error_code:02X} ({e.message})"


def _broadcast(panda: Panda, payload: bytes, log, label: str) -> None:
    """Send a single-frame ISO-TP request to functional ID 0x700.
    Suppress-positive-response bit is expected on the sub-function byte.
    No reply is awaited — the broadcast is fire-and-forget.
    """
    assert len(payload) <= 7, f"functional broadcast must fit one frame: {payload.hex()}"
    frame = bytes([len(payload)]) + payload + b"\x55" * (7 - len(payload))
    panda.can_send(FUNCTIONAL_TX, frame, BUS)
    log(f"     0x{FUNCTIONAL_TX:03X}: {frame.hex(' ')}   ← {label}")


def _read_did(uds: UdsClient, did: int, label: str, log) -> bytes | None:
    try:
        payload = uds.read_data_by_identifier(did)
    except NegativeResponseError as e:
        log(f"   $22 0x{did:04X} ({label}) NRC: {_nrc(e)}")
        return None
    except Exception as e:  # noqa: BLE001
        log(f"   $22 0x{did:04X} ({label}) {type(e).__name__}: {e}")
        return None
    try:
        text = payload.decode("ascii").rstrip("\x00 ")
        if all(0x20 <= b < 0x7F or b == 0 for b in payload):
            disp = text
        else:
            disp = payload.hex(" ")
    except Exception:
        disp = payload.hex(" ")
    log(f"   $22 0x{did:04X} ({label}): {disp}")
    return payload


def _start_routine_precondition(uds: UdsClient, log) -> bool:
    """The ONLY $31 routine permitted by this script. Routine ID is
    hard-coded; no CLI argument can change it."""
    assert PRECONDITION_ROUTINE_ID == 0x0203, "routine ID changed — abort"
    try:
        result = uds.routine_control(
            ROUTINE_CONTROL_TYPE.START, PRECONDITION_ROUTINE_ID,
        )
    except NegativeResponseError as e:
        log(f"   $31 01 02 03 NRC: {_nrc(e)}")
        return False
    except Exception as e:  # noqa: BLE001
        log(f"   $31 01 02 03 {type(e).__name__}: {e}")
        return False
    log(f"   $31 01 02 03 ok  result={result.hex(' ') if result else '(empty)'}")
    return True


def _do_upload(uds: UdsClient, addr: int, length: int, out_dir: Path,
               log, frf_dir: Path) -> bytes | None:
    log(f"   $35 RequestUpload  addr=0x{addr:08X} len={length} (0x{length:X})")
    try:
        max_block = uds.request_upload(
            memory_address=addr,
            memory_size=length,
            memory_address_bytes=4,
            memory_size_bytes=4,
            data_format=0x00,
        )
    except NegativeResponseError as e:
        log(f"   $35 NRC: {_nrc(e)}")
        return None
    except Exception as e:  # noqa: BLE001
        log(f"   $35 {type(e).__name__}: {e}")
        return None
    log(f"   $35 ok  maxNumberOfBlockLength={max_block}")
    out = bytearray()
    counter = 1
    try:
        while len(out) < length:
            chunk = uds.transfer_data(counter)
            if not chunk:
                log(f"   $36 ctr={counter} empty — stopping at {len(out)} B")
                break
            out.extend(chunk)
            counter = (counter + 1) & 0xFF
        log(f"   $36 done — {len(out)} B")
    except NegativeResponseError as e:
        log(f"   $36 ctr={counter} NRC: {_nrc(e)} (got {len(out)} B)")
    except Exception as e:  # noqa: BLE001
        log(f"   $36 ctr={counter} {type(e).__name__}: {e}")
    finally:
        try:
            uds.request_transfer_exit()
            log("   $37 ok")
        except Exception as e:  # noqa: BLE001
            log(f"   $37 warn: {type(e).__name__}: {e}")

    if not out:
        return None
    out_path = out_dir / f"cal_0x{addr:08X}_{len(out)}B.bin"
    out_path.write_bytes(bytes(out))
    log(f"   saved {len(out)} B → {out_path.name}")
    log(f"   first 32 B: {bytes(out[:32]).hex(' ')}")

    cal_ref = frf_dir / "cal_80140000.bin"
    if cal_ref.exists():
        expected = cal_ref.read_bytes()
        offset = addr - CAL_PHYS_ADDR
        if 0 <= offset and offset + len(out) <= len(expected):
            slice_ = expected[offset:offset + len(out)]
            if slice_ == bytes(out):
                log(f"   [verify] MATCH against {cal_ref.name} "
                    f"(sha256={hashlib.sha256(bytes(out)).hexdigest()[:16]}…)")
            else:
                match_n = sum(1 for a, b in zip(out, slice_) if a == b)
                log(f"   [verify] PARTIAL {match_n}/{len(out)} bytes match "
                    f"({100*match_n/len(out):.1f}%) — adaptation deltas expected")
        else:
            log(f"   [verify] offset 0x{offset:X} outside FRF block")
    return bytes(out)


# ──────────────────────────────────────────────────────────────────────
# Main flow
# ──────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("═")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--output-dir", type=Path, default=None)
    ap.add_argument("--frf-dir", type=Path,
                    default=Path("/data/VW_Flash/extracted_FL_0DL300012N_2110"))
    ap.add_argument("--pt-direct", action="store_true",
                    help="bus 1 → raw PT-CAN (default: OBD-II tunnel, matches ODIS)")
    ap.add_argument("--read", nargs="?", type=int, const=READ_BYTES_DEFAULT, default=None,
                    metavar="N",
                    help=f"submit key + read N bytes from CAL (default "
                         f"{READ_BYTES_DEFAULT}, max {READ_BYTES_MAX}). "
                         f"Without this flag the script stops after computing "
                         f"the key and never submits it.")
    args = ap.parse_args()

    if args.read is not None:
        args.read = max(1, min(args.read, READ_BYTES_MAX))

    out_dir = args.output_dir or Path(f"dsg_uds_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.txt"
    log_file = open(log_path, "w")

    def log(msg: str) -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log(f"DSG UDS ODIS-mirror — {datetime.now().isoformat()}")
    log(f"Output: {out_dir.resolve()}")
    log(f"FRF:    {args.frf_dir} ({'present' if args.frf_dir.exists() else 'NOT FOUND'})")
    log(f"Mode:   {'READ ' + str(args.read) + ' B' if args.read else 'dry-run (no key submission)'}")
    log(f"Bus:    {'PT-CAN direct' if args.pt_direct else 'OBD-II tunnel'}")
    log("")

    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
        panda.set_obd(not args.pt_direct)
        panda.can_clear(0xFFFF)
    except Exception as e:  # noqa: BLE001
        log(f"Panda setup failed: {type(e).__name__}: {e}")
        log_file.close()
        return 1

    uds = UdsClient(panda, TCU_TX, TCU_RX, BUS, timeout=2.0)

    # Cleanup state: did we send $85/$28 yet? Used by the finally block to
    # decide whether to send the re-enable counterparts.
    quiesced = False

    try:
        # ──────────────────────────────────────────────────────────────
        # ODIS-mirror flow.
        # Reference trace: TMBLJ9NS3J8068062_20260519T154011_CAN.vmt
        # (real ODIS-E session that successfully flashed EPS 0x712).
        # Each step below cites the trace line(s) so the wire pattern
        # can be cross-checked against ODIS exactly.
        # ──────────────────────────────────────────────────────────────

        # STEP 1 — Continuous functional TesterPresent broadcasts.
        # ODIS sends `02 3E 80 ...` to 0x700 every ~500 ms throughout
        # the entire flash session (trace lines 3, 8, 13, 18 ...).
        # 0x3E with sub-function 0x80 = suppress-positive bit set, so
        # no ECU replies; the bus stays alive without echo traffic.
        # We send a small burst up-front; opendbc's UDS calls below are
        # quick enough that S3 timeout (~5 s) won't trip mid-flow.
        log("── STEP 1: wake broadcasts — $3E 80 to 0x700 (ODIS trace L3..) ──")
        for _ in range(3):
            _broadcast(panda, bytes([0x3E, 0x80]), log, "TesterPresent suppress-pos")
            time.sleep(0.05)

        # STEPS 2-4 — Per-TCU extended session + VIN + precondition.
        # Trace L107 ($10 03), L109 ($31 01 02 03). On ODIS this was
        # against EPS 0x712; for TCU we retarget to 0x7E1. The $22 F190
        # VIN read isn't strictly part of the session entry, but ODIS
        # always does it and it provides a side-benefit S3 reset.
        log("")
        log("── STEP 2-4: per-TCU $10 03 → $22 F190 → $31 0x0203 (trace L107-110) ──")
        try:
            uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
            log("   $10 03 ok")
        except Exception as e:  # noqa: BLE001
            log(f"   $10 03 {type(e).__name__}: {e} — abort")
            return 2
        _read_did(uds, 0xF190, "VIN", log)
        _start_routine_precondition(uds, log)

        # STEP 5 — Functional broadcast $10 83 to take entire bus into
        # extended. Sub-function 0x83 = (0x80 suppress | 0x03 extended).
        # Trace L125. Putting ALL ECUs into extended together is what
        # the gateway-side gate requires before any single ECU will
        # accept $10 02.
        log("")
        log("── STEP 5: functional broadcast $10 83 (bus-wide extended) — trace L125 ──")
        _broadcast(panda, bytes([0x10, 0x83]), log, "$10 83 extended suppress-pos")
        time.sleep(0.1)

        # STEPS 6-7 — Per-TCU re-issue extended + precondition.
        # Trace L126 ($10 03), L129 ($31 01 02 03). ODIS does this
        # again post-broadcast — possibly because the functional
        # extended is suppress-positive and ODIS wants explicit
        # confirmation that the TCU is in extended.
        log("")
        log("── STEP 6-7: re-issue $10 03 + $31 0x0203 post-broadcast (trace L126-130) ──")
        try:
            uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
            log("   $10 03 ok")
        except Exception as e:  # noqa: BLE001
            log(f"   $10 03 {type(e).__name__}: {e}")
        _start_routine_precondition(uds, log)

        # STEP 8 — Functional broadcast $85 0x82 0xFFFFFF.
        # Trace L131. ControlDTCSetting sub-function 0x82 = (0x80
        # suppress | 0x02 OFF). Argument 0xFFFFFF = "all DTC groups."
        # This stops every ECU from logging new DTCs during programming,
        # so the TCU disappearing from PT-CAN (when we hit $10 02 below)
        # doesn't fault out the engine ECU, cluster, gateway etc.
        # Transient: reverts on S3 timeout, or explicitly via $85 81.
        log("")
        log("── STEP 8: functional broadcast $85 0x82 0xFFFFFF (DTC off) — trace L131 ──")
        _broadcast(panda, bytes([0x85, 0x82, 0xFF, 0xFF, 0xFF]), log,
                   "ControlDTCSetting off all DTCs")
        time.sleep(0.05)

        # STEP 9 — Functional broadcast $28 0x81 0x01.
        # Trace L135. CommunicationControl sub-function 0x81 = (0x80
        # suppress | 0x01 disableRxNormalCommunication). Argument 0x01
        # = normalCommunication (vs networkManagement). All ECUs stop
        # broadcasting normal-priority frames, freeing bus bandwidth
        # for the upcoming flash transfer. Instrument cluster may
        # briefly show warning lamps; reverts on $28 0x80 01 below
        # or on session timeout.
        log("")
        log("── STEP 9: functional broadcast $28 0x81 0x01 (silence Tx) — trace L135 ──")
        _broadcast(panda, bytes([0x28, 0x81, 0x01]), log,
                   "CommunicationControl disable Tx normal")
        quiesced = True
        time.sleep(0.1)

        # STEP 10 — Programming session.
        # Trace L137 ($10 02 request), L138 (NRC 0x78 responsePending),
        # L139 (positive response 06 50 02 00 0A 01 F4). Note the
        # initial responsePending — the TCU may need a moment to
        # finalize the bus-quiesced state before accepting; opendbc's
        # response_pending_timeout (10s default) handles this.
        log("")
        log("── STEP 10: per-TCU $10 02 programmingSession — trace L137-139 ──")
        try:
            uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
            log("   $10 02 ok — in programming session (TCU is now in CBOOT)")
        except NegativeResponseError as e:
            log(f"   $10 02 NRC: {_nrc(e)} — abort")
            return 3
        except Exception as e:  # noqa: BLE001
            log(f"   $10 02 {type(e).__name__}: {e} — abort")
            return 3

        # STEP 11 — Request seed.
        # Trace L140 (request), L141 (seed = D7 DD 14 E8 for the EPS
        # run). For TCU the seed will be different each session
        # because it's a fresh PRNG draw on the ECU.
        log("")
        log("── STEP 11: $27 0x11 requestSeed (SA L17) — trace L140-141 ──")
        try:
            seed = uds.security_access(SA_LEVEL_DSG)
        except NegativeResponseError as e:
            log(f"   request_seed NRC: {_nrc(e)} — abort")
            return 4
        log(f"   seed = {seed.hex()}")
        if all(b == 0 for b in seed):
            log("   seed is all-zero → already authenticated at L17")
            authed = True
            key = None
        else:
            seed_int = int.from_bytes(seed, "big")
            key_int = Sa2SeedKey(SA2_SCRIPT_DQ500_0DL, seed_int).execute()
            key = key_int.to_bytes(len(seed), "big")
            log(f"   computed key = {key.hex()}")
            authed = False

        # ── 12. Stop here in dry-run ─────────────────────────────────
        if args.read is None:
            log("")
            log("── dry-run: NOT submitting key. Cleanup will re-enable bus. ──")
            return 0

        # STEP 13 — Send key. Trace L142 (request), L143 (NRC 0x78
        # responsePending), L144 (positive 02 67 12). The TCU is now
        # SA17-unlocked. Wrong key would NRC 0x35 invalidKey and bump
        # the lockout counter; we make exactly one attempt then abort.
        if not authed:
            log("")
            log("── STEP 13: $27 0x12 sendKey — trace L142-144 ──")
            try:
                uds.security_access(SA_LEVEL_DSG + 1, key)
                log("   ✓ SA17 unlocked")
                authed = True
            except NegativeResponseError as e:
                log(f"   sendKey NRC: {_nrc(e)} — abort, lockout counter advanced")
                return 5

        # STEPS 14-16 — Read CAL via $35 RequestUpload / $36 / $37.
        # This is where we DIVERGE from ODIS. ODIS at this point does:
        #   $2E F1 5A 26 05 19 11 11 11 11 11 11  (write workshop code, trace L145-148)
        #   $34 00 41 30 00 00 0D 18              (RequestDownload, trace L149-152)
        #   $36 <ctr> <payload>                   (TransferData write, trace L153+)
        #   $37                                   (commit write)
        # We do the inverse:
        #   $35 00 44 <4-byte phys> <4-byte len>  (RequestUpload, no encryption)
        #   $36 <ctr>                             (TransferData read)
        #   $37                                   (end transfer; no commit needed)
        # $34 is in our NEVER list; the script cannot send it. Without
        # $34, $36 stays in read-mode (the upload state machine started
        # by $35), so no flash is modified.
        log("")
        log("── STEPS 14-16: $35 / $36 / $37 read CAL (inverse of ODIS write path) ──")
        _do_upload(uds, CAL_PHYS_ADDR, args.read, out_dir, log, args.frf_dir)

        log("")
        log("── ODIS-mirror flow complete ──")
        return 0

    finally:
        # STEPS 17-19 — Cleanup. Mirrors ODIS exit (trace L75039-75044):
        # ODIS sends $85 82 + $28 81 again (re-quiesce) then $28 80 01
        # and $85 81 FF FF FF (re-enable). We just need to re-enable;
        # the re-quiesce in ODIS is paranoid extra coverage for ECUs
        # that may have come back online during the post-ECU-reset
        # window. Then $10 01 default session on the TCU returns it
        # to ASW immediately (vs waiting for S3 timeout).
        log("")
        log("── STEPS 17-19: cleanup (re-enable bus, default session) ──")
        if quiesced:
            try:
                # Order mirrors ODIS exit sequence (trace lines 75042/75044):
                # $28 80 01  = enable Rx+Tx normal,  suppress-positive
                # $85 81 FF FF FF = ControlDTCSetting ON, suppress-positive
                _broadcast(panda, bytes([0x28, 0x80, 0x01]), log,
                           "CommunicationControl re-enable Tx (suppress-pos)")
                time.sleep(0.05)
                _broadcast(panda, bytes([0x85, 0x81, 0xFF, 0xFF, 0xFF]), log,
                           "ControlDTCSetting re-enable (suppress-pos)")
                time.sleep(0.05)
            except Exception as e:  # noqa: BLE001
                log(f"   cleanup warn: {type(e).__name__}: {e}")
        # Drop TCU back to default session (S3 timeout would do this too)
        try:
            uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
            log("   $10 01 (default) ok — TCU back to ASW")
        except Exception:
            pass
        log_file.close()


if __name__ == "__main__":
    sys.exit(main())
