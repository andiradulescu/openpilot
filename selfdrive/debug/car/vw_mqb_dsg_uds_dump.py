#!/usr/bin/env python3
"""
UDS recon + read of the VW MQB DSG TCU (DQ500 0DL, Bosch on Renesas SH-2A
R5F72549R). Tester 0x7E1, responder 0x7E9, via OBD-II tunnel on panda
bus 1. Mirrors the YOYO Diagnostic tool's read flow as closely as
possible (see DQ500_0DL_MEMORY_MAP.md).

═════════════════════════════════════════════════════════════════════
GATED OPERATIONS (each independently selectable)
═════════════════════════════════════════════════════════════════════

Default (no flags) = Phase A, strictly read-only recon:
  • $10 03 ExtendedDiagnostic
  • $22 ReadDataByIdentifier (identity DIDs)
  • $23 ReadMemoryByAddress 16-byte probe across documented regions
  • $3E TesterPresent (keepalive)
  No SecurityAccess, no key submission, no $35 transfer state.

  --auth-dry-run
        Request seed via $27 0x11 (free — no penalty), derive key with
        the SA2 byte-code from dq500_0dl.py, print BOTH seed and key,
        then EXIT. Use this FIRST to verify the algorithm produces
        plausible bytes before risking the lockout counter.

  --auth
        Same as --auth-dry-run + submit the key via $27 0x12.
        ⚠ A wrong key bumps the ECU's lockout counter (after N strikes
        SA is time-locked). Gated behind --i-understand-lockout-risk
        so it can't run by accident. Aborts immediately on first NRC —
        no retries.

  --i-understand-lockout-risk
        Required companion to --auth.

  --read-cal-prefix [N]
        Recommended minimal first read after --auth. Issues ONE
        $35 RequestUpload at phys 0x00140000 (CAL partition 23 start)
        for N bytes (default 256, max 65536), $36 loop until done,
        $37 RequestTransferExit. Compares against extracted FRF CAL
        for byte-for-byte verification. This is the smallest possible
        test that proves auth + read protocol work end-to-end.

  --read-phys ADDR LEN
        Generic version of --read-cal-prefix: $35 at 4-byte phys
        address ADDR, length LEN (capped by --upload-bytes-cap).

═════════════════════════════════════════════════════════════════════
HARD GUARANTEES (independent of flags)
═════════════════════════════════════════════════════════════════════
Never issues these services, regardless of any flag combination:
  $2E WriteDataByIdentifier        $3D WriteMemoryByAddress
  $31 RoutineControl               $34 RequestDownload
  $14 ClearDiagnosticInformation   $11 ECUReset
  $2F InputOutputControlByIdentifier $2C DynamicallyDefineDataIdentifier
  $28 CommunicationControl         $85 ControlDTCSetting
  $86 ResponseOnEvent              $83 AccessTimingParameter
  $87 LinkControl

Only services that can fire (and even those only behind explicit gates):
  Always:        $10 03, $22, $23, $3E
  With --auth*:  $27 0x11 (request_seed)
  With --auth:   $27 0x12 (send_key, ONE attempt)
  With --read-*: $35, $36, $37 (read-side transfer; flash not modified)

Vehicle requirements:
  * Ignition ON, engine OFF, P + parking brake
  * `sudo systemctl stop comma` so the panda is free
  * Panda plugged into OBD-II — script forces bus 1 + set_obd(True)
"""

import argparse
import hashlib
import sys
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from panda import Panda
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    ACCESS_TYPE,
)
from opendbc.car.structs import CarParams


# ──────────────────────────────────────────────────────────────────────
# Topology + DSG constants
# ──────────────────────────────────────────────────────────────────────
TCU_TX = 0x7E1
TCU_RX = 0x7E9
BUS_OBD = 1
SA_LEVEL_DSG = 0x11   # SA17 — matches VW_Flash/lib/flash_uds.py:519
SA2_SCRIPT_DQ500_0DL = bytes.fromhex("6806814A05876B5F7DD5494C")  # dq500_0dl.py:36

# CAL partition 23-24 (per DQ500_0DL_MEMORY_MAP.md; YOYO confirmed)
CAL_ADDR = 0x00140000
CAL_SIZE = 0x40000  # 2 × 128 KB

# EEPROM (per DQ500_0DL_MEMORY_MAP.md; YOYO confirmed)
EEPROM_ADDR = 0x80100000
EEPROM_SIZE = 0x20000  # 16 × 8 KB

# Default cap on $36 payload bytes per single --read-phys invocation
UPLOAD_BYTES_CAP_DEFAULT = 65536
UPLOAD_BYTES_CAP_MAX = 524288

IDENTITY_DIDS = [
    (0xF187, "VW spare part number"),
    (0xF189, "VW application SW version"),
    (0xF18C, "ECU serial number"),
    (0xF191, "VW ECU HW number"),
    (0xF197, "VW system name / DSG model"),
    (0xF19E, "ASAM/ODX file identifier"),
    (0xF1A2, "VW programming preconditions"),
]


class Region(NamedTuple):
    label: str
    addr_phys: int
    addr_va: int | None
    size: int
    note: str


REGIONS: list[Region] = [
    Region("cal",          0x00140000, 0x80140000, 16,
           "CAL — readable per YOYO; expected $23 NRC pre-SA"),
    Region("sboot",        0x00000000, 0x80000000, 16, "SBOOT — protected"),
    Region("cboot",        0x00010000, 0x80010000, 16, "CBOOT — protected"),
    Region("asw",          0x00030000, 0x80030000, 16, "ASW — protected"),
    Region("upper_factory", 0x00180000, 0x80180000, 16,
           "upper 0x180000-0x27FFFF — protected"),
    Region("dflash",       0x80100000, None, 16,
           "EEPROM at VA 0x80100000 — readable per YOYO"),
]


# ──────────────────────────────────────────────────────────────────────
# SA2 byte-code VM (inlined from re-vw/sa2_seed_key; same algorithm
# VW_Flash uses on DSG — public, deterministic seed→key map). Proven
# correct against EPS in vw_mqb_sa17_probe.py on this codebase.
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


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _nrc_str(e: NegativeResponseError) -> str:
    return f"0x{e.error_code:02X} ({e.message})"


def _try_rmba(uds: UdsClient, addr: int, size: int,
              addr_bytes: int = 4) -> tuple[str, bytes | str]:
    try:
        data = uds.read_memory_by_address(
            memory_address=addr, memory_size=size,
            memory_address_bytes=addr_bytes, memory_size_bytes=1,
        )
    except NegativeResponseError as e:
        return ("nrc", _nrc_str(e))
    except MessageTimeoutError:
        return ("err", "timeout")
    except Exception as e:  # noqa: BLE001
        return ("err", f"{type(e).__name__}: {e}")
    if not data:
        return ("err", "empty response")
    return ("ok", data)


def _verify_against_frf(addr_offset: int, data: bytes, frf_path: Path, log) -> None:
    if not frf_path.exists():
        log(f"       [verify] {frf_path.name} not found — skipping comparison")
        return
    expected = frf_path.read_bytes()
    if addr_offset + len(data) > len(expected):
        log(f"       [verify] offset 0x{addr_offset:X}+{len(data)}B beyond FRF block 0x{len(expected):X}")
        return
    slice_ = expected[addr_offset:addr_offset + len(data)]
    if slice_ == data:
        log(f"       [verify] MATCH against {frf_path.name} "
            f"(sha256(read)={hashlib.sha256(data).hexdigest()[:16]}…)")
    else:
        # Count matching bytes for partial-match metric (CAL diverges due
        # to adaptation, so a partial match is also informative)
        match_n = sum(1 for a, b in zip(data, slice_) if a == b)
        log(f"       [verify] PARTIAL match against {frf_path.name}: "
            f"{match_n}/{len(data)} bytes equal "
            f"({100 * match_n / len(data):.1f}%)")
        log(f"                read[:32]:     {data[:32].hex(' ')}")
        log(f"                expected[:32]: {slice_[:32].hex(' ')}")


def _phase_a_recon(uds: UdsClient, frf_dir: Path, log) -> None:
    log("── $10 03 ExtendedDiagnostic ──")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        log("   ok")
    except NegativeResponseError as e:
        log(f"   NRC: {_nrc_str(e)}")
    except Exception as e:  # noqa: BLE001
        log(f"   {type(e).__name__}: {e}")
        raise

    log("")
    log("── $22 ReadDataByIdentifier (identity) ──")
    for did, desc in IDENTITY_DIDS:
        try:
            payload = uds.read_data_by_identifier(did)
        except NegativeResponseError as e:
            log(f"   0x{did:04X} {desc:35s} : NRC ({e})")
            continue
        except Exception as e:  # noqa: BLE001
            log(f"   0x{did:04X} {desc:35s} : {type(e).__name__}: {e}")
            continue
        try:
            text = payload.decode("ascii").rstrip("\x00 ")
            text_ok = all(0x20 <= b < 0x7F or b == 0 for b in payload)
        except Exception:
            text = ""
            text_ok = False
        display = text if text_ok and text else payload.hex(" ")
        log(f"   0x{did:04X} {desc:35s} : {display}")

    log("")
    log("── $23 ReadMemoryByAddress probe (16 B per region) ──")
    for r in REGIONS:
        log(f"   [{r.label}] phys=0x{r.addr_phys:08X}", )
        st, val = _try_rmba(uds, r.addr_phys, r.size)
        log(f"     phys-form: {st.upper()} {val.hex(' ') if isinstance(val, bytes) else val}")
        if r.addr_va is not None and r.addr_va != r.addr_phys:
            st, val = _try_rmba(uds, r.addr_va, r.size)
            log(f"     va-form  : {st.upper()} {val.hex(' ') if isinstance(val, bytes) else val}")


def _do_auth(uds: UdsClient, log, submit_key: bool) -> tuple[bool, bytes | None, bytes | None]:
    """Returns (authenticated, seed, key_bytes). If submit_key=False, never sends key."""
    log("")
    log("── $27 SecurityAccess L17 ──")
    log(f"   SA2 byte-code (dq500_0dl.py): {SA2_SCRIPT_DQ500_0DL.hex()}")
    log(f"   request_seed sub-function: 0x{SA_LEVEL_DSG:02X}")
    log(f"   send_key sub-function    : 0x{SA_LEVEL_DSG + 1:02X}")
    try:
        seed = uds.security_access(SA_LEVEL_DSG)
    except NegativeResponseError as e:
        log(f"   request_seed NRC: {_nrc_str(e)}")
        return (False, None, None)
    except Exception as e:  # noqa: BLE001
        log(f"   request_seed failed: {type(e).__name__}: {e}")
        return (False, None, None)
    log(f"   seed = {seed.hex()}  ({len(seed)} bytes)")
    if all(b == 0 for b in seed):
        log("   seed is all-zero → already authenticated at L17 (no key needed)")
        return (True, seed, None)

    seed_int = int.from_bytes(seed, "big")
    try:
        key_int = Sa2SeedKey(SA2_SCRIPT_DQ500_0DL, seed_int).execute()
    except Exception as e:  # noqa: BLE001
        log(f"   SA2 VM failed: {type(e).__name__}: {e}")
        return (False, seed, None)
    key = key_int.to_bytes(len(seed), "big")
    log(f"   computed key = {key.hex()}  ({len(key)} bytes)")

    if not submit_key:
        log("   --auth-dry-run: NOT submitting key. Lockout counter NOT advanced.")
        log("   Verify the key bytes look plausible (random-looking, same length as")
        log("   seed) before re-running with --auth --i-understand-lockout-risk.")
        return (False, seed, key)

    log("   submitting key (single attempt — aborts on NRC)")
    try:
        uds.security_access(SA_LEVEL_DSG + 1, key)
    except NegativeResponseError as e:
        log(f"   send_key NRC: {_nrc_str(e)}")
        log("   → algorithm/key mismatch. DO NOT RETRY blindly. Counter has advanced.")
        return (False, seed, key)
    except Exception as e:  # noqa: BLE001
        log(f"   send_key failed: {type(e).__name__}: {e}")
        return (False, seed, key)
    log("   ✓ authenticated at L17")
    return (True, seed, key)


def _do_upload(uds: UdsClient, addr: int, length: int, label: str,
               out_dir: Path, log, frf_dir: Path,
               frf_block: str | None = None,
               frf_offset: int = 0) -> bytes | None:
    """YOYO-mirror $35/$36/$37 read of LENGTH bytes at 4-byte phys ADDR."""
    log("")
    log(f"── $35 RequestUpload + $36 TransferData + $37 Exit ({label}) ──")
    log(f"   address (4-byte phys) = 0x{addr:08X}")
    log(f"   length                = {length} (0x{length:X}) B")
    log(f"   data_format           = 0x00 (no compression/encryption)")
    try:
        max_block = uds.request_upload(
            memory_address=addr,
            memory_size=length,
            memory_address_bytes=4,
            memory_size_bytes=4,
            data_format=0x00,
        )
    except NegativeResponseError as e:
        log(f"   $35 NRC: {_nrc_str(e)}")
        return None
    except Exception as e:  # noqa: BLE001
        log(f"   $35 failed: {type(e).__name__}: {e}")
        return None
    log(f"   $35 ok — maxNumberOfBlockLength = {max_block}")

    out = bytearray()
    counter = 1
    try:
        while len(out) < length:
            chunk = uds.transfer_data(counter)
            if not chunk:
                log(f"   $36 empty at counter={counter}, len={len(out)} — stopping")
                break
            out.extend(chunk)
            counter = ((counter) & 0xFF) + 1
            if counter == 256:
                counter = 0  # wrap to 0 per ISO 14229
        log(f"   $36 done — got {len(out)} B")
    except NegativeResponseError as e:
        log(f"   $36 NRC at counter={counter}, accumulated {len(out)} B: {_nrc_str(e)}")
    except Exception as e:  # noqa: BLE001
        log(f"   $36 failed at counter={counter}, accumulated {len(out)} B: "
            f"{type(e).__name__}: {e}")
    finally:
        try:
            uds.request_transfer_exit()
            log("   $37 exit ok — transfer state cleared")
        except Exception as e:  # noqa: BLE001
            log(f"   $37 exit warn: {type(e).__name__}: {e}")

    if not out:
        return None
    out_path = out_dir / f"{label}_0x{addr:08X}_{len(out)}B.bin"
    out_path.write_bytes(bytes(out))
    log(f"   saved {len(out)} B → {out_path.name}")
    log(f"   first 32 B: {bytes(out[:32]).hex(' ')}")
    if frf_block:
        _verify_against_frf(frf_offset, bytes(out), frf_dir / frf_block, log)
    return bytes(out)


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("═")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full gate definitions.",
    )
    ap.add_argument("--output-dir", type=Path, default=None)
    ap.add_argument("--frf-dir", type=Path,
                    default=Path("/data/VW_Flash/extracted_FL_0DL300012N_2110"))
    ap.add_argument("--bus", type=int, default=BUS_OBD)
    ap.add_argument("--auth-dry-run", action="store_true",
                    help="request seed + derive key + print, NO submit")
    ap.add_argument("--auth", action="store_true",
                    help="request seed + derive key + submit (requires --i-understand-lockout-risk)")
    ap.add_argument("--i-understand-lockout-risk", action="store_true",
                    help="required companion to --auth")
    ap.add_argument("--read-cal-prefix", nargs="?", type=int, const=256, default=None,
                    metavar="N",
                    help="after --auth, read N bytes (default 256, max --upload-bytes-cap) "
                         "from CAL phys 0x00140000")
    ap.add_argument("--read-phys", nargs=2, type=lambda x: int(x, 0), default=None,
                    metavar=("ADDR", "LEN"),
                    help="after --auth, read LEN bytes at 4-byte phys ADDR")
    ap.add_argument("--upload-bytes-cap", type=int, default=UPLOAD_BYTES_CAP_DEFAULT,
                    help=f"global cap on $36 read per invocation "
                         f"(default {UPLOAD_BYTES_CAP_DEFAULT}, max {UPLOAD_BYTES_CAP_MAX})")
    args = ap.parse_args()

    if args.auth and not args.i_understand_lockout_risk:
        print("ERROR: --auth requires --i-understand-lockout-risk", file=sys.stderr)
        return 64
    if args.upload_bytes_cap > UPLOAD_BYTES_CAP_MAX:
        print(f"ERROR: --upload-bytes-cap > {UPLOAD_BYTES_CAP_MAX}", file=sys.stderr)
        return 64
    if (args.read_cal_prefix is not None or args.read_phys is not None) and not args.auth:
        print("ERROR: --read-* requires --auth (and --i-understand-lockout-risk)", file=sys.stderr)
        return 64

    out_dir = args.output_dir or Path(f"dsg_uds_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.txt"
    log_file = open(log_path, "w")

    def log(msg: str) -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log(f"DSG UDS recon — {datetime.now().isoformat()}")
    log(f"Output: {out_dir.resolve()}")
    log(f"FRF:    {args.frf_dir} ({'present' if args.frf_dir.exists() else 'NOT FOUND'})")
    log(f"Gates:  auth_dry_run={args.auth_dry_run}  auth={args.auth}  "
        f"read_cal_prefix={args.read_cal_prefix}  read_phys={args.read_phys}  "
        f"upload_bytes_cap={args.upload_bytes_cap}")
    log("")

    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
        panda.set_obd(True)
        panda.can_clear(0xFFFF)
    except Exception as e:  # noqa: BLE001
        log(f"Panda setup failed: {type(e).__name__}: {e}")
        log_file.close()
        return 1

    uds = UdsClient(panda, TCU_TX, TCU_RX, args.bus, timeout=2.0)

    # Phase A always runs (cheap, useful baseline)
    try:
        _phase_a_recon(uds, args.frf_dir, log)
    except Exception:
        log_file.close()
        return 2

    # SA gates
    submit = args.auth
    do_sa = args.auth_dry_run or args.auth
    authed = False
    if do_sa:
        authed, _, _ = _do_auth(uds, log, submit_key=submit)
        if args.auth_dry_run and not args.auth:
            log("")
            log("── auth-dry-run complete; no key submitted. Exiting. ──")
            log_file.close()
            return 0
        if args.auth and not authed:
            log("")
            log("── auth failed; not running read-* gates ──")
            log_file.close()
            return 3

    # Read gates (only if authed)
    if authed:
        if args.read_cal_prefix is not None:
            n = min(args.read_cal_prefix, args.upload_bytes_cap)
            _do_upload(uds, addr=CAL_ADDR, length=n,
                       label="cal_prefix",
                       out_dir=out_dir, log=log, frf_dir=args.frf_dir,
                       frf_block="cal_80140000.bin", frf_offset=0)
        if args.read_phys is not None:
            addr, length = args.read_phys
            length = min(length, args.upload_bytes_cap)
            # Pick the FRF block if the address falls in a known range
            frf_block = None
            frf_offset = 0
            if 0x00140000 <= addr < 0x00180000:
                frf_block = "cal_80140000.bin"
                frf_offset = addr - 0x00140000
            elif 0x00010000 <= addr < 0x00030000:
                frf_block = "cboot_80010000.bin"
                frf_offset = addr - 0x00010000
            elif 0x00030000 <= addr < 0x00140000:
                frf_block = "asw_80030000.bin"
                frf_offset = addr - 0x00030000
            _do_upload(uds, addr=addr, length=length,
                       label=f"phys",
                       out_dir=out_dir, log=log, frf_dir=args.frf_dir,
                       frf_block=frf_block, frf_offset=frf_offset)

    log("")
    log("══════════════════════════════════════════════════════")
    log("END — log.txt + saved .bin files in output dir.")
    log_file.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
