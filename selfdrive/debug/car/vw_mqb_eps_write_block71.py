#!/usr/bin/env python3
"""
Read or write block 0x71 of the VW MQB EPS controller (module 0x44) via UDS.

Block 0x71 is the per-vehicle parametrization partition. On 5Q0909143* it
holds the EPS torque cap at offset 0x3E8 (BE u16, units cNm). The cap is
empirically 300 cNm = 3.00 Nm on stock; raising it to 500 cNm allows
openpilot to push more lateral torque without `steerFaultTemporary`.

Wire protocol (verified by MCD-data trace + web corroboration):
  - Service: $2E WriteDataByIdentifier (NOT $34/$36/$37 partition flash)
  - DID:     0x0071 (a 2-byte UDS DataIdentifier, NOT a flash address)
  - Session: $10 03 Extended (NOT $10 02 Programming)
  - SA:      level 2 ($27 03/04), login 44595 (parametrization tier)
  - Payload: 1950 bytes including a CRC-16/ARC trailer the ECU validates

Subcommands:
    read    dump current block 0x71 to a .bin file (read-only, safe)
    write   apply a patched block 0x71 (output of patch_block71_torque_cap.py)
            defaults to DRY-RUN; --commit flag required to actually write

═════════════════════════════════════════════════════════════════════
SAFETY POSTURE
═════════════════════════════════════════════════════════════════════
Defaults to read-only / dry-run. The actual `$2E` write requires --commit.

Hard guarantees:
  * Input CRC-16/ARC validated before any ECU interaction (write subcmd)
  * Current block 0x71 read + saved to backup BEFORE any write — script
    aborts if the backup read fails
  * Diff of original → new is displayed before commit
  * Readback verification runs after every write; mismatch = stop
  * On any NRC during SA, script aborts immediately — does NOT retry
    alternate logins (would risk lockout)
  * No `$11 ECUReset` issued — operator decides when to ignition-cycle

Failure modes if --commit is set and write fails:
  * Failure BEFORE the $2E request — rack untouched, safe to retry
  * NRC on the $2E itself — rack untouched (the $2E either succeeds
    fully, or the partition stays at the old contents). The ECU
    validates the CRC trailer server-side and rejects with NRC $72
    if invalid; the partition is then unchanged.
  * Failure AFTER successful $2E (verify mismatch) — write took, but
    something else is off; restore by re-running with --input pointing
    at the saved backup file.

  Atomic write (single $2E frame, multi-frame ISO-TP transparent) means
  there is NO partial-erase window where you can brick by cancelling
  mid-operation, unlike the older $34/$36/$37 partition-flash protocol.

Vehicle requirements:
  * Ignition ON, engine OFF
  * On newer cars: HOOD OPEN to defeat the diagnostic firewall
  * Battery support unit recommended (≥ 12.5 V steady)
  * `tmux kill-session -t comma` if on a comma3 with openpilot up
  * Nothing else on the bus should be running diagnostics

Usage examples:
    # READ — dump current block to a backup file (no writes)
    python3 vw_mqb_eps_write_block71.py read

    # WRITE dry-run — full handshake + diff, no actual write
    python3 vw_mqb_eps_write_block71.py write \\
        --input block71_v03935255dc_500cnm.bin

    # WRITE commit — actually performs the $2E write + readback verify
    python3 vw_mqb_eps_write_block71.py write \\
        --input block71_v03935255dc_500cnm.bin --commit

Pre-staged sidecar .bins next to this script:
    block71_v03935255dc_orig.bin       — original Skoda V03935255DC ZDC, cap 300
    block71_v03935255dc_500cnm.bin     — same with cap raised to 500 cNm

Run from the openpilot tree:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
        selfdrive/debug/car/vw_mqb_eps_write_block71.py read
"""

import argparse
import struct
import sys
from datetime import datetime, date as date_t
from pathlib import Path

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    DATA_IDENTIFIER_TYPE,
    ACCESS_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


# Standard MQB EPS UDS addresses
MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x712 + 0x6A   # = 0x77C

# Parametrization-tier login. The XML's LOGIN="44595" field on every
# block-0x70/0x71 ZDC payload uses this value. One of three documented SA2
# seed codes for module 0x44 (others: 19249 standard coding, 28183 adaptation).
PARAM_LOGIN = 44595

# UDS sub-functions for SA Level 2 (per ISO 14229-1:2020 §10.4 — level N uses
# 2N-1 / 2N). Same level vw_mqb_lku_derating.py uses end-to-end on this rack.
SA_REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
SA_SEND_KEY     = ACCESS_TYPE.SEND_KEY     + 2   # 0x04

# DID 0x0071 = the parametrization block we're reading/writing.
DID_BLOCK_71 = 0x0071
EXPECTED_LEN = 1950
CAP_OFFSET   = 0x3E8


# ─────────────────────────────────────────────────────────────────────
# CRC-16/ARC (poly 0x8005, init 0, reflected, no xor)
# Same algorithm as patch_block71_torque_cap.py. Verified against 4 known-
# good ZDC trailers. The ECU validates this server-side; mismatch = NRC $72.
# ─────────────────────────────────────────────────────────────────────
def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def validate_block(blob: bytes) -> tuple[bool, str]:
    """Return (ok, reason). Reject anything not the expected size, or with
    a broken CRC, or a clearly-implausible cap value."""
    if len(blob) != EXPECTED_LEN:
        return False, f"size {len(blob)} != expected {EXPECTED_LEN}"
    body, trailer = blob[:-2], blob[-2:]
    expected_crc = crc16_arc(body)
    actual_crc = struct.unpack(">H", trailer)[0]
    if expected_crc != actual_crc:
        return False, (f"CRC mismatch: trailer 0x{actual_crc:04X}, "
                       f"computed 0x{expected_crc:04X} — re-run patcher")
    cap = struct.unpack(">H", blob[CAP_OFFSET:CAP_OFFSET+2])[0]
    if cap > 1000:
        return False, f"cap @ 0x{CAP_OFFSET:X} = {cap} cNm — implausibly high"
    if cap < 100:
        return False, f"cap @ 0x{CAP_OFFSET:X} = {cap} cNm — implausibly low"
    return True, (f"size={len(blob)}, CRC OK (0x{actual_crc:04X}), "
                  f"cap={cap} cNm ({cap/100:.2f} Nm)")


def report_block(blob: bytes, log) -> None:
    """Print everything we can derive from a block_0x71 blob."""
    log(f"  size: {len(blob)} bytes")
    if len(blob) >= 2:
        body, trailer = blob[:-2], blob[-2:]
        stored = struct.unpack(">H", trailer)[0]
        computed = crc16_arc(body)
        ok = stored == computed
        mark = "✓" if ok else "✗"
        log(f"  {mark} CRC-16/ARC: stored=0x{stored:04X}, computed=0x{computed:04X}")
    if len(blob) >= CAP_OFFSET + 2:
        cap = struct.unpack(">H", blob[CAP_OFFSET:CAP_OFFSET+2])[0]
        log(f"  torque cap @ 0x{CAP_OFFSET:04X}: {cap} cNm = {cap/100:.2f} Nm")
    if len(blob) >= 16:
        ascii_tag = blob[6:14].decode("ascii", errors="replace").rstrip("\x00")
        log(f"  variant tag (bytes 6..13, ASCII): {ascii_tag!r}")


# ─────────────────────────────────────────────────────────────────────
# UDS helpers
# ─────────────────────────────────────────────────────────────────────
def open_extended(uds: UdsClient, log) -> bool:
    log("── Open extended session ($10 03) ──")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        return False
    log("  ✓ extended session opened")
    return True


def identify(uds: UdsClient, log) -> None:
    log("\n── ECU identification ──")
    queries = [
        ("HW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER),
        ("SW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER),
        ("SW ver",   DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER),
        ("ODX file", DATA_IDENTIFIER_TYPE.ODX_FILE),
    ]
    for label, did in queries:
        try:
            v = uds.read_data_by_identifier(did)
            log(f"  {label:>9}: {v.decode('utf-8', errors='replace').rstrip(chr(0)).strip()}")
        except (NegativeResponseError, MessageTimeoutError) as e:
            log(f"  {label:>9}: <error: {type(e).__name__}>")


def _nrc_byte(e: NegativeResponseError) -> int | None:
    """Extract the NRC byte from a udsoncan NegativeResponseError, or None."""
    for attr in ("code", "response"):
        v = getattr(e, attr, None)
        if isinstance(v, int):
            return v
        c = getattr(v, "code", None)
        if isinstance(c, int):
            return c
    return None


def security_access(uds: UdsClient, login: int, log) -> bool:
    """Single-attempt SA L2. On NRC, prints NRC-specific guidance and
    returns False — does NOT auto-retry with alternate logins or alternate
    key formulas (would burn the SA attempt counter; typical limit is 3
    wrong keys before a ~10 s SA delay timer kicks in)."""
    log(f"\n── SecurityAccess L2 (login {login}) ──")
    try:
        seed = uds.security_access(SA_REQUEST_SEED)
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        log(f"  ✗ requestSeed NRC 0x{nrc:02X}" if nrc is not None
            else f"  ✗ requestSeed: {e}")
        if nrc == 0x36:
            log(f"     exceededNumberOfAttempts — SA counter is FULL.")
            log(f"     Wait out the SA delay (typically ~10 s on Bosch BAS Gen-1)")
            log(f"     before any further $27 attempts.")
        elif nrc == 0x37:
            log(f"     requiredTimeDelayNotExpired — SA delay is still running.")
            log(f"     Wait then retry.")
        return False
    except MessageTimeoutError as e:
        log(f"  ✗ requestSeed timeout: {e}")
        return False
    if len(seed) != 4:
        log(f"  ✗ unexpected seed length {len(seed)} (expected 4): {seed.hex()}")
        return False
    seed_int = struct.unpack("!I", seed)[0]
    key_int = (seed_int + login) & 0xFFFFFFFF
    log(f"  seed=0x{seed_int:08X}, login={login}, key=0x{key_int:08X} "
        f"(formula: seed + login)")
    try:
        uds.security_access(SA_SEND_KEY, struct.pack("!I", key_int))
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        log(f"  ✗ sendKey NRC 0x{nrc:02X}" if nrc is not None
            else f"  ✗ sendKey: {e}")
        if nrc == 0x35:
            log(f"     invalidKey — key FORMULA is wrong, but most ECUs do NOT")
            log(f"     increment the SA attempt counter on $35 (only $36 does).")
            log(f"     Likely fix: try the literal-key form (key = login, ignoring")
            log(f"     seed). Edit the script: replace `key_int = (seed_int + login)`")
            log(f"     with `key_int = login & 0xFFFFFFFF` and re-run. Don't auto-")
            log(f"     retry from here — burn at most one attempt per script run.")
        elif nrc == 0x33:
            log(f"     securityAccessDenied — usually a SESSION / PRECONDITION")
            log(f"     issue, NOT the key formula. Check that $10 03 succeeded,")
            log(f"     hood is open if needed, openpilot is not running.")
        elif nrc == 0x36:
            log(f"     exceededNumberOfAttempts — SA counter is now full.")
            log(f"     Wait the SA delay (typically ~10 s) before any further $27.")
        elif nrc == 0x37:
            log(f"     requiredTimeDelayNotExpired — SA delay still running.")
        else:
            log(f"     Unrecognised NRC. Logins to consider: 44595 = parametrization,")
            log(f"     28183 = adaptation, 19249 = coding. Don't spam — try one.")
        return False
    except MessageTimeoutError as e:
        log(f"  ✗ sendKey timeout: {e}")
        return False
    log("  ✓ authenticated")
    return True


def write_prerequisites(uds: UdsClient, log) -> bool:
    """Some MQB ECUs require PROGRAMMING_DATE + REPAIR_SHOP_CODE writes
    before any $2E coding/adaptation write succeeds. Best-effort — if the
    writes fail we continue anyway since these may not be required for
    parametrization-tier DIDs (uncertainty noted in WRITABLE.md)."""
    log("\n── Prerequisite stamps ──")
    try:
        d = date_t.today()
        uds.write_data_by_identifier(
            DATA_IDENTIFIER_TYPE.PROGRAMMING_DATE,
            bytes([d.year - 2000, d.month, d.day]),
        )
        log(f"  ✓ wrote PROGRAMMING_DATE = {d.year - 2000:02X}-{d.month:02X}-{d.day:02X}")
        tester = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.CALIBRATION_REPAIR_SHOP_CODE_OR_CALIBRATION_EQUIPMENT_SERIAL_NUMBER
        )
        uds.write_data_by_identifier(
            DATA_IDENTIFIER_TYPE.REPAIR_SHOP_CODE_OR_TESTER_SERIAL_NUMBER, tester
        )
        log(f"  ✓ wrote REPAIR_SHOP_CODE = {tester.hex()}")
        return True
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ⚠ prerequisite stamp failed: {type(e).__name__}: {e}")
        log(f"     (continuing — these may not be required for DID 0x0071)")
        return False


def read_did_71(uds: UdsClient, log) -> bytes | None:
    log(f"\n── $22 00 71 ReadDataByIdentifier ──")
    try:
        # Bump request_timeout for the multi-frame ISO-TP read of ~1950 bytes.
        old_to = uds._client.config.get("request_timeout", 1.0)
        uds._client.config["request_timeout"] = 5.0
        try:
            data = uds.read_data_by_identifier(DID_BLOCK_71)
        finally:
            uds._client.config["request_timeout"] = old_to
    except NegativeResponseError as e:
        log(f"  ✗ NRC: {e}")
        return None
    except MessageTimeoutError:
        log(f"  ✗ timeout — partition read did not complete within 5 s")
        return None
    log(f"  ✓ received {len(data)} bytes")
    return data


def write_did_71(uds: UdsClient, blob: bytes, log) -> bool:
    log(f"\n── $2E 00 71 WriteDataByIdentifier ({len(blob)} bytes) ──")
    try:
        old_to = uds._client.config.get("request_timeout", 1.0)
        uds._client.config["request_timeout"] = 10.0
        try:
            uds.write_data_by_identifier(DID_BLOCK_71, blob)
        finally:
            uds._client.config["request_timeout"] = old_to
    except NegativeResponseError as e:
        log(f"  ✗ NRC: {e}")
        log(f"     NRC $72 = generalProgrammingFailure (likely CRC trailer mismatch)")
        log(f"     NRC $33 = securityAccessDenied (SA didn't take or wore off)")
        log(f"     NRC $13 = incorrectMessageLength (wrong payload size)")
        log(f"     NRC $31 = requestOutOfRange (DID 0x0071 not writable in this EV)")
        log(f"     NRC $24 = requestSequenceError (missing prerequisite stamp)")
        log(f"  Rack should be UNCHANGED — $2E is atomic, no partial state.")
        return False
    except MessageTimeoutError:
        log(f"  ✗ timeout — write did not get a response within 10 s")
        log(f"  Rack state UNCERTAIN. Re-run `read` to check.")
        return False
    log(f"  ✓ write accepted (positive response)")
    return True


# ─────────────────────────────────────────────────────────────────────
# Output dir + log helpers
# ─────────────────────────────────────────────────────────────────────
def make_log(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.txt"
    log_file = open(log_path, "w")
    def log(msg: str = "") -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()
    return log, log_file


def setup_uds(login: int, log) -> UdsClient | None:
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:
        log(f"FATAL: panda setup failed: {type(e).__name__}: {e}")
        return None
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=2.0)
    if not open_extended(uds, log):
        return None
    identify(uds, log)
    if login >= 0 and not security_access(uds, login, log):
        return None
    return uds


# ─────────────────────────────────────────────────────────────────────
# read subcommand
# ─────────────────────────────────────────────────────────────────────
def cmd_read(args) -> int:
    out_dir = args.output_dir or Path(f"block71_read_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    log, log_file = make_log(out_dir)
    log(f"Mode: READ (no writes)")
    log(f"Output dir: {out_dir.resolve()}")
    log(f"Started: {datetime.now().isoformat()}")
    log(f"Login: {args.login}\n")

    uds = setup_uds(args.login, log)
    if uds is None:
        log_file.close()
        return 1

    blob = read_did_71(uds, log)
    if blob is None:
        log("\nRead failed — see NRC above.")
        log("If NRC $33: SA didn't grant access to this DID. Try a different login.")
        log("If NRC $31: DID 0x0071 isn't readable on this EV. Check ECU identification.")
        log_file.close()
        return 1

    log("\n── Block contents ──")
    report_block(blob, log)

    out_file = args.output or (out_dir / "block_0x71.bin")
    Path(out_file).write_bytes(blob)
    log(f"\n  saved {len(blob)} bytes → {out_file}")

    ok, msg = validate_block(blob)
    log(f"\n  validation: {'PASS' if ok else 'FAIL'} — {msg}")
    log_file.close()
    return 0 if ok else 1


# ─────────────────────────────────────────────────────────────────────
# write subcommand
# ─────────────────────────────────────────────────────────────────────
def cmd_write(args) -> int:
    # Validate input BEFORE any ECU contact
    try:
        new_block = args.input.read_bytes()
    except OSError as e:
        print(f"FATAL: cannot read input file: {e}")
        return 1
    ok, msg = validate_block(new_block)
    if not ok:
        print(f"FATAL: input file rejected: {msg}")
        return 1
    print(f"Input OK: {args.input}")
    print(f"   {msg}")

    out_dir = args.output_dir or Path(f"block71_write_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    log, log_file = make_log(out_dir)
    log(f"Mode: {'COMMIT (will write)' if args.commit else 'DRY-RUN (no writes)'}")
    log(f"Output dir: {out_dir.resolve()}")
    log(f"Started: {datetime.now().isoformat()}")
    log(f"Login: {args.login}")
    log(f"Input: {args.input}\n")

    uds = setup_uds(args.login, log)
    if uds is None:
        log_file.close()
        return 1

    # Mandatory backup
    log("\n── Mandatory pre-write backup ──")
    current = read_did_71(uds, log)
    if current is None:
        log("\n  ✗ backup read failed — REFUSING TO PROCEED.")
        log("  We will not write a 'patched' block without first having a")
        log("  known-good restore copy of the original.")
        log_file.close()
        return 1
    backup_file = out_dir / "block_0x71_original.bin"
    backup_file.write_bytes(current)
    log(f"  ✓ saved {len(current)} bytes → {backup_file.name}")
    bok, bmsg = validate_block(current)
    if not bok:
        log(f"\n  ✗ live block 0x71 has unexpected shape: {bmsg}")
        log(f"  Refusing to write a 'patched' version on top — investigate first.")
        log_file.close()
        return 1
    log(f"  validation: {bmsg}")

    # Diff
    log("\n── Diff (original → new) ──")
    diff = [(i, a, b) for i, (a, b) in enumerate(zip(current, new_block)) if a != b]
    if not diff:
        log("  no differences — input already matches what's on the rack.")
        log("  Nothing to do.")
        log_file.close()
        return 0
    log(f"  {len(diff)} bytes differ")
    for i, a, b in diff[:32]:
        log(f"    +0x{i:04X}: 0x{a:02X} → 0x{b:02X}")
    if len(diff) > 32:
        log(f"    ... and {len(diff) - 32} more differing bytes")
    cap_old = struct.unpack(">H", current[CAP_OFFSET:CAP_OFFSET+2])[0]
    cap_new = struct.unpack(">H", new_block[CAP_OFFSET:CAP_OFFSET+2])[0]
    log(f"\n  cap @ 0x{CAP_OFFSET:04X}: {cap_old} cNm ({cap_old/100:.2f} Nm) "
        f"→ {cap_new} cNm ({cap_new/100:.2f} Nm)")

    if not args.commit:
        log("\n── DRY-RUN — no writes performed. ──")
        log(f"Backup is at: {backup_file}")
        log("To actually write, re-run with --commit.")
        log("If a commit fails partway, restore by re-running with --input")
        log(f"pointed at {backup_file}.")
        log_file.close()
        return 0

    # Optional prerequisites — best-effort (parametrization tier may not need)
    write_prerequisites(uds, log)

    log("\n══════════════════════════════════════════════════════════════")
    log("COMMIT path — single $2E frame goes out next. ATOMIC.")
    log("══════════════════════════════════════════════════════════════")
    if not write_did_71(uds, new_block, log):
        log(f"\n  ✗ write failed — see NRC above.")
        log(f"  Rack should be UNCHANGED. Backup is at: {backup_file}")
        log_file.close()
        return 1

    log(f"\n── Read-back verification ──")
    readback = read_did_71(uds, log)
    if readback is None:
        log(f"  ✗ readback failed. Write may still be intact — ignition cycle and re-run `read`.")
        log_file.close()
        return 1
    if readback != new_block:
        diff_count = sum(1 for a, b in zip(readback, new_block) if a != b)
        log(f"  ✗ readback mismatch: {diff_count} bytes differ from intended.")
        readback_file = out_dir / "block_0x71_readback_after_write.bin"
        readback_file.write_bytes(readback)
        log(f"     readback saved to {readback_file.name}")
        log_file.close()
        return 1
    log("  ✓ readback matches intended bytes exactly")
    report_block(readback, log)

    log("\n══════════════════════════════════════════════════════════════")
    log("DONE. Block 0x71 written and verified.")
    log("Next steps:")
    log("  1. Cycle ignition (key off ~30 s, then on)")
    log("  2. Drive briefly straight on flat ground to re-learn adaptations")
    log("  3. Confirm no DTCs raised (e.g., via VCDS or another ODIS run)")
    log(f"  4. Backup of original block kept at: {backup_file}")
    log("     If anything seems off, run:")
    log(f"       python3 vw_mqb_eps_write_block71.py write \\")
    log(f"           --input {backup_file} --commit")
    log("══════════════════════════════════════════════════════════════")
    log_file.close()
    return 0


# ─────────────────────────────────────────────────────────────────────
# Main / argparse
# ─────────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--login", type=int, default=PARAM_LOGIN,
                   help=f"SA L2 login constant (default {PARAM_LOGIN} = parametrization "
                        f"tier; alternatives: 28183 adaptation, 19249 coding). "
                        f"Pass -1 to skip SA entirely (test if DID is unauth-readable).")
    p.add_argument("--output-dir", type=Path, default=None,
                   help="output directory for logs / backups / dumps "
                        "(default: block71_<read|write>_<timestamp>/)")
    p.add_argument("--debug", action="store_true",
                   help="enable ISO-TP / UDS debug output")

    sub = p.add_subparsers(dest="action", required=True)

    sp_read = sub.add_parser("read", help="dump current block 0x71 to a file (no writes)")
    sp_read.add_argument("--output", type=Path, default=None,
                         help="output .bin path (default: <output-dir>/block_0x71.bin)")

    sp_write = sub.add_parser("write", help="diff + optionally apply a patched block 0x71")
    sp_write.add_argument("--input", type=Path, required=True,
                          help="patched block 0x71 .bin "
                               "(output of patch_block71_torque_cap.py)")
    sp_write.add_argument("--commit", action="store_true",
                          help="actually write. Default is dry-run (full handshake "
                               "+ backup + diff, no $2E goes out).")

    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    if args.action == "read":
        return cmd_read(args)
    elif args.action == "write":
        return cmd_write(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
