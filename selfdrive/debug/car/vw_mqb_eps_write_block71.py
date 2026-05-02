#!/usr/bin/env python3
"""
Read or write the EEPROM block 0x71 of the VW MQB EPS controller
(module 0x44) via UDS. Two subcommands:

    read    dump the current block 0x71 to a .bin file (no writes)
    write   apply a patched block 0x71 (the output of
            patch_block71_torque_cap.py) — defaults to dry-run

Both share the same panda + opendbc.car.uds stack and the same SA2
handshake (login defaults to 44595 — the well-known parametrization
tier login per CLAUDE.md / WRITABLE.md).

═════════════════════════════════════════════════════════════════════
SAFETY POSTURE
═════════════════════════════════════════════════════════════════════
This script can BRICK the EPS rack if used incorrectly. It defaults to
**DRY-RUN** mode — every step except the actual `$34/$36/$37` write +
the `$31 EraseMemory` is performed, including the SecurityAccess
handshake and the readback of the current block (which becomes a
mandatory backup). The actual destructive sequence requires the
explicit `--commit` flag.

Hard guarantees:
  * Input CRC-16/ARC is validated before ANY ECU interaction
  * Current block 0x71 is read and saved to a backup file BEFORE any
    erase / write happens — guaranteed (script aborts if backup fails)
  * Erase + write only happen if --commit is set AND backup succeeded
  * Read-back verification runs after every write; mismatch = stop
  * On ANY NRC during auth, the script aborts immediately (does NOT
    try alternate logins — that's how you lock yourself out)
  * `$11 ECUReset` is NOT issued — operator decides when to ignition-cycle

Failure modes if --commit is set and the script fails mid-way:
  * Failure BEFORE erase — rack untouched, safe to retry
  * Failure DURING erase + before write completes — block 0x71 is
    partially erased; rack will likely show yellow steering icon and
    refuse to assist until the write is completed (re-run script with
    same input file). This is the WINDOW where you can brick by
    cancelling/disconnecting.
  * Failure AFTER successful write — readback will detect; original
    can be restored by running script again with --input pointed at
    the saved backup file.

═════════════════════════════════════════════════════════════════════

Usage:
    # READ — safe; dumps current block 0x71 from the rack to a file.
    # Opens programming session + SA2 auth but no destructive ops.
    python3 vw_mqb_eps_write_block71.py read \
        [--output <path>]              # default: block71_<timestamp>.bin

    # WRITE dry-run — full handshake + diff, no actual erase/write.
    # Always saves a backup of the current block first.
    python3 vw_mqb_eps_write_block71.py write \
        --input <patched_block71.bin>

    # WRITE commit — actually erases + writes + verifies. Same input
    # required, plus the explicit --commit flag.
    python3 vw_mqb_eps_write_block71.py write \
        --input <patched_block71.bin> --commit

Optional flags (apply to both subcommands):
    --login N         override SA2 login constant (default 44595 — the
                      well-known parametrization-tier login per CLAUDE.md
                      / WRITABLE.md). Use 28183 for coding-tier writes,
                      19249 for the alternate adaptation-tier.
    --backup-dir DIR  where to save backups / read output (default:
                      block71_<timestamp>/)
    --debug           ISO-TP/UDS debug logging

Recommended workflow:
    1. Run `read` first — confirms the SA2 handshake works at the
       requested login + dumps a clean copy of the current block as a
       safety baseline. If `read` fails, do NOT run `write` — the
       login or session is wrong.
    2. Run `write` (dry-run) with the patched .bin — confirms the diff
       is what you expect.
    3. Only then run `write --commit`.

Vehicle requirements:
    * Ignition ON, engine OFF
    * On newer cars: HOOD OPEN (defeats diagnostic firewall)
    * Battery support unit recommended (>= 12.5 V steady)
    * `tmux kill-session -t comma` if on a comma3 with openpilot up
    * Nothing else on the bus should be running diagnostics
"""

import argparse
import struct
import sys
import time
from datetime import datetime, date as date_t
from pathlib import Path

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    ACCESS_TYPE,
    ROUTINE_CONTROL_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda
import udsoncan

# ──────────────────────────────────────────────────────────────────────
# Constants (per CLAUDE.md / WRITABLE.md)
# ──────────────────────────────────────────────────────────────────────
MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x712 + 0x6A    # 0x77C
PARTITION_SELECTOR = 0x71    # the EEPROM short-block we're writing
BLOCK_SIZE = 1950            # bytes — verified from datasets/bin/
CAP_OFFSET = 0x3E8           # the 16-bit cap value (BE u16, cNm)

# SA2 — well-known seed-key formula `key = seed_uint32_BE + N`. Verified
# for coding-tier (N=28183) per upstream openpilot vw_mqb_config.py.
# Parametrization-tier (N=44595) is documented in CLAUDE.md / icanhack
# PQ EPS findings but not yet empirically confirmed for our MQB part.
DEFAULT_LOGIN = 44595

# Per ISO 14229-1:2020 §10.4, security level N uses subFunction (2N-1, 2N).
# Use level 2 (subfunctions 0x03/0x04) — same level vw_mqb_config.py uses.
class ACCESS_TYPE_LEVEL_2:
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2           # 0x04

# Transfer chunk size — keep small to avoid ISO-TP fragmentation issues.
TRANSFER_CHUNK = 0xFF


# ──────────────────────────────────────────────────────────────────────
# CRC-16/ARC (poly 0x8005, init 0x0000, reflected, xor 0)
# Same algorithm as patch_block71_torque_cap.py. Required for input
# validation — we MUST NOT write a block with a bad CRC.
# ──────────────────────────────────────────────────────────────────────
def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


# ──────────────────────────────────────────────────────────────────────
# Validators
# ──────────────────────────────────────────────────────────────────────
def validate_input(blob: bytes) -> tuple[bool, str]:
    """Return (ok, reason). Reject anything not exactly the expected size,
    not CRC-valid, or with a clearly-broken cap value."""
    if len(blob) != BLOCK_SIZE:
        return False, f"size {len(blob)} != expected {BLOCK_SIZE}"
    body, trailer = blob[:-2], blob[-2:]
    expected_crc = crc16_arc(body)
    actual_crc = struct.unpack(">H", trailer)[0]
    if expected_crc != actual_crc:
        return False, (f"CRC mismatch: trailer 0x{actual_crc:04X}, "
                       f"computed 0x{expected_crc:04X} — re-run patcher")
    cap = struct.unpack(">H", blob[CAP_OFFSET:CAP_OFFSET+2])[0]
    if cap > 1000:    # sanity ceiling — 10.00 Nm. cap is cNm.
        return False, f"cap value at 0x{CAP_OFFSET:X} = {cap} cNm seems implausibly high"
    if cap < 100:
        return False, f"cap value at 0x{CAP_OFFSET:X} = {cap} cNm seems implausibly low"
    return True, f"size={len(blob)}, CRC valid (0x{actual_crc:04X}), cap={cap} cNm ({cap/100:.2f} Nm)"


# ──────────────────────────────────────────────────────────────────────
# UDS helpers — read/write a partition by selector via $35/$34
# ──────────────────────────────────────────────────────────────────────
def upload_partition(uds: UdsClient, selector: int, size: int, log) -> bytes | None:
    """$35 RequestUpload + loop $36 + $37. Returns bytes on success,
    None on any failure (failure paths logged, no exception raised)."""
    log(f"  $35 RequestUpload selector=0x{selector:02X} size={size}")
    try:
        uds.request_upload(
            memory_address=selector, memory_size=size,
            memory_address_bytes=1, memory_size_bytes=4,
        )
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ {type(e).__name__}: {e}")
        return None
    out = bytearray()
    counter = 1
    deadline = time.time() + 30
    while len(out) < size:
        if time.time() > deadline:
            log(f"    ✗ upload timeout at {len(out)}/{size}")
            return None
        try:
            resp = uds.transfer_data(counter, b"")
        except (NegativeResponseError, MessageTimeoutError) as e:
            log(f"    ✗ transfer_data #{counter} {type(e).__name__}: {e}")
            return None
        chunk = bytes(resp.service_data.parameter_records) if hasattr(resp, "service_data") else bytes(resp)[1:]
        if not chunk:
            log(f"    ✗ empty transfer_data response at {len(out)}/{size}")
            return None
        out.extend(chunk)
        counter = 1 if counter == 0xFF else counter + 1
    try:
        uds.request_transfer_exit()
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ⚠ exit {type(e).__name__}: {e} — but data may be intact")
    return bytes(out[:size])


def download_partition(uds: UdsClient, selector: int, data: bytes, log) -> bool:
    """Erase + $34 RequestDownload + loop $36 + $37. Returns True on
    success, False on any failure."""
    # Erase first (mirror eps_flash.py pattern)
    log(f"  $31 EraseMemory selector=0x{selector:02X}")
    try:
        uds.routine_control(
            ROUTINE_CONTROL_TYPE.START,
            0xFF00,    # ERASE_MEMORY
            routine_option_record=bytes([0x01, selector]),
        )
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ erase {type(e).__name__}: {e}")
        return False

    log(f"  $34 RequestDownload selector=0x{selector:02X} size={len(data)}")
    try:
        dfi = udsoncan.DataFormatIdentifier(compression=0, encryption=0)
        memloc = udsoncan.MemoryLocation(
            address=selector, memorysize=len(data),
            address_format=8, memorysize_format=32,
        )
        uds.request_download(memloc, dfi=dfi)
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ requestDownload {type(e).__name__}: {e}")
        log(f"    ⚠⚠ block 0x{selector:02X} IS NOW ERASED but write failed.")
        log(f"       Re-run with same input ASAP — rack may not assist until restored.")
        return False

    log(f"  $36 TransferData ({len(data)} bytes in {(len(data)+TRANSFER_CHUNK-1)//TRANSFER_CHUNK} chunks)")
    counter = 1
    for off in range(0, len(data), TRANSFER_CHUNK):
        end = min(off + TRANSFER_CHUNK, len(data))
        try:
            uds.transfer_data(counter, data[off:end])
        except (NegativeResponseError, MessageTimeoutError) as e:
            log(f"    ✗ transferData #{counter} (offset {off}) {type(e).__name__}: {e}")
            log(f"    ⚠⚠ partial write — block 0x{selector:02X} is in indeterminate state.")
            return False
        counter = 1 if counter == 0xFF else counter + 1

    log(f"  $37 RequestTransferExit")
    try:
        uds.request_transfer_exit()
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ transferExit {type(e).__name__}: {e}")
        return False
    return True


# ──────────────────────────────────────────────────────────────────────
# SA2 handshake — single attempt, no retry on different login
# ──────────────────────────────────────────────────────────────────────
def security_access(uds: UdsClient, login: int, log) -> bool:
    """Returns True if auth succeeded. On NRC, returns False — script
    must NOT retry with a different login (risks lockout)."""
    log(f"  $27 03 REQUEST_SEED level 2")
    try:
        seed_resp = uds.security_access(ACCESS_TYPE_LEVEL_2.REQUEST_SEED)
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ {type(e).__name__}: {e}")
        return False
    seed = bytes(seed_resp.service_data.seed) if hasattr(seed_resp, "service_data") else bytes(seed_resp)
    if len(seed) != 4:
        log(f"    ✗ unexpected seed length {len(seed)} (expected 4)")
        return False
    if all(b == 0 for b in seed):
        log("    seed is all-zero — already authenticated, skipping send_key")
        return True
    seed_int = struct.unpack(">I", seed)[0]
    key_int = (seed_int + login) & 0xFFFFFFFF
    key = struct.pack(">I", key_int)
    log(f"    seed = 0x{seed_int:08X}, login = {login}, key = 0x{key_int:08X}")
    log(f"  $27 04 SEND_KEY")
    try:
        uds.security_access(ACCESS_TYPE_LEVEL_2.SEND_KEY, key)
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"    ✗ {type(e).__name__}: {e}")
        log(f"    HINT: login {login} did not auth. The well-known logins for")
        log(f"    this rack tier are 28183 (coding), 44595 (parametrization),")
        log(f"    19249 (adaptation alt). DO NOT spam — try one at a time.")
        return False
    log("    ✓ auth ok")
    return True


# ──────────────────────────────────────────────────────────────────────
# Shared setup — bring the rack up into "auth'd in programming session"
# state. Used by both `read` and `write` subcommands.
# ──────────────────────────────────────────────────────────────────────
def setup_session(login: int, log) -> UdsClient | None:
    """Returns an authenticated UdsClient, or None on any failure."""
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:
        log(f"FATAL: panda setup failed: {type(e).__name__}: {e}")
        return None

    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=2.0)

    log("\n── Programming session ($10 02) ──")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
        log("  ✓ programming session opened")
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        log("  Cannot proceed — programming session is required for partition I/O.")
        return None

    log(f"\n── SecurityAccess level 2, login {login} ──")
    if not security_access(uds, login, log):
        log("  Aborting — script will NOT retry with alternate logins.")
        return None

    return uds


def make_log(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.txt"
    log_file = open(log_path, "w")
    def log(msg: str) -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()
    return log, log_file


# ──────────────────────────────────────────────────────────────────────
# read subcommand — dump current block 0x71 to disk, no writes
# ──────────────────────────────────────────────────────────────────────
def cmd_read(args) -> int:
    out_dir = args.backup_dir or Path(f"block71_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    log, log_file = make_log(out_dir)
    log(f"Mode: READ (no writes)")
    log(f"Login: {args.login}")
    log(f"Output dir: {out_dir.resolve()}")
    log(f"Started: {datetime.now().isoformat()}")

    uds = setup_session(args.login, log)
    if uds is None:
        log_file.close()
        return 1

    log(f"\n── Reading block 0x{PARTITION_SELECTOR:02X} ($35 RequestUpload) ──")
    current = upload_partition(uds, PARTITION_SELECTOR, BLOCK_SIZE, log)
    if current is None:
        log("  ✗ read failed.")
        log("  $35 RequestUpload was denied. Possible causes:")
        log("    - Wrong login for this partition tier")
        log("    - Programming session was lost (idle timeout)")
        log("    - This selector requires a different upload mechanism")
        log_file.close()
        return 1

    out_file = args.output or (out_dir / f"block_0x{PARTITION_SELECTOR:02X}.bin")
    out_file.write_bytes(current)
    log(f"  ✓ saved {len(current)} bytes → {out_file}")

    # Verify CRC and report cap value
    ok, msg = validate_input(current)
    log(f"  {('✓' if ok else '⚠')} {msg}")
    if ok:
        cap = struct.unpack(">H", current[CAP_OFFSET:CAP_OFFSET+2])[0]
        log(f"  current torque cap at 0x{CAP_OFFSET:04X}: "
            f"{cap} cNm ({cap/100:.2f} Nm)")

    log("\n── Done. No writes were performed. ──")
    log("To diff this against a patched .bin and write it back, run:")
    log(f"  python3 vw_mqb_eps_write_block71.py write --input <patched.bin>")
    log_file.close()
    return 0


# ──────────────────────────────────────────────────────────────────────
# write subcommand — diff, optionally erase + write + verify
# ──────────────────────────────────────────────────────────────────────
def cmd_write(args) -> int:
    # Validate input BEFORE touching the ECU
    try:
        new_block = args.input.read_bytes()
    except Exception as e:
        print(f"FATAL: cannot read input file: {e}")
        return 1
    ok, msg = validate_input(new_block)
    if not ok:
        print(f"FATAL: input file rejected: {msg}")
        return 1
    print(f"Input OK: {args.input}")
    print(f"   {msg}")

    backup_dir = args.backup_dir or Path(f"backup_block71_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    log, log_file = make_log(backup_dir)
    log(f"Mode: {'COMMIT (will write)' if args.commit else 'DRY-RUN (no writes)'}")
    log(f"Login: {args.login}")
    log(f"Backup dir: {backup_dir.resolve()}")
    log(f"Started: {datetime.now().isoformat()}")

    uds = setup_session(args.login, log)
    if uds is None:
        log_file.close()
        return 1

    # Backup current block — MANDATORY before any write
    log(f"\n── Mandatory backup of current block 0x{PARTITION_SELECTOR:02X} ──")
    current = upload_partition(uds, PARTITION_SELECTOR, BLOCK_SIZE, log)
    if current is None:
        log("  ✗ backup failed — refusing to proceed.")
        log_file.close()
        return 1
    backup_file = backup_dir / f"block_0x{PARTITION_SELECTOR:02X}_original.bin"
    backup_file.write_bytes(current)
    log(f"  ✓ saved {len(current)} bytes → {backup_file.name}")

    bok, bmsg = validate_input(current)
    if not bok:
        log(f"  ⚠ current block 0x71 from ECU has unexpected shape: {bmsg}")
        log(f"  Refusing to write a 'patched' version on top — investigate first.")
        log_file.close()
        return 1
    log(f"  current block: {bmsg}")

    # Diff
    log(f"\n── Diff (original → new) ──")
    diff_bytes = [(i, a, b) for i, (a, b) in enumerate(zip(current, new_block)) if a != b]
    if not diff_bytes:
        log("  no differences — input already matches what's on the rack. Nothing to do.")
        log_file.close()
        return 0
    log(f"  {len(diff_bytes)} bytes differ")
    for i, a, b in diff_bytes:
        log(f"    +0x{i:04X}: 0x{a:02X} → 0x{b:02X}")
    cap_old = struct.unpack(">H", current[CAP_OFFSET:CAP_OFFSET+2])[0]
    cap_new = struct.unpack(">H", new_block[CAP_OFFSET:CAP_OFFSET+2])[0]
    log(f"  CAP at 0x{CAP_OFFSET:04X}: {cap_old} cNm ({cap_old/100:.2f} Nm) → "
        f"{cap_new} cNm ({cap_new/100:.2f} Nm)")

    if not args.commit:
        log("\n── DRY-RUN — no writes performed. ──")
        log("To actually write, re-run with --commit. The backup above is")
        log("preserved either way; if the commit fails partway, restore")
        log("by re-running with --input pointed at the backup file.")
        log_file.close()
        return 0

    log("\n══════════════════════════════════════════════════════════════")
    log("COMMIT path — erase + write begins now. DO NOT POWER OFF.")
    log("══════════════════════════════════════════════════════════════")
    if not download_partition(uds, PARTITION_SELECTOR, new_block, log):
        log("  ✗ write failed — see message above.")
        log(f"  Backup is at: {backup_file}")
        log_file.close()
        return 1

    log(f"\n── Read-back verification ──")
    readback = upload_partition(uds, PARTITION_SELECTOR, BLOCK_SIZE, log)
    if readback is None:
        log("  ✗ readback failed. Write may still be intact — ignition cycle and re-read.")
        log_file.close()
        return 1
    if readback != new_block:
        diff_count = sum(1 for a, b in zip(readback, new_block) if a != b)
        log(f"  ✗ readback mismatch: {diff_count} bytes differ from intended.")
        readback_file = backup_dir / f"block_0x{PARTITION_SELECTOR:02X}_readback_after_write.bin"
        readback_file.write_bytes(readback)
        log(f"     readback saved to {readback_file.name}")
        log_file.close()
        return 1
    log("  ✓ readback matches intended bytes exactly")

    log("\n══════════════════════════════════════════════════════════════")
    log("DONE. Block 0x71 written and verified.")
    log("Next steps:")
    log("  1. Cycle ignition (key off ~30 s, then on)")
    log("  2. Drive briefly straight on flat ground to re-learn adaptations")
    log("  3. Optional: $31 01 03 17 (Reset of Adaptation Values) if behavior")
    log("     seems off")
    log("  4. Re-run vw_mqb_eps_dump.py to confirm Parameter set version")
    log("     incremented and no DTCs raised")
    log("══════════════════════════════════════════════════════════════")
    log_file.close()
    return 0


# ──────────────────────────────────────────────────────────────────────
# Main — dispatch to read / write subcommands
# ──────────────────────────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--login", type=int, default=DEFAULT_LOGIN,
                   help=f"SA2 login constant (default {DEFAULT_LOGIN})")
    p.add_argument("--backup-dir", type=Path, default=None,
                   help="output directory for logs / backups / dumps "
                        "(default: block71_<timestamp>/ for read, "
                        "backup_block71_<timestamp>/ for write)")
    p.add_argument("--debug", action="store_true",
                   help="enable ISO-TP/UDS debug output")

    sub = p.add_subparsers(dest="action", required=True)

    sp_read = sub.add_parser("read", help="dump current block 0x71 to a file (no writes)")
    sp_read.add_argument("--output", type=Path, default=None,
                         help="output .bin path (default: <backup-dir>/block_0x71.bin)")

    sp_write = sub.add_parser("write", help="diff + optionally erase+write a patched block 0x71")
    sp_write.add_argument("--input", type=Path, required=True,
                          help="patched block 0x71 .bin "
                               "(output of patch_block71_torque_cap.py)")
    sp_write.add_argument("--commit", action="store_true",
                          help="actually erase + write. Default is dry-run "
                               "(stops after backup readback, before any destructive op).")

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
