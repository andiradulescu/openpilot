#!/usr/bin/env python3
"""
Write a full ODIS-E parametrize dataset to the VW MQB EPS (module 0x44) via
the SAME wire protocol ODIS-E uses, derived from the captured ODIS-E trace
2026-05-05 (odis-write-dataset/trace_logs/TMBLJ9NS3J8068062_20260505T142956_CAN.vmt).

Input is the dataset XML directly — `<PARAMETER_DATA START_ADDRESS=...>` blocks
plus ZDC_NAME / ZDC_VERSION / LOGIN attributes are parsed and replayed. This
matches what ODIS does when running "010.01 Writing the Data Set".

Wire protocol replayed (per-block-write order: 0x71 then 0x70):

  $10 03                             open extended session
  $10 40                             VW OEM custom session ("parametrize")
  $27 03 / $27 04 + login            SecurityAccess L2 (login=44595 default,
                                       SA key = (seed + login) BE u32)
  $2E F198 <6 bytes>                 workshop tester fingerprint
  $2E F199 <YY MM DD BCD>            programming date
  $31 01 0300 03 01 00               precondition routine (RID 0x0300 start)
  $31 03 0300                          and request results
    for each PARAMETER_DATA block:
      $34 00 44 <addr u32 BE> <size u32 BE>  RequestDownload
      $36 NN <data>                          TransferData chunks (server-
                                              negotiated max block length)
      $37                                    RequestTransferExit
      $31 01 02EF 03 01 00                   verify routine
      $31 03 02EF                              and request results
  $2E F1A0 <ZDC_NAME ASCII>          stamp parameter set part number
  $2E F1A1 <ZDC_VERSION ASCII>       stamp parameter set version
  $2E F1A4 <equipment-code 12 B>     restore previous F1A4 (or stomp per ODIS,
                                       see --f1a4)
  $11 02                             ECU reset (key-off-on)
  $10 03                             reopen extended session
  $14 FF FF FF                       clear all DTCs

═════════════════════════════════════════════════════════════════════
SAFETY POSTURE
═════════════════════════════════════════════════════════════════════
Default is DRY-RUN: full handshake + diff + per-block CRC validation, but no
$34/$36/$37/$2E goes out. --commit required for the actual write.

CRC trailer of the block_0x71 payload is validated client-side BEFORE any
ECU contact (CRC-16/ARC, poly 0x8005, reflected, init 0). The ECU also
validates server-side after each $37; mismatch raises NRC.

F1A4 is read at the very start (before any session change) and written
back at the very end. ODIS replaces F1A4 with FF…FE which has been
observed to break LKAS-from-button on this rack (memory note
f1a4_reset_by_odis_e.md). Use --f1a4=stomp to do what ODIS does instead.

Vehicle requirements:
  * Ignition ON, engine OFF
  * Hood OPEN if your model year has the diagnostic firewall
  * Battery support unit recommended (≥ 12.5 V steady)
  * `tmux kill-session -t comma` if running on a comma3 with openpilot up

Run from the openpilot tree (uses opendbc UdsClient + panda):
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
        ~/Projects/re-vw/steering/vw_mqb_eps_write_dataset.py \\
        --xml ~/Projects/re-vw/steering/datasets/\\
GetParametrizeDataDataset_TMBLJ9NS3J8068062_0044_5Q0909143P_5Q_500cnm.xml \\
        --commit
"""

from __future__ import annotations

import argparse
import re
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
    DATA_IDENTIFIER_TYPE,
    ACCESS_TYPE,
    ROUTINE_CONTROL_TYPE,
    RESET_TYPE,
    DTC_GROUP_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x712 + 0x6A   # = 0x77C

PARAM_LOGIN = 44595
SA_REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
SA_SEND_KEY     = ACCESS_TYPE.SEND_KEY     + 2   # 0x04

VW_PARAMETRIZE_SESSION = 0x40   # observed ODIS-E custom session after $10 03

# RoutineControl identifiers replayed verbatim from the ODIS trace.
RID_PRECONDITION = 0x0300       # before first $34
RID_VERIFY       = 0x02EF       # after each $37
ROUTINE_OPTIONS  = bytes([0x03, 0x01, 0x00])   # constant in trace, semantics unknown

DID_F198 = DATA_IDENTIFIER_TYPE.REPAIR_SHOP_CODE_OR_TESTER_SERIAL_NUMBER     # 0xF198
DID_F199 = DATA_IDENTIFIER_TYPE.PROGRAMMING_DATE                              # 0xF199
DID_F1A0 = DATA_IDENTIFIER_TYPE.VW_APPLICATION_DATA_IDENTIFIATION_NUMBER \
    if hasattr(DATA_IDENTIFIER_TYPE, "VW_APPLICATION_DATA_IDENTIFIATION_NUMBER") else 0xF1A0
DID_F1A1 = 0xF1A1
DID_F1A4 = 0xF1A4

# Block 0x71 cap location (informational; only checked when block_0x71 present)
CAP_OFFSET = 0x3E8


# ─────────────────────────────────────────────────────────────────────
# Dataset XML parsing
# ─────────────────────────────────────────────────────────────────────
PARAM_BLOCK_RE = re.compile(
    rb'<PARAMETER_DATA\b([^>]*)>([^<]+)</PARAMETER_DATA>'
)
ATTR_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')


def parse_dataset_xml(path: Path) -> dict:
    """Return {'blocks': [(addr_int, bytes, attrs_dict), ...],
              'zdc_name', 'zdc_version', 'login', 'diag_addr'}.

    Blocks come back in the order they appear in the XML, which matches
    the ODIS-E write order (0x71 then 0x70 for module 0x44 datasets).
    """
    raw = path.read_bytes()
    blocks = []
    zdc_name = zdc_version = login = diag_addr = None
    for m in PARAM_BLOCK_RE.finditer(raw):
        attrs_raw, payload_raw = m.group(1), m.group(2)
        attrs = {k.decode(): v.decode() for k, v in ATTR_RE.findall(attrs_raw)}
        payload = bytes(int(tok, 16) for tok in payload_raw.replace(b" ", b"").split(b",") if tok)
        addr = int(attrs["START_ADDRESS"], 16)
        blocks.append((addr, payload, attrs))
        zdc_name = attrs.get("ZDC_NAME", zdc_name)
        zdc_version = attrs.get("ZDC_VERSION", zdc_version)
        login = attrs.get("LOGIN", login)
        diag_addr = attrs.get("DIAGNOSTIC_ADDRESS", diag_addr)
    if not blocks:
        raise ValueError(f"no PARAMETER_DATA elements in {path}")
    return {
        "blocks": blocks,
        "zdc_name": zdc_name,
        "zdc_version": zdc_version,
        "login": int(login) if login else None,
        "diag_addr": int(diag_addr, 16) if diag_addr else None,
    }


# ─────────────────────────────────────────────────────────────────────
# CRC-16/ARC for block_0x71 trailer validation
# ─────────────────────────────────────────────────────────────────────
def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def report_block(addr: int, payload: bytes, log) -> None:
    log(f"  block 0x{addr:02X}: {len(payload)} bytes")
    if addr == 0x71 and len(payload) >= 2:
        body, trailer = payload[:-2], payload[-2:]
        stored = struct.unpack(">H", trailer)[0]
        computed = crc16_arc(body)
        ok = "✓" if stored == computed else "✗"
        log(f"    {ok} CRC-16/ARC stored=0x{stored:04X} computed=0x{computed:04X}")
        if len(payload) >= CAP_OFFSET + 2:
            cap = struct.unpack(">H", payload[CAP_OFFSET:CAP_OFFSET + 2])[0]
            log(f"    cap @ 0x{CAP_OFFSET:04X}: {cap} cNm = {cap / 100:.2f} Nm")


# ─────────────────────────────────────────────────────────────────────
# UDS protocol steps
# ─────────────────────────────────────────────────────────────────────
def open_session(uds: UdsClient, sf: int, label: str, log) -> bool:
    log(f"── $10 {sf:02X}  {label} ──")
    try:
        uds.diagnostic_session_control(sf)
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        return False
    log(f"  ✓ session 0x{sf:02X} entered")
    return True


def identify(uds: UdsClient, log) -> dict:
    """Return a {DID: bytes_or_None} fingerprint of the rack."""
    log("\n── ECU identification ──")
    out = {}
    for label, did in [
        ("HW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER),
        ("SW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER),
        ("SW ver",   DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER),
        ("ODX file", DATA_IDENTIFIER_TYPE.ODX_FILE),
        ("ZDC name (F1A0)", DID_F1A0),
        ("ZDC version (F1A1)", DID_F1A1),
        ("Equipment (F1A4)", DID_F1A4),
    ]:
        try:
            v = uds.read_data_by_identifier(did)
            out[did] = v
            try:
                pretty = v.decode("utf-8").rstrip("\x00 ").strip()
                if not pretty.isprintable():
                    raise ValueError
                log(f"  {label:>20}: {pretty}")
            except (UnicodeDecodeError, ValueError):
                log(f"  {label:>20}: {v.hex()}")
        except (NegativeResponseError, MessageTimeoutError) as e:
            out[did] = None
            log(f"  {label:>20}: <error: {type(e).__name__}>")
    return out


def _nrc_byte(e: NegativeResponseError) -> int | None:
    for attr in ("code", "response"):
        v = getattr(e, attr, None)
        if isinstance(v, int):
            return v
        c = getattr(v, "code", None)
        if isinstance(c, int):
            return c
    return None


def security_access(uds: UdsClient, login: int, log) -> bool:
    log(f"\n── SecurityAccess L2 (login {login}) ──")
    try:
        seed = uds.security_access(SA_REQUEST_SEED)
    except NegativeResponseError as e:
        log(f"  ✗ requestSeed: NRC 0x{_nrc_byte(e):02X}" if _nrc_byte(e) is not None else f"  ✗ {e}")
        return False
    except MessageTimeoutError as e:
        log(f"  ✗ requestSeed timeout: {e}")
        return False
    if len(seed) != 4:
        log(f"  ✗ unexpected seed length {len(seed)}: {seed.hex()}")
        return False
    seed_int = struct.unpack("!I", seed)[0]
    key_int = (seed_int + login) & 0xFFFFFFFF
    log(f"  seed=0x{seed_int:08X} login={login} key=0x{key_int:08X} (seed+login)")
    try:
        uds.security_access(SA_SEND_KEY, struct.pack("!I", key_int))
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        log(f"  ✗ sendKey NRC 0x{nrc:02X}" if nrc is not None else f"  ✗ sendKey: {e}")
        return False
    except MessageTimeoutError as e:
        log(f"  ✗ sendKey timeout: {e}")
        return False
    log("  ✓ authenticated")
    return True


def write_fingerprint(uds: UdsClient, tester: bytes, log) -> bool:
    """$2E F198 (6 bytes workshop) + $2E F199 (3 bytes BCD date)."""
    log("\n── Workshop fingerprint stamps ──")
    try:
        uds.write_data_by_identifier(DID_F198, tester)
        log(f"  ✓ $2E F198 = {tester.hex()}")
        d = date_t.today()
        date_bcd = bytes([d.year - 2000, d.month, d.day])
        uds.write_data_by_identifier(DID_F199, date_bcd)
        log(f"  ✓ $2E F199 = {date_bcd.hex()} ({d.year:04d}-{d.month:02d}-{d.day:02d})")
        return True
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        return False


def run_routine(uds: UdsClient, rid: int, label: str, log) -> bool:
    """$31 01 <RID> + $31 03 <RID> with the constant ODIS option triplet."""
    log(f"\n── RoutineControl RID 0x{rid:04X} ({label}) ──")
    try:
        uds.routine_control(ROUTINE_CONTROL_TYPE.START, rid, ROUTINE_OPTIONS)
        log(f"  ✓ start ($31 01 {rid:04X} {ROUTINE_OPTIONS.hex()})")
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ start: {type(e).__name__}: {e}")
        return False
    try:
        result = uds.routine_control(ROUTINE_CONTROL_TYPE.REQUEST_RESULTS, rid)
        log(f"  ✓ result ($31 03 {rid:04X}): {result.hex() or '<empty>'}")
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ requestResults: {type(e).__name__}: {e}")
        return False
    return True


def transfer_block(uds: UdsClient, addr: int, payload: bytes, log) -> bool:
    """$34 + $36×N + $37 + post-flash verify routine."""
    log(f"\n── Block 0x{addr:02X}: $34 RequestDownload + $36 TransferData + $37 ──")
    log(f"  {len(payload)} bytes  (addr=0x{addr:08X}, size=0x{len(payload):08X})")
    try:
        max_block_len = uds.request_download(
            memory_address=addr, memory_size=len(payload),
            memory_address_bytes=4, memory_size_bytes=4, data_format=0x00,
        )
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ $34: {type(e).__name__}: {e}")
        return False
    chunk_size = max_block_len - 2     # subtract $36 + seq overhead
    log(f"  ✓ $34 ok; server max_block_len=0x{max_block_len:04X}, chunk_size={chunk_size}")
    seq = 1
    sent = 0
    while sent < len(payload):
        chunk = payload[sent:sent + chunk_size]
        try:
            uds.transfer_data(seq & 0xFF, chunk)
        except (NegativeResponseError, MessageTimeoutError) as e:
            log(f"  ✗ $36 seq=0x{seq & 0xFF:02X} ({sent} -> {sent + len(chunk)}): "
                f"{type(e).__name__}: {e}")
            return False
        sent += len(chunk)
        seq += 1
    log(f"  ✓ $36 streamed {sent} bytes in {seq - 1} chunks")
    try:
        uds.request_transfer_exit()
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ $37: {type(e).__name__}: {e}")
        return False
    log("  ✓ $37 RequestTransferExit accepted")
    return run_routine(uds, RID_VERIFY, f"verify block 0x{addr:02X}", log)


def stamp_dataset_identity(uds: UdsClient, zdc_name: str, zdc_version: str,
                           f1a4: bytes, log) -> bool:
    log("\n── Post-write dataset-identity stamps ──")
    try:
        name_bytes = zdc_name.encode("ascii")
        uds.write_data_by_identifier(DID_F1A0, name_bytes)
        log(f"  ✓ $2E F1A0 = {name_bytes!r} ({len(name_bytes)} B)")
        ver_bytes = zdc_version.encode("ascii")
        uds.write_data_by_identifier(DID_F1A1, ver_bytes)
        log(f"  ✓ $2E F1A1 = {ver_bytes!r} ({len(ver_bytes)} B)")
        uds.write_data_by_identifier(DID_F1A4, f1a4)
        log(f"  ✓ $2E F1A4 = {f1a4.hex()} ({len(f1a4)} B)")
        return True
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        return False


def ecu_reset_and_clear_dtc(uds: UdsClient, log) -> bool:
    log("\n── $11 02 ECUReset (key-off-on) ──")
    try:
        uds.ecu_reset(RESET_TYPE.KEY_OFF_ON)
        log("  ✓ reset accepted; pausing 2 s for re-init")
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ✗ {type(e).__name__}: {e}")
        return False
    time.sleep(2.0)
    if not open_session(uds, SESSION_TYPE.EXTENDED_DIAGNOSTIC, "extended (post-reset)", log):
        return False
    log("\n── $14 FF FF FF ClearDiagnosticInformation ──")
    try:
        uds.clear_diagnostic_information(DTC_GROUP_TYPE.ALL)
        log("  ✓ DTCs cleared")
    except (NegativeResponseError, MessageTimeoutError) as e:
        log(f"  ⚠ DTC clear: {type(e).__name__}: {e}")
    return True


# ─────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────
def make_log(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    f = open(out_dir / "log.txt", "w")
    def log(msg: str = "") -> None:
        print(msg)
        f.write(msg + "\n")
        f.flush()
    return log, f


def setup_panda(log) -> Panda | None:
    try:
        p = Panda()
        p.set_safety_mode(CarParams.SafetyModel.elm327)
        return p
    except Exception as e:
        log(f"FATAL: panda setup failed: {type(e).__name__}: {e}")
        return None


def cmd_write(args) -> int:
    # 1. Parse + validate XML before any ECU contact
    ds = parse_dataset_xml(args.xml)
    print(f"Dataset: {args.xml}")
    print(f"  ZDC_NAME    = {ds['zdc_name']}")
    print(f"  ZDC_VERSION = {ds['zdc_version']}")
    print(f"  LOGIN       = {ds['login']}")
    print(f"  blocks      = {[f'0x{a:02X}({len(p)}B)' for a, p, _ in ds['blocks']]}")
    if ds["diag_addr"] is not None and ds["diag_addr"] != 0x44:
        print(f"FATAL: dataset is for diagnostic_address 0x{ds['diag_addr']:04X}, not 0x0044 (EPS)")
        return 1
    for addr, payload, _ in ds["blocks"]:
        if addr == 0x71 and len(payload) >= 2:
            stored = struct.unpack(">H", payload[-2:])[0]
            computed = crc16_arc(payload[:-2])
            if stored != computed:
                print(f"FATAL: block_0x71 CRC mismatch (stored=0x{stored:04X} "
                      f"computed=0x{computed:04X}) — XML is corrupt or hand-edited "
                      f"without recomputing the trailer.")
                return 1
    login = args.login if args.login is not None else (ds["login"] or PARAM_LOGIN)

    out_dir = args.output_dir or Path(f"dataset_write_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    log, log_file = make_log(out_dir)
    try:
        log(f"Mode:    {'COMMIT' if args.commit else 'DRY-RUN'}")
        log(f"Started: {datetime.now().isoformat()}")
        log(f"XML:     {args.xml}")
        log(f"Login:   {login}")
        log(f"F1A4 mode: {args.f1a4}")
        log("\n── Dataset summary ──")
        for addr, payload, _ in ds["blocks"]:
            report_block(addr, payload, log)

        panda = setup_panda(log)
        if panda is None:
            return 1
        # timeout=10 for $34/$36/$37: server-side CRC validation on $37 can
        # take a couple of seconds, and the routine-control verify after each
        # block can take longer than the default 1 s.
        uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=10.0,
                        response_pending_timeout=15.0)

        # 2. Open extended session and read current F1A4 BEFORE anything else.
        if not open_session(uds, SESSION_TYPE.EXTENDED_DIAGNOSTIC, "extended", log):
            return 1
        ident = identify(uds, log)
        prior_f1a4 = ident.get(DID_F1A4)
        if prior_f1a4 is None:
            log(f"\n  ⚠ could not read F1A4 — restore-prior is unavailable.")
        else:
            log(f"\n  prior F1A4 captured: {prior_f1a4.hex()} ({len(prior_f1a4)} B)")
            (out_dir / "f1a4_prior.bin").write_bytes(prior_f1a4)

        # 3. Decide the F1A4 we'll write at the end.
        if args.f1a4 == "preserve":
            if prior_f1a4 is None:
                log("FATAL: --f1a4=preserve but rack F1A4 read failed.")
                return 1
            f1a4_to_write = prior_f1a4
        elif args.f1a4 == "stomp":
            f1a4_to_write = bytes.fromhex("FF" * 11 + "FE")  # 12 B, ODIS catalog default
        else:
            try:
                f1a4_to_write = bytes.fromhex(args.f1a4.replace(" ", ""))
            except ValueError:
                log(f"FATAL: --f1a4={args.f1a4!r} is neither preserve/stomp nor a hex string")
                return 1
            if len(f1a4_to_write) != 12:
                log(f"FATAL: explicit --f1a4 must be 12 bytes (24 hex chars), got {len(f1a4_to_write)}")
                return 1
        log(f"  F1A4 plan: write {f1a4_to_write.hex()} ({len(f1a4_to_write)} B) "
            f"after dataset transfer")

        if not args.commit:
            log("\n── DRY-RUN — stopping before $10 40 / SA / write. ──")
            log("Re-run with --commit to actually write the dataset.")
            return 0

        # 4. The actual ODIS-faithful write sequence.
        if not open_session(uds, VW_PARAMETRIZE_SESSION, "VW parametrize (custom)", log):
            return 1
        if not security_access(uds, login, log):
            return 1
        tester = bytes.fromhex(args.workshop_tester)
        if len(tester) != 6:
            log(f"FATAL: --workshop-tester must be 12 hex chars, got {len(tester)} bytes")
            return 1
        if not write_fingerprint(uds, tester, log):
            log("  (continuing — some racks accept the dataset write without these)")
        if not run_routine(uds, RID_PRECONDITION, "precondition", log):
            return 1
        for addr, payload, _ in ds["blocks"]:
            if not transfer_block(uds, addr, payload, log):
                log(f"\n  ✗ block 0x{addr:02X} write failed — STOPPING.")
                log(f"  Other blocks were NOT transferred.")
                log(f"  prior F1A4 captured: {out_dir / 'f1a4_prior.bin'}")
                return 1
        if not stamp_dataset_identity(uds, ds["zdc_name"], ds["zdc_version"],
                                       f1a4_to_write, log):
            log("  ✗ identity stamp failed — DTCs likely set, F1A4 may be in")
            log("    intermediate state. Investigate before driving.")
            return 1
        if not ecu_reset_and_clear_dtc(uds, log):
            log("  ⚠ reset/DTC clear had errors — operator should ignition-cycle.")

        log("\n══════════════════════════════════════════════════════════════")
        log("DONE. Dataset written via ODIS-faithful protocol.")
        log("Verify on car:")
        log("  • LKAS-from-button still works (regression check for F1A4 stomp)")
        log("  • Cap behaves: openpilot can hold > 3.0 Nm without steerFaultTemporary")
        log(f"  • Prior F1A4 saved at {out_dir / 'f1a4_prior.bin'}")
        log("══════════════════════════════════════════════════════════════")
        return 0
    finally:
        log_file.close()


def cmd_inspect(args) -> int:
    """Parse + summarise the XML without touching the rack."""
    ds = parse_dataset_xml(args.xml)
    print(f"Dataset:    {args.xml}")
    print(f"diag_addr:  0x{ds['diag_addr']:04X}" if ds['diag_addr'] is not None else "diag_addr:  -")
    print(f"ZDC_NAME:   {ds['zdc_name']}")
    print(f"ZDC_VER:    {ds['zdc_version']}")
    print(f"LOGIN:      {ds['login']}")
    print(f"blocks:     {len(ds['blocks'])}")
    for addr, payload, _ in ds["blocks"]:
        report_block(addr, payload, lambda s="": print(s))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--debug", action="store_true", help="enable opendbc UDS debug logging")
    sub = p.add_subparsers(dest="action", required=True)

    sp_w = sub.add_parser("write", help="write a dataset XML to the EPS (default DRY-RUN)")
    sp_w.add_argument("--xml", type=Path, required=True,
                      help="dataset XML (e.g. GetParametrizeDataDataset_…_500cnm.xml). "
                           "Both PARAMETER_DATA blocks (0x71 then 0x70) get written in "
                           "the order they appear, matching ODIS-E.")
    sp_w.add_argument("--commit", action="store_true",
                      help="actually write. Default is dry-run: parse + CRC-validate + "
                           "open session + identify + read F1A4, then stop.")
    sp_w.add_argument("--login", type=int, default=None,
                      help=f"override SA L2 login (default: dataset's LOGIN attribute, "
                           f"falling back to {PARAM_LOGIN})")
    sp_w.add_argument("--workshop-tester", default="111111111111",
                      help="6-byte (12-hex) workshop tester ID for $2E F198. "
                           "Default = '111111111111' to match the captured ODIS trace.")
    sp_w.add_argument("--f1a4", default="preserve",
                      help="what to write to F1A4 at the end of the sequence. "
                           "'preserve' (default) = restore the value read at start; "
                           "'stomp' = FF×11+FE like ODIS does (breaks LKAS-from-button "
                           "on this rack — see memory note f1a4_reset_by_odis_e.md); "
                           "or 24 hex chars for an explicit value.")
    sp_w.add_argument("--output-dir", type=Path, default=None,
                      help="output dir for log + F1A4 backup (default: dataset_write_<ts>/)")

    sp_i = sub.add_parser("inspect", help="parse + summarise an XML, no ECU contact")
    sp_i.add_argument("--xml", type=Path, required=True)

    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")
    if args.action == "write":
        return cmd_write(args)
    if args.action == "inspect":
        return cmd_inspect(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
