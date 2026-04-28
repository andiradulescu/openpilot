#!/usr/bin/env python3
"""
Enumerate UDS sessions and OEM/supplier services on the 5Q0909143 EPS.

Hypothesis: ODIS uses only session $10 03 (extended) and SA L2 (subfunc 03/04).
The supplier (Continental/TRW/ZF) and VW factory likely have additional
sessions (esp. VWEndOfLine in $10 40..7F) and/or OEM-range ($A0..$BF) /
supplier-range ($F0..$FF) custom services that would unlock $23 / $35,
both of which return NRC 0x11 in standard extended session (confirmed by
vw_mqb_dump_zdc.py 2026-04-28).

PURELY READ-PROBE. No SA, no $2E, no $34/$36/$37. After each accepted
session change, immediately runs the canary probes ($23 / $35 small reads)
and then returns to default session ($10 01). Always returns to default
before exit, even on Ctrl-C / exception.

Worst case: triggers transient diagnostic events that clear on ignition
cycle. Do NOT run with engine running or while moving — keep ignition ON
and engine OFF, vehicle stationary.

Phases:
  1. Session enumeration: $10 NN for NN in 0x01..0x7F. Record positive
     responses (P2/P2* timing) and NRC for non-positive.
  2. For each NEWLY-accepted session (beyond known 0x01/0x02/0x03),
     retry the canary probes:
       - $23 22 5E 00 0004              (ReadMemoryByAddress, 4B at 0x5E00)
       - $35 00 11 70 0004              (RequestUpload, 4B from selector 0x70)
     Watch whether NRC changes from 0x11 to anything else.
  3. Service enumeration: send 1-byte request $XX for XX in 0xA0..0xBF
     (OEM range) and 0xF0..0xFF (supplier range). NRC 0x11 = service does
     not exist; NRC 0x13/0x12 = service exists but request malformed
     (the interesting case — names a discoverable handler).
  4. Always: $10 01 (default session) before exit.

Usage:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
      ~/Projects/re-vw/steering/vw_mqb_session_probe.py

    # quick single-session check:
    python3 vw_mqb_session_probe.py --session 0x60

    # only the service enumeration phase:
    python3 vw_mqb_session_probe.py --skip-sessions
"""

import argparse
import struct
import sys
import time

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    SERVICE_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
EPS_BUS = 1

# Sessions we already know are accepted — skip in the canary retry phase
# but still report their NRC for completeness.
KNOWN_SESSIONS = {0x01, 0x02, 0x03}

# Canary probes — small length, harmless even if the service does execute.
CANARY_READMEM_REQ = bytes([0x23, 0x22, 0x5E, 0x00, 0x00, 0x04])  # $23 22 SE 00 0004
CANARY_UPLOAD_REQ  = bytes([0x35, 0x00, 0x11, 0x70, 0x00, 0x04])  # $35 00 11 70 0004

OEM_SVC_RANGE      = range(0xA0, 0xC0)   # 0xA0..0xBF
SUPPLIER_SVC_RANGE = range(0xF0, 0x100)  # 0xF0..0xFF


def nrc_name(code: int) -> str:
    return {
        0x10: "generalReject",
        0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLengthOrInvalidFormat",
        0x14: "responseTooLong",
        0x21: "busyRepeatRequest",
        0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError",
        0x25: "noResponseFromSubnet",
        0x26: "failurePreventsExecutionOfRequestedAction",
        0x31: "requestOutOfRange",
        0x33: "securityAccessDenied",
        0x35: "invalidKey",
        0x36: "exceededNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired",
        0x70: "uploadDownloadNotAccepted",
        0x71: "transferDataSuspended",
        0x72: "generalProgrammingFailure",
        0x73: "wrongBlockSequenceCounter",
        0x78: "requestCorrectlyReceivedResponsePending",
        0x7E: "subFunctionNotSupportedInActiveSession",
        0x7F: "serviceNotSupportedInActiveSession",
    }.get(code, f"unknown(0x{code:02X})")


# ─── raw-frame helpers (UdsClient doesn't support arbitrary service IDs) ──────

def can_drain(panda: Panda) -> None:
    deadline = time.time() + 0.05
    while time.time() < deadline:
        if not panda.can_recv():
            break


def raw_uds_request(panda: Panda, payload: bytes, timeout: float = 0.3) -> bytes | None:
    """Single-frame ISO-TP only (payload <= 7 bytes). Sufficient for all probes here."""
    if len(payload) > 7:
        raise ValueError(f"raw_uds_request payload too long for single-frame: {len(payload)}")
    can_drain(panda)
    frame = bytes([len(payload)]) + payload + b"\x00" * (7 - len(payload))
    panda.can_send(MQB_EPS_TX, frame, EPS_BUS)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for addr, _ts, data, src in panda.can_recv():
            if addr == MQB_EPS_RX and src == EPS_BUS and len(data) >= 1:
                pci = data[0] >> 4
                if pci == 0x0:  # single frame
                    n = data[0] & 0x0F
                    return bytes(data[1:1 + n])
                # ignore flow-control / multi-frame for these tiny probes
        time.sleep(0.005)
    return None


def decode_response(req_sid: int, resp: bytes | None) -> tuple[str, str]:
    """Return ('positive'|'nrc'|'no-response', detail_string)."""
    if resp is None:
        return "no-response", "(timeout)"
    if len(resp) >= 1 and resp[0] == req_sid + 0x40:
        return "positive", resp.hex()
    if len(resp) >= 3 and resp[0] == 0x7F and resp[1] == req_sid:
        return "nrc", f"0x{resp[2]:02X} {nrc_name(resp[2])}"
    return "nrc", f"unexpected: {resp.hex()}"


# ─── phases ───────────────────────────────────────────────────────────────────

def open_extended(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended session — is the rack alive?")


def return_to_default(panda: Panda) -> None:
    """Best-effort $10 01. Never raise."""
    try:
        resp = raw_uds_request(panda, bytes([0x10, 0x01]))
        kind, detail = decode_response(0x10, resp)
        print(f"  $10 01 → {kind}: {detail}")
    except Exception as e:
        print(f"  ⚠ $10 01 (return to default) failed: {e}")
        print("  ⚠ ECU may be in a non-default session — ignition cycle to clear")


def phase_session_enum(panda: Panda, session_ids: list[int]) -> dict[int, dict]:
    """For each session ID, send $10 NN, record outcome, run canary probes if accepted."""
    results = {}
    print(f"\n──── Phase 1: enumerating {len(session_ids)} sessions ────")
    for sid in session_ids:
        resp = raw_uds_request(panda, bytes([0x10, sid]))
        kind, detail = decode_response(0x10, resp)
        rec = {"open": (kind, detail), "canary_23": None, "canary_35": None}
        marker = "  " if kind == "nrc" and detail.startswith("0x12") else ""

        if kind == "positive":
            tag = "NEW " if sid not in KNOWN_SESSIONS else "(known) "
            print(f"  $10 {sid:02X} → {tag}positive {detail}")

            # Canary probes in the new session
            r23 = raw_uds_request(panda, CANARY_READMEM_REQ)
            k23, d23 = decode_response(0x23, r23)
            rec["canary_23"] = (k23, d23)
            print(f"    canary $23 → {k23}: {d23}")

            r35 = raw_uds_request(panda, CANARY_UPLOAD_REQ)
            k35, d35 = decode_response(0x35, r35)
            rec["canary_35"] = (k35, d35)
            print(f"    canary $35 → {k35}: {d35}")

            # Return to extended for the next iteration (default would lose tester present)
            r03 = raw_uds_request(panda, bytes([0x10, 0x03]))
            k03, _ = decode_response(0x10, r03)
            if k03 != "positive":
                # If we can't get back to extended, bail out cleanly
                print("    ⚠ failed to re-enter extended after probe; aborting enumeration")
                results[sid] = rec
                break
        elif kind == "nrc":
            # Only print interesting NRCs (suppress flood of 0x12 subFunctionNotSupported)
            if not detail.startswith("0x12"):
                print(f"  $10 {sid:02X} → nrc: {detail}")
        else:
            print(f"  $10 {sid:02X} → {kind}: {detail}")
        results[sid] = rec
    return results


def phase_service_enum(panda: Panda) -> dict[int, tuple[str, str]]:
    """Send 1-byte $XX for each candidate service ID. NRC 0x11 = doesn't exist."""
    results = {}
    print(f"\n──── Phase 2: probing OEM ($A0..$BF) and supplier ($F0..$FF) services ────")
    print("  NRC 0x11 = serviceNotSupported (skipped from print)")
    print("  any other response = service handler exists\n")
    for sid in list(OEM_SVC_RANGE) + list(SUPPLIER_SVC_RANGE):
        resp = raw_uds_request(panda, bytes([sid]))
        kind, detail = decode_response(sid, resp)
        results[sid] = (kind, detail)
        # Filter the noise: only print when something actually responds
        if kind == "nrc" and detail.startswith("0x11"):
            continue  # service doesn't exist
        print(f"  ${sid:02X} → {kind}: {detail}")
    return results


def report(session_results: dict, service_results: dict) -> None:
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)

    new_sessions = [
        sid for sid, rec in session_results.items()
        if rec["open"][0] == "positive" and sid not in KNOWN_SESSIONS
    ]
    print(f"\nNew sessions accepted: {len(new_sessions)}")
    for sid in new_sessions:
        rec = session_results[sid]
        print(f"  $10 {sid:02X}: open={rec['open'][1]}")
        if rec["canary_23"]:
            print(f"    $23 in this session: {rec['canary_23'][0]}: {rec['canary_23'][1]}")
        if rec["canary_35"]:
            print(f"    $35 in this session: {rec['canary_35'][0]}: {rec['canary_35'][1]}")

    interesting_svcs = [
        sid for sid, (kind, detail) in service_results.items()
        if not (kind == "nrc" and detail.startswith("0x11"))
    ]
    print(f"\nCustom services with handlers: {len(interesting_svcs)}")
    for sid in interesting_svcs:
        kind, detail = service_results[sid]
        print(f"  ${sid:02X}: {kind}: {detail}")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--debug", action="store_true", help="enable ISO-TP/UDS debug output")
    p.add_argument("--session", type=lambda s: int(s, 0),
                   help="probe a single session ID (e.g. 0x60) and exit")
    p.add_argument("--skip-sessions", action="store_true",
                   help="skip phase 1 (session enum)")
    p.add_argument("--skip-services", action="store_true",
                   help="skip phase 2 (custom service enum)")
    p.add_argument("--lo", type=lambda s: int(s, 0), default=0x01,
                   help="session enum start (default 0x01)")
    p.add_argument("--hi", type=lambda s: int(s, 0), default=0x7F,
                   help="session enum end inclusive (default 0x7F)")
    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, EPS_BUS, timeout=0.2)

    print("Started:", time.strftime("%Y-%m-%dT%H:%M:%S"))
    print(f"INFO: connecting to panda {panda.get_serial()}")
    open_extended(uds)
    print("Opened extended session ($10 03)")

    session_results: dict = {}
    service_results: dict = {}

    try:
        if args.session is not None:
            session_results = phase_session_enum(panda, [args.session])
        elif not args.skip_sessions:
            ids = [s for s in range(args.lo, args.hi + 1) if s != 0x00 and s != 0x7F]
            session_results = phase_session_enum(panda, ids)

        if not args.skip_services:
            service_results = phase_service_enum(panda)

        report(session_results, service_results)
    finally:
        print("\n──── Cleanup: returning to default session ────")
        return_to_default(panda)

    return 0


if __name__ == "__main__":
    sys.exit(main())
