#!/usr/bin/env python3
"""
Probe UDS sessions and OEM/supplier services on the 5Q0909143 EPS.

DEFAULT BEHAVIOR (no flags): test the highest-prior hypothesis from the
BV pool grep (2026-04-28): does `$10 4F` (Development Session) accept,
and do `$23 ReadMemoryByAddress` / `$35 RequestUpload` work in it?
The pool description for $10 4F: "alle Services erlaubt die der Server
implementiert hat" — every service the firmware implements is reachable.

Output ends with a VERDICT block and a concrete next command.

Other flags:
  --scan       full session enumeration $10 01..7F (then canaries in any
               accepted session beyond 01/02/03)
  --services   sweep OEM range $A0..$BF and supplier range $F0..$FF for
               custom service handlers (NRC 0x11 = doesn't exist)
  --session NN probe one session ID and exit
  --lo / --hi  bounds for --scan (default 0x01..0x7F)

Usage from a comma3 with openpilot stopped:
  tmux kill-session -t comma
  cd /data/openpilot && git pull
  # ignition ON, engine OFF, vehicle in park, hood open
  python selfdrive/debug/car/vw_mqb_session_probe.py
"""

import argparse
import sys
import time

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    SESSION_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
DEFAULT_EPS_BUS = 1  # comma3 enumeration of the F-CAN segment behind J533;
                     # validated empirically via LKU_Derating + dump_zdc.
                     # On a standalone OBD-II panda this same physical segment
                     # is bus 0 (per icanhack's pqflasher) — bus numbering
                     # differs between standalone panda and comma3-internal.
EPS_BUS = DEFAULT_EPS_BUS  # overridden by --bus in main()

DEV_SESSION = 0x4F  # the headline target — "Development Session" per BV pool

# Sessions we already know are accepted; not "new" findings.
KNOWN_SESSIONS = {0x01, 0x02, 0x03}

# Canary probes — small length, single-frame ISO-TP. Goal is to detect
# whether the *service* is reachable, not to actually read useful bytes.
CANARY_READMEM_REQ = bytes([0x23, 0x22, 0x5E, 0x00, 0x00, 0x04])  # $23 22 5E00 0004
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


# ─── session phase ────────────────────────────────────────────────────────────

def open_extended(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended session — is the rack alive?")


def return_to_default(panda: Panda) -> None:
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
    if len(session_ids) == 1 and session_ids[0] == DEV_SESSION:
        title = f"Probing $10 {DEV_SESSION:02X} (Development Session — BV pool lead)"
    else:
        title = f"Enumerating {len(session_ids)} session(s)"
    print(f"\n──── {title} ────")

    for sid in session_ids:
        resp = raw_uds_request(panda, bytes([0x10, sid]))
        kind, detail = decode_response(0x10, resp)
        rec = {"open": (kind, detail), "canary_23": None, "canary_35": None}

        if kind == "positive":
            tag = "(known) " if sid in KNOWN_SESSIONS else "NEW "
            print(f"  $10 {sid:02X} → {tag}positive {detail}")

            r23 = raw_uds_request(panda, CANARY_READMEM_REQ)
            k23, d23 = decode_response(0x23, r23)
            rec["canary_23"] = (k23, d23)
            print(f"    canary $23 22 5E00 0004 → {k23}: {d23}")

            r35 = raw_uds_request(panda, CANARY_UPLOAD_REQ)
            k35, d35 = decode_response(0x35, r35)
            rec["canary_35"] = (k35, d35)
            print(f"    canary $35 00 11 70 0004 → {k35}: {d35}")

            r03 = raw_uds_request(panda, bytes([0x10, 0x03]))
            k03, _ = decode_response(0x10, r03)
            if k03 != "positive":
                print("    ⚠ failed to re-enter extended after probe; aborting enumeration")
                results[sid] = rec
                break
        elif kind == "nrc":
            if not detail.startswith("0x12"):  # suppress flood of subFunctionNotSupported
                print(f"  $10 {sid:02X} → nrc: {detail}")
        else:
            print(f"  $10 {sid:02X} → {kind}: {detail}")
        results[sid] = rec
    return results


def phase_service_enum(panda: Panda) -> dict[int, tuple[str, str]]:
    """Send 1-byte $XX for each candidate service ID. NRC 0x11 = doesn't exist."""
    results = {}
    print("\n──── Probing OEM ($A0..$BF) and supplier ($F0..$FF) services ────")
    print("  NRC 0x11 = serviceNotSupported (suppressed)")
    print("  any other response = service handler exists\n")
    for sid in list(OEM_SVC_RANGE) + list(SUPPLIER_SVC_RANGE):
        resp = raw_uds_request(panda, bytes([sid]))
        kind, detail = decode_response(sid, resp)
        results[sid] = (kind, detail)
        if kind == "nrc" and detail.startswith("0x11"):
            continue
        print(f"  ${sid:02X} → {kind}: {detail}")
    return results


# ─── verdict / next-step printer ──────────────────────────────────────────────

def _starts(detail: str | None, code: str) -> bool:
    return isinstance(detail, str) and detail.startswith(code)


def _canary_unlocked(c: tuple[str, str] | None) -> bool:
    """positive return OR NRC 0x31 (out of range) — both mean the service works."""
    if c is None:
        return False
    kind, detail = c
    return kind == "positive" or _starts(detail, "0x31")


def _canary_sa_locked(c: tuple[str, str] | None) -> bool:
    return c is not None and c[0] == "nrc" and _starts(c[1], "0x33")


def _canary_no_service(c: tuple[str, str] | None) -> bool:
    return c is not None and c[0] == "nrc" and (
        _starts(c[1], "0x11") or _starts(c[1], "0x7F")
    )


def print_verdict(session_results: dict, service_results: dict) -> None:
    dev = session_results.get(DEV_SESSION)
    bar = "═" * 70
    print()
    print(bar)

    # Did we even probe $10 4F? If not, just summarize what was found.
    if dev is None:
        print("VERDICT: (no $10 4F probe in this run — pass no flags or --session 0x4F)")
        print(bar)
        new_sessions = [
            sid for sid, rec in session_results.items()
            if rec["open"][0] == "positive" and sid not in KNOWN_SESSIONS
        ]
        if new_sessions:
            print(f"New sessions accepted: {', '.join(f'$10 {s:02X}' for s in new_sessions)}")
            print("  Re-run focused on the most interesting one with:")
            for s in new_sessions[:3]:
                print(f"    python selfdrive/debug/car/vw_mqb_session_probe.py --session 0x{s:02X}")
        else:
            print("No new sessions accepted in this scan.")
        if service_results:
            interesting = [s for s, (k, d) in service_results.items()
                           if not (k == "nrc" and _starts(d, "0x11"))]
            if interesting:
                print(f"Custom services with handlers: {', '.join(f'${s:02X}' for s in interesting)}")
        return

    open_kind, open_detail = dev["open"]

    # CASE 1: $10 4F itself rejected.
    if open_kind != "positive":
        print(f"VERDICT: $10 4F (Development Session) REJECTED — {open_detail}")
        print(bar)
        if _starts(open_detail, "0x22"):
            print("Likely cause: SA must be authenticated FIRST (before $10 4F).")
            print("Candidate: SA L17 (Bootloader, subfunctions 0x11/0x12).")
            print("L17 SA2 bytecode is in eps_flash.py:EPS_SA2_BYTECODE.")
            print()
            print("Next:")
            print("  This script doesn't yet do L17 auth. Either:")
            print("    a) extend it with L17 SA2 (~30 lines)")
            print("    b) try the XCP path which has its own SA hypothesis:")
            print("       python selfdrive/debug/car/vw_mqb_xcp_probe.py")
        elif _starts(open_detail, "0x12") or _starts(open_detail, "0x7F"):
            print("The session ID isn't recognized in the current top-level state.")
            print("BV pool's $10 4F definition may not apply to this firmware build.")
            print()
            print("Next:")
            print("  Enumerate the full 0x01..0x7F range to find what IS accepted:")
            print("    python selfdrive/debug/car/vw_mqb_session_probe.py --scan")
        else:
            print("Unexpected NRC. Inspect canary output above.")
            print()
            print("Next:")
            print("  python selfdrive/debug/car/vw_mqb_session_probe.py --scan")
        print()
        print("Independent fallback (always worth trying):")
        print("  python selfdrive/debug/car/vw_mqb_xcp_probe.py")
        return

    # $10 4F accepted. What about the canaries?
    c23 = dev.get("canary_23")
    c35 = dev.get("canary_35")

    if _canary_unlocked(c23) and _canary_unlocked(c35):
        print("VERDICT: ALL READ PATHS OPEN — $10 4F unlocks $23 AND $35")
        print(bar)
        print("Next: write vw_mqb_uds_dump.py to bulk-read the priority targets.")
        print("Suggested $23 calls (open $10 4F first, then loop SET_MTA equivalents):")
        print()
        print("  $23 24 0007630C 00002000   # off-FRF UDS dispatch table")
        print("  $23 24 0005E000 00002000   # 8 KB master ZDC (the goal)")
        print("  $23 24 40000CDA 00000400   # SRAM per-session permission matrix")
        print("  $23 24 00076000 00002000   # 8 KB containing dispatch table")
        print("  $23 24 00071550 0000FAB0   # off-FRF tail / bootloader region")
        print("  $23 24 40004000 00010000   # 64 KB RAM-shadowed cal block")
        return

    if _canary_unlocked(c23) and not _canary_unlocked(c35):
        print("VERDICT: $23 OPEN, $35 STILL GATED")
        print(bar)
        print("$23 ReadMemoryByAddress is enough for the master ZDC + dispatcher dump.")
        print("$35 RequestUpload would also work but requires extra auth (likely SA L17).")
        print()
        print("Next: write vw_mqb_uds_dump.py using $23 only — covers the goal.")
        return

    if _canary_sa_locked(c23) or _canary_sa_locked(c35):
        print("VERDICT: SESSION ACCEPTED, BUT $23/$35 NEED SECURITYACCESS")
        print(bar)
        print("$10 4F unlocks the route, but the services are still SA-gated.")
        print("Candidate: SA L17 (Bootloader) — subfunctions 0x11/0x12.")
        print("L17 SA2 bytecode is in eps_flash.py:EPS_SA2_BYTECODE (27 bytes).")
        print()
        print("Next:")
        print("  This script doesn't yet do L17 auth. Either:")
        print("    a) extend it with L17 SA2 (~30 lines, plus the bytecode interpreter)")
        print("    b) try the XCP path which is independent:")
        print("       python selfdrive/debug/car/vw_mqb_xcp_probe.py")
        return

    if _canary_no_service(c23) and _canary_no_service(c35):
        print("VERDICT: SESSION ACCEPTED, BUT $23/$35 STILL NRC 0x11/0x7F")
        print(bar)
        print("Surprising — BV pool said these services should be in $10 4F.")
        print("Possible: firmware has different gating than the BV pool docs,")
        print("or an additional precondition we haven't met.")
        print()
        print("Next:")
        print("  Enumerate OEM/supplier custom services in case there's a parallel path:")
        print("    python selfdrive/debug/car/vw_mqb_session_probe.py --services")
        print("  Or fall through to XCP:")
        print("    python selfdrive/debug/car/vw_mqb_xcp_probe.py")
        return

    print("VERDICT: PARTIAL / MIXED — see canary output above")
    print(bar)
    print(f"  $23 → {c23}")
    print(f"  $35 → {c35}")
    print("Inspect manually.")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--debug", action="store_true", help="enable ISO-TP/UDS debug output")
    p.add_argument("--scan", action="store_true",
                   help="enumerate the full $10 0x01..0x7F session range "
                        "(default: probe only $10 4F, the BV-pool lead)")
    p.add_argument("--session", type=lambda s: int(s, 0),
                   metavar="ID",
                   help="probe a single session ID (e.g. 0x60); overrides --scan")
    p.add_argument("--services", action="store_true",
                   help="also sweep OEM ($A0..$BF) and supplier ($F0..$FF) "
                        "service ranges for custom handlers")
    p.add_argument("--lo", type=lambda s: int(s, 0), default=0x01,
                   help="--scan range start (default 0x01)")
    p.add_argument("--hi", type=lambda s: int(s, 0), default=0x7F,
                   help="--scan range end inclusive (default 0x7F)")
    p.add_argument("--bus", type=int, default=DEFAULT_EPS_BUS, choices=(0, 1, 2),
                   help=f"CAN bus the EPS is on (default {DEFAULT_EPS_BUS} — "
                        "comma3 + J533 harness on MQB; try 0 or 2 if no UDS reply)")
    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    global EPS_BUS
    EPS_BUS = args.bus

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, EPS_BUS, timeout=0.2)
    print(f"Using EPS bus {EPS_BUS}")

    print("Started:", time.strftime("%Y-%m-%dT%H:%M:%S"))
    print(f"INFO: connecting to panda {panda.get_serial()}")
    open_extended(uds)
    print("Opened extended session ($10 03)")

    session_results: dict = {}
    service_results: dict = {}

    try:
        if args.session is not None:
            session_results = phase_session_enum(panda, [args.session])
        elif args.scan:
            ids = [s for s in range(args.lo, args.hi + 1) if s != 0x00 and s != 0x7F]
            session_results = phase_session_enum(panda, ids)
        else:
            # default: just the BV-pool lead
            session_results = phase_session_enum(panda, [DEV_SESSION])

        if args.services:
            service_results = phase_service_enum(panda)

        print_verdict(session_results, service_results)
    finally:
        print("\n──── Cleanup: returning to default session ────")
        return_to_default(panda)

    return 0


if __name__ == "__main__":
    sys.exit(main())
