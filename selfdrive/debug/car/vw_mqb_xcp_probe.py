#!/usr/bin/env python3
"""
Discover the XCP CAN IDs on the 5Q0909143 EPS and characterize the slave.

Background: UDS $23 ReadMemoryByAddress is locked on this rack (NRC 0x11). The
firmware has an XCP slave (`Build01_IXCP` string in FD_0DATA, plus DID 0x0501
`Calibration_protocol_XCP` for runtime enable). The XCP master/slave CAN IDs
are not publicly documented for VAG MQB EPS — must be discovered.

What this script does:
  1. UDS extended session, SecurityAccess level 2 (seed + 28183)
  2. PROGRAMMING_DATE + REPAIR_SHOP_CODE prerequisites
  3. Write 0x01 to DID 0x0501 → enable XCP slave
  4. Sweep candidate XCP TX/RX CAN ID pairs sending CONNECT (mode=0)
  5. For each responsive pair, decode the CONNECT response
  6. Try SHORT_UPLOAD on a known SRAM address WITHOUT auth (test the
     "UDS gate is the only auth" hypothesis from the research notes)
  7. On exit: write DID 0x0501 = 0x00 to disable XCP slave (always, even on
     ctrl-c / exception)

STRICTLY READ-PROBE: this script issues only CONNECT, GET_STATUS, SHORT_UPLOAD,
                    DISCONNECT on the XCP side. No XCP DOWNLOAD, no XCP PROGRAM.
                    On the UDS side: only the documented enable/disable writes.

XCP layer is delegated to opendbc's XcpClient (`opendbc.car.xcp.XcpClient`),
which handles CONNECT/UPLOAD/SET_MTA/etc with proper response decoding,
correct ASAM error-code mapping (0x25 = "Seed & Key required"), and
slave_block_mode / max_cto / max_dto negotiation on CONNECT.

Usage:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
      ~/Projects/re-vw/steering/vw_mqb_xcp_probe.py

    # wider scan if the default candidate list misses:
    python3 vw_mqb_xcp_probe.py --scan-range 0x600 0x7FF

    # one pair only (no collateral on other modules):
    python3 vw_mqb_xcp_probe.py --tx-rx 0x780 0x788

Vehicle requirements:
  * Ignition ON, engine OFF preferred
  * On newer vehicles open the hood to defeat the diagnostic firewall
  * `tmux kill-session -t comma` first if openpilot is running
"""

import argparse
import struct
import sys
import time
from datetime import date
from enum import IntEnum

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
    DATA_IDENTIFIER_TYPE,
    ACCESS_TYPE,
)
from opendbc.car.xcp import (
    XcpClient,
    ERROR_CODES,
    CommandTimeoutError,
    CommandResponseError,
)
from opendbc.car.structs import CarParams
from panda import Panda


# ─── UDS-side constants ───────────────────────────────────────────────────────

class VW_DATA_IDENTIFIER(IntEnum):
    CALIBRATION_PROTOCOL_XCP = 0x0501


class ACCESS_TYPE_LEVEL_2(IntEnum):
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2  # 0x03
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2          # 0x04


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
SECURITY_ACCESS_CONSTANT = 28183
EPS_BUS = 1  # F-CAN behind comma3 panda — matches existing scripts


# ─── XCP-side candidate list ──────────────────────────────────────────────────

# Candidate XCP CAN ID pairs to probe (from XCP.md + agent research).
# Ordered by prior likelihood for VAG / supplier conventions.
DEFAULT_CANDIDATES = [
    (0x780, 0x788),  # very common XCP default
    (0x7E0, 0x7E8),  # engine-ECU range (CAN-ID 11 OBD-II std)
    (0x6F1, 0x6FA),  # VAG-specific diagnostic range
    (0x740, 0x748),  # body-controller / generic
    (0x710, 0x718),  # adjacent to UDS pair
    (0x711, 0x719),
    (0x713, 0x71B),
    (0x7A0, 0x7A8),
    (0x7B0, 0x7B8),
    (0x7C0, 0x7C8),
    (0x712, 0x77C),  # UDS pair shared (last resort — some impls reuse)
]

# A known SRAM address to test SHORT_UPLOAD (read-only, harmless): the
# scaled-HCA-torque vestigial path. 2 bytes, int16. From CLAUDE.md / HCA_PIPELINE.
NOAUTH_TEST_ADDR = 0x4000DC30
NOAUTH_TEST_LEN  = 2


# ─── UDS phase: enable / disable XCP slave ─────────────────────────────────────

def open_extended_session(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended diagnostic session with EPS")


def enable_xcp(uds: UdsClient) -> None:
    """SA2 + prerequisites + $2E 0501 01.

    Mirrors vw_mqb_lku_derating.py:write_value() exactly — same SA2 algorithm,
    same prerequisite ritual. Only the target DID changes.
    """
    seed = uds.security_access(ACCESS_TYPE_LEVEL_2.REQUEST_SEED)
    key = struct.unpack("!I", seed)[0] + SECURITY_ACCESS_CONSTANT
    uds.security_access(ACCESS_TYPE_LEVEL_2.SEND_KEY, struct.pack("!I", key))

    d = date.today()
    uds.write_data_by_identifier(
        DATA_IDENTIFIER_TYPE.PROGRAMMING_DATE,
        bytes([d.year - 2000, d.month, d.day]),
    )
    tester = uds.read_data_by_identifier(
        DATA_IDENTIFIER_TYPE.CALIBRATION_REPAIR_SHOP_CODE_OR_CALIBRATION_EQUIPMENT_SERIAL_NUMBER
    )
    uds.write_data_by_identifier(
        DATA_IDENTIFIER_TYPE.REPAIR_SHOP_CODE_OR_TESTER_SERIAL_NUMBER, tester
    )
    uds.write_data_by_identifier(
        VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP, bytes([0x01])
    )

    readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP)
    if readback != bytes([0x01]):
        sys.exit(f"DID 0x0501 readback mismatch after enable: {readback.hex()}")


def disable_xcp(uds: UdsClient) -> None:
    """Best-effort restore — never raise from here."""
    try:
        uds.write_data_by_identifier(
            VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP, bytes([0x00])
        )
        readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP)
        if readback == bytes([0x00]):
            print("  ✓ XCP slave disabled (DID 0x0501 = 0x00)")
        else:
            print(f"  ⚠ DID 0x0501 readback = {readback.hex()} (expected 00)")
    except Exception as e:
        print(f"  ⚠ failed to disable XCP slave: {e}")
        print("  ⚠ MANUAL CLEANUP NEEDED: write DID 0x0501 = 0 with another tool")


# ─── XCP probe operations (via opendbc XcpClient) ─────────────────────────────

def try_connect(panda: Panda, tx: int, rx: int, timeout: float, debug: bool):
    """Return (client, info) on success, (None, fail_dict) on failure.

    On success, the slave is in the connected state — caller MUST disconnect()
    or keep using the client.
    """
    client = XcpClient(panda, tx, rx, bus=EPS_BUS, timeout=timeout, debug=debug)
    try:
        info = client.connect()
        return client, info
    except CommandTimeoutError:
        return None, {"kind": "timeout"}
    except CommandResponseError as e:
        return None, {"kind": "rejected", "code": e.return_code, "message": e.message}
    except AssertionError as e:
        return None, {"kind": "malformed", "message": str(e)}


def safe_disconnect(client: XcpClient) -> None:
    try:
        client.disconnect()
    except Exception:
        pass


# ─── Reporting ────────────────────────────────────────────────────────────────

def fmt_connect_info(info: dict) -> list[str]:
    resources = ", ".join(
        name for name, on in [
            ("CAL_PAG", info["cal_support"]),
            ("DAQ", info["daq_support"]),
            ("STIM", info["stim_support"]),
            ("PGM", info["pgm_support"]),
        ] if on
    ) or "(none)"
    byte_order = "MSB-first (BE)" if info["byte_order"] == ">" else "LSB-first (LE)"
    return [
        f"resources:           {resources}",
        f"byte order:          {byte_order}",
        f"address granularity: {info['address_granularity']} byte(s)",
        f"slave block mode:    {info['slave_block_mode']}",
        f"MAX_CTO / MAX_DTO:   {info['max_cto']} / {info['max_dto']} bytes",
        f"protocol/transport:  v{info['protocol_version']} / v{info['transport_version']}",
    ]


def build_candidate_list(args) -> list[tuple[int, int]]:
    if args.scan_range:
        lo, hi = args.scan_range
        # Scan TX = each step, RX = TX+8 (the prevailing convention)
        return [(tx, tx + 8) for tx in range(lo, hi + 1, 0x10)]
    if args.tx_rx:
        return [tuple(args.tx_rx)]
    return DEFAULT_CANDIDATES


def run_probe(panda: Panda, candidates: list[tuple[int, int]],
              timeout: float, debug: bool) -> list[dict]:
    """For each candidate pair: try CONNECT, record outcome, disconnect cleanly.

    Returns a list of hit records — one per candidate, with the slave info
    if CONNECT succeeded.
    """
    hits = []
    for tx, rx in candidates:
        print(f"  TX 0x{tx:03X} → RX 0x{rx:03X}: ", end="", flush=True)
        client, result = try_connect(panda, tx, rx, timeout, debug)

        if client is None:
            kind = result["kind"]
            if kind == "timeout":
                print("no response")
            elif kind == "rejected":
                code = result["code"]
                desc = ERROR_CODES.get(code, "unknown error")
                print(f"slave rejected CONNECT — 0x{code:02X} {desc}")
                hits.append({"tx": tx, "rx": rx, "rejected": result})
            else:
                print(f"malformed response: {result['message']}")
            continue

        print("POSITIVE")
        for line in fmt_connect_info(result):
            print(f"    {line}")
        hits.append({"tx": tx, "rx": rx, "info": result})
        # Don't keep the connection open across candidates — a single CONNECT
        # is enough to characterize the slave; we'll re-CONNECT per pair if a
        # follow-up test is needed.
        safe_disconnect(client)

    return hits


def test_noauth_upload(panda: Panda, tx: int, rx: int,
                       timeout: float, debug: bool) -> None:
    """Re-CONNECT on the chosen pair, then SHORT_UPLOAD without GET_SEED/UNLOCK.

    Tests the "UDS gate is the only auth" hypothesis end-to-end.
    """
    print(f"\n──── No-auth SHORT_UPLOAD test on TX 0x{tx:03X} → RX 0x{rx:03X} ────")
    print(f"  reading {NOAUTH_TEST_LEN} B at 0x{NOAUTH_TEST_ADDR:08X} (HCA_scaled_vest)")

    client, result = try_connect(panda, tx, rx, timeout, debug)
    if client is None:
        kind = result["kind"]
        if kind == "rejected":
            code = result["code"]
            desc = ERROR_CODES.get(code, "unknown error")
            print(f"  ✗ couldn't reconnect for upload test: 0x{code:02X} {desc}")
        else:
            print(f"  ✗ couldn't reconnect for upload test: {kind}")
        return

    try:
        data = client.short_upload(NOAUTH_TEST_LEN, 0, NOAUTH_TEST_ADDR)
        as_int = struct.unpack(">h", data)[0] if NOAUTH_TEST_LEN == 2 else None
        print(f"  ✓ POSITIVE: data = {data.hex()}  (int16 BE = {as_int})")
        print("  ✦ HYPOTHESIS CONFIRMED: XCP requires NO seed/key after UDS-gate enable")
        print("    ↳ next: write vw_mqb_xcp_dump.py to bulk-read SRAM regions")
    except CommandResponseError as e:
        code = e.return_code
        desc = ERROR_CODES.get(code, "unknown error")
        print(f"  ✗ NEGATIVE: 0x{code:02X} {desc}")
        if code == 0x25:  # Access denied, Seed & Key required
            print("    ↳ resource requires GET_SEED/UNLOCK")
            print("    ↳ next step: find XCP seed/key algorithm via firmware static RE")
            print("    ↳ try seed+28183 first (UDS L2 algorithm) — sometimes shared")
        elif code == 0x24:  # Memory location not accessible
            print(f"    ↳ address {NOAUTH_TEST_ADDR:#x} not reachable in current state")
            print("    ↳ try a different address before concluding access is locked")
        elif code == 0x23:  # Memory location write protected (irrelevant for UPLOAD, but log)
            print("    ↳ unexpected — 0x23 is for writes; protocol misuse on slave side?")
    except CommandTimeoutError:
        print("  ✗ no response to SHORT_UPLOAD (slave hung after CONNECT?)")
    finally:
        safe_disconnect(client)


def report(hits: list[dict]) -> None:
    print("\n" + "=" * 70)
    positive = [h for h in hits if "info" in h]
    print(f"XCP probe summary: {len(positive)} positive responder(s) / "
          f"{len(hits)} that talked at all")
    print("=" * 70)
    for hit in hits:
        tx, rx = hit["tx"], hit["rx"]
        if "info" in hit:
            print(f"\n  TX 0x{tx:03X} → RX 0x{rx:03X}  POSITIVE")
            for line in fmt_connect_info(hit["info"]):
                print(f"    {line}")
        elif "rejected" in hit:
            r = hit["rejected"]
            desc = ERROR_CODES.get(r["code"], "unknown")
            print(f"\n  TX 0x{tx:03X} → RX 0x{rx:03X}  rejected — 0x{r['code']:02X} {desc}")


# ─── Main flow ────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full vehicle/safety requirements.",
    )
    p.add_argument("--debug", action="store_true", help="enable ISO-TP/UDS/XCP debug output")
    p.add_argument("--scan-range", nargs=2, type=lambda s: int(s, 0),
                   metavar=("LO", "HI"),
                   help="brute scan TX in [LO, HI] step 0x10, RX = TX+8 "
                        "(e.g. --scan-range 0x600 0x7FF)")
    p.add_argument("--tx-rx", nargs=2, type=lambda s: int(s, 0),
                   metavar=("TX", "RX"),
                   help="probe just one pair, e.g. --tx-rx 0x780 0x788")
    p.add_argument("--timeout", type=float, default=0.3,
                   help="per-candidate XCP CONNECT timeout in seconds (default 0.3)")
    p.add_argument("--skip-enable", action="store_true",
                   help="skip the UDS enable step (assume DID 0x0501 already 1)")
    p.add_argument("--skip-disable", action="store_true",
                   help="don't write DID 0x0501 = 0 on exit "
                        "(useful for chaining into validate/dump script)")
    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, EPS_BUS, timeout=0.2)

    print("Started:", time.strftime("%Y-%m-%dT%H:%M:%S"))
    print(f"INFO: connecting to panda {panda.get_serial()}")
    open_extended_session(uds)
    print("Opened extended diagnostic session ($10 03)")

    enabled = False
    try:
        if not args.skip_enable:
            print("\n──── Enabling XCP slave ────")
            try:
                enable_xcp(uds)
                enabled = True
                print("  ✓ DID 0x0501 = 0x01 (XCP slave active)")
            except (NegativeResponseError, MessageTimeoutError) as e:
                print(f"  ✗ enable failed: {e}")
                print("  ↳ on newer vehicles OPEN THE HOOD to defeat the firewall")
                print("  ↳ also try: tmux kill-session -t comma")
                return 1
            time.sleep(0.5)  # let the slave spin up
        else:
            print("\n──── Skipping enable (--skip-enable) ────")

        candidates = build_candidate_list(args)
        print(f"\n──── Probing {len(candidates)} candidate XCP CAN ID pair(s) ────")
        hits = run_probe(panda, candidates, timeout=args.timeout, debug=args.debug)

        report(hits)

        # If exactly one positive, follow up with a no-auth SHORT_UPLOAD test.
        positive = [h for h in hits if "info" in h]
        if positive:
            test_noauth_upload(panda, positive[0]["tx"], positive[0]["rx"],
                               timeout=args.timeout, debug=args.debug)

    finally:
        if enabled and not args.skip_disable:
            print("\n──── Disabling XCP slave ────")
            disable_xcp(uds)
        elif args.skip_disable:
            print("\n──── Leaving XCP slave enabled (--skip-disable) ────")
            print("    remember to disable manually: write DID 0x0501 = 0x00")

    return 0


if __name__ == "__main__":
    sys.exit(main())
