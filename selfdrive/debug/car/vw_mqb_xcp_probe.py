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

Usage:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
      ~/Projects/re-vw/steering/vw_mqb_xcp_probe.py

    # wider scan if the default candidate list misses:
    python3 vw_mqb_xcp_probe.py --scan-range 0x600 0x7FF

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


# ─── XCP-side constants ───────────────────────────────────────────────────────

XCP_PID_CONNECT      = 0xFF
XCP_PID_DISCONNECT   = 0xFE
XCP_PID_GET_STATUS   = 0xFD
XCP_PID_SHORT_UPLOAD = 0xF4
XCP_RESP_OK          = 0xFF  # positive response leading byte
XCP_RESP_ERR         = 0xFE  # error/event leading byte

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


# ─── XCP-on-CAN raw frame helpers (no pyxcp yet — IDs are unknown) ────────────

def xcp_send(panda: Panda, tx_id: int, payload: bytes) -> None:
    """Pad payload to 8 bytes per CAN, send on EPS_BUS."""
    frame = payload + b"\x00" * (8 - len(payload))
    panda.can_send(tx_id, frame, EPS_BUS)


def xcp_recv(panda: Panda, rx_id: int, timeout: float = 0.3) -> bytes | None:
    """Wait up to `timeout` s for a frame on rx_id+EPS_BUS. Return data or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for addr, _ts, data, src in panda.can_recv():
            if addr == rx_id and src == EPS_BUS and len(data) >= 1:
                return bytes(data)
        time.sleep(0.005)
    return None


def xcp_drain(panda: Panda) -> None:
    """Drain any pending RX so a stale frame doesn't masquerade as a response."""
    deadline = time.time() + 0.05
    while time.time() < deadline:
        if not panda.can_recv():
            break


def decode_connect_response(resp: bytes) -> dict:
    """Per ASAM XCP §3 CONNECT positive response.

    Layout: FF RR CB MC MD0 MD1 PV TV
    """
    if len(resp) < 8 or resp[0] != XCP_RESP_OK:
        return {"raw": resp.hex(), "valid": False}
    rr = resp[1]
    cb = resp[2]
    return {
        "raw": resp.hex(),
        "valid": True,
        "resources": {
            "CAL_PAG": bool(rr & 0x01),
            "DAQ":     bool(rr & 0x04),
            "STIM":    bool(rr & 0x08),
            "PGM":     bool(rr & 0x10),
        },
        "byte_order_msb_first": bool(cb & 0x01),
        "address_granularity": (cb >> 1) & 0x03,  # 0=BYTE, 1=WORD, 2=DWORD
        "slave_block_mode":   bool(cb & 0x40),
        "optional_comm_mode": bool(cb & 0x80),
        "max_cto": resp[3],
        "max_dto": struct.unpack(">H", resp[4:6])[0],  # default BE for CONNECT
        "protocol_layer_version":  resp[6],
        "transport_layer_version": resp[7],
    }


# ─── XCP probe operations ─────────────────────────────────────────────────────

def probe_connect(panda: Panda, tx: int, rx: int, timeout: float = 0.3) -> bytes | None:
    """Send CONNECT (mode=0); return response bytes or None."""
    xcp_drain(panda)
    xcp_send(panda, tx, bytes([XCP_PID_CONNECT, 0x00]))
    return xcp_recv(panda, rx, timeout)


def try_short_upload(panda: Panda, tx: int, rx: int, addr: int, length: int) -> bytes | None:
    """SHORT_UPLOAD without prior GET_SEED/UNLOCK — tests no-auth hypothesis.

    Frame: F4 LL 00 EE  AA AA AA AA   (LL=length, EE=addr-extension=0,
                                       AA=address big-endian)
    """
    payload = struct.pack(">BBBB I", XCP_PID_SHORT_UPLOAD, length, 0x00, 0x00, addr)
    xcp_drain(panda)
    panda.can_send(tx, payload, EPS_BUS)
    return xcp_recv(panda, rx, timeout=0.3)


def try_disconnect(panda: Panda, tx: int, rx: int) -> None:
    xcp_send(panda, tx, bytes([XCP_PID_DISCONNECT]))
    xcp_recv(panda, rx, timeout=0.2)  # ack but ignore


# ─── Main flow ────────────────────────────────────────────────────────────────

def build_candidate_list(args) -> list[tuple[int, int]]:
    if args.scan_range:
        lo, hi = args.scan_range
        # Scan TX = each step, RX = TX+8 (the prevailing convention)
        return [(tx, tx + 8) for tx in range(lo, hi + 1, 0x10)]
    if args.tx_rx:
        return [tuple(args.tx_rx)]
    return DEFAULT_CANDIDATES


def run_probe(panda: Panda, candidates: list[tuple[int, int]]) -> list[dict]:
    found = []
    for tx, rx in candidates:
        print(f"  TX 0x{tx:03X} → RX 0x{rx:03X}: ", end="", flush=True)
        resp = probe_connect(panda, tx, rx)
        if resp is None:
            print("no response")
            continue
        if resp[0] == XCP_RESP_OK:
            decoded = decode_connect_response(resp)
            print(f"POSITIVE  {resp.hex()}")
            found.append({"tx": tx, "rx": rx, "connect_resp": decoded})
        elif resp[0] == XCP_RESP_ERR:
            print(f"ERROR     {resp.hex()}  (slave responded but rejected CONNECT)")
            found.append({"tx": tx, "rx": rx, "error_resp": resp.hex()})
        else:
            print(f"unknown   {resp.hex()}")
    return found


def report(found: list[dict]) -> None:
    print("\n" + "=" * 70)
    print(f"XCP probe summary: {len(found)} responsive pair(s)")
    print("=" * 70)
    for hit in found:
        tx, rx = hit["tx"], hit["rx"]
        print(f"\n  TX 0x{tx:03X} → RX 0x{rx:03X}")
        if "connect_resp" in hit and hit["connect_resp"]["valid"]:
            d = hit["connect_resp"]
            res = ", ".join(k for k, v in d["resources"].items() if v) or "(none)"
            print(f"    resources:           {res}")
            print(f"    byte order:          {'MSB-first (BE)' if d['byte_order_msb_first'] else 'LSB-first (LE)'}")
            print(f"    addr granularity:    {['BYTE','WORD','DWORD'][d['address_granularity']]}")
            print(f"    MAX_CTO / MAX_DTO:   {d['max_cto']} / {d['max_dto']} bytes")
            print(f"    protocol/transport:  v{d['protocol_layer_version']} / v{d['transport_layer_version']}")
        elif "error_resp" in hit:
            print(f"    error response:      {hit['error_resp']}")


def test_noauth_upload(panda: Panda, tx: int, rx: int) -> None:
    """Try SHORT_UPLOAD with no GET_SEED/UNLOCK first."""
    print(f"\n──── No-auth SHORT_UPLOAD test on TX 0x{tx:03X} → RX 0x{rx:03X} ────")
    print(f"  reading {NOAUTH_TEST_LEN} B at 0x{NOAUTH_TEST_ADDR:08X} (HCA_scaled_vest)")
    resp = try_short_upload(panda, tx, rx, NOAUTH_TEST_ADDR, NOAUTH_TEST_LEN)
    if resp is None:
        print("  ✗ no response")
    elif resp[0] == XCP_RESP_OK:
        data = resp[1:1 + NOAUTH_TEST_LEN]
        as_int = struct.unpack(">h", data)[0] if NOAUTH_TEST_LEN == 2 else None
        print(f"  ✓ POSITIVE: data = {data.hex()}  (int16 BE = {as_int})")
        print("  ✦ HYPOTHESIS CONFIRMED: XCP requires NO seed/key after UDS-gate enable")
        print("    ↳ next: write vw_mqb_xcp_validate.py to read all known addrs")
    elif resp[0] == XCP_RESP_ERR:
        err_code = resp[1] if len(resp) > 1 else None
        # Per ASAM XCP §1.1.4 ERR_ codes; 0x21 = ERR_ACCESS_LOCKED
        err_name = {
            0x10: "ERR_CMD_BUSY",
            0x11: "ERR_DAQ_ACTIVE",
            0x12: "ERR_PGM_ACTIVE",
            0x20: "ERR_CMD_SYNCH",
            0x21: "ERR_ACCESS_LOCKED",
            0x22: "ERR_ACCESS_DENIED",
            0x23: "ERR_OUT_OF_RANGE",
            0x24: "ERR_WRITE_PROTECTED",
            0x30: "ERR_RESOURCE_TEMPORARY_NOT_ACCESSIBLE",
        }.get(err_code, f"0x{err_code:02X}")
        print(f"  ✗ NEGATIVE: {err_name}  (raw {resp.hex()})")
        if err_code == 0x21:
            print("    ↳ resource is locked — GET_SEED/UNLOCK required")
            print("    ↳ next step: vw_mqb_xcp_validate.py with seed/key (try seed+28183 first)")


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full vehicle/safety requirements.",
    )
    p.add_argument("--debug", action="store_true", help="enable ISO-TP/UDS debug output")
    p.add_argument("--scan-range", nargs=2, type=lambda s: int(s, 0),
                   metavar=("LO", "HI"),
                   help="brute scan TX in [LO, HI] step 0x10, RX = TX+8 "
                        "(e.g. --scan-range 0x600 0x7FF)")
    p.add_argument("--tx-rx", nargs=2, type=lambda s: int(s, 0),
                   metavar=("TX", "RX"),
                   help="probe just one pair, e.g. --tx-rx 0x780 0x788")
    p.add_argument("--skip-enable", action="store_true",
                   help="skip the UDS enable step (assume DID 0x0501 already 1)")
    p.add_argument("--skip-disable", action="store_true",
                   help="don't write DID 0x0501 = 0 on exit "
                        "(useful for chaining into validate script)")
    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=0.2)

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
        found = run_probe(panda, candidates)

        report(found)

        # If exactly one positive responder, follow up with no-auth SHORT_UPLOAD test.
        positive = [h for h in found if "connect_resp" in h and h["connect_resp"]["valid"]]
        if positive:
            hit = positive[0]
            try_disconnect(panda, hit["tx"], hit["rx"])  # clean state before re-CONNECT
            time.sleep(0.1)
            # Re-CONNECT before the upload (DISCONNECT closed the session)
            probe_connect(panda, hit["tx"], hit["rx"])
            test_noauth_upload(panda, hit["tx"], hit["rx"])
            try_disconnect(panda, hit["tx"], hit["rx"])

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
