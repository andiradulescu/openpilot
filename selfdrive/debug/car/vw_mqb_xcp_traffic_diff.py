#!/usr/bin/env python3
"""
Diagnostic: does enabling XCP (DID 0x0501 = 0x01) change bus-0 traffic?

We had a probe report `TX 0x6B0 → RX 0x6B8: POSITIVE` and a SHORT_UPLOAD
appearing to read SRAM correctly. Subsequent debug-trace runs showed the
"response" was actually a periodic broadcast at 0x6B8 with payload
`98 08 4c 70 12 78 00 00` — and `0x98` isn't a valid XCP PID. So we may
have been chasing background traffic.

This script settles it:
  1. Force DID 0x0501 = 0x00 (disable XCP) — try harder if it refuses
  2. Listen passively to all 3 buses for 3s — record IDs and payloads (BASELINE)
  3. SA2 + prerequisites + write DID 0x0501 = 0x01 (enable XCP)
  4. Sleep 2s for slave warmup
  5. Listen passively for 3s again (ENABLED)
  6. Print every CAN ID that appears ONLY in ENABLED — those are the XCP slave's
     real broadcast IDs (if any). If the diff is empty, DID 0x0501 is a no-op
     coding flag with no runtime effect on this rack.

Run from comma three with openpilot stopped.
"""

import struct
import sys
import time
from datetime import date
from enum import IntEnum

from opendbc.car.uds import (
    UdsClient,
    SESSION_TYPE,
    DATA_IDENTIFIER_TYPE,
    ACCESS_TYPE,
    NegativeResponseError,
)
from opendbc.car.structs import CarParams
from panda import Panda


class VW_DATA_IDENTIFIER(IntEnum):
    CALIBRATION_PROTOCOL_XCP = 0x0501


class ACCESS_TYPE_LEVEL_2(IntEnum):
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2


SECURITY_ACCESS_CONSTANT = 28183
MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
UDS_BUS = 1
LISTEN_SECONDS = 3.0
WARMUP_SECONDS = 2.0


def listen(panda: Panda, seconds: float, label: str) -> dict:
    """Returns {(bus, addr): set(payload_hex_strings)}."""
    print(f"  → listening {seconds}s ({label})...", flush=True)
    panda.can_clear(0xFFFF)
    seen: dict[tuple[int, int], set[str]] = {}
    deadline = time.time() + seconds
    while time.time() < deadline:
        for addr, data, src in panda.can_recv() or []:
            seen.setdefault((src, addr), set()).add(bytes(data).hex())
    return seen


def force_disable_xcp(uds: UdsClient) -> None:
    """Best-effort restore. May fail if previous session put $2E in a weird state."""
    try:
        uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)  # back to default first
    except Exception:
        pass
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception as e:
        print(f"  ⚠ couldn't open extended session: {e}")
        return
    try:
        # Try direct write first — might succeed in fresh session
        uds.write_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP, bytes([0x00]))
        readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP)
        print(f"  XCP enable flag now: {readback.hex()}")
        return
    except NegativeResponseError as e:
        print(f"  direct $2E 0x0501=0x00 failed: {e}; trying full SA2 path")

    # Full path: SA2 + prerequisites + write
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
    uds.write_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP, bytes([0x00]))
    readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP)
    print(f"  after SA2: XCP enable flag = {readback.hex()}")


def enable_xcp_full(uds: UdsClient) -> None:
    """Same enable ritual as vw_mqb_xcp_probe.py."""
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
    uds.write_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP, bytes([0x01]))
    readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CALIBRATION_PROTOCOL_XCP)
    if readback != bytes([0x01]):
        sys.exit(f"DID 0x0501 readback mismatch after enable: {readback.hex()}")


def diff_traffic(baseline: dict, enabled: dict) -> None:
    print()
    print("══════════════════════════════════════════════════════════════════════")
    print("  Diff: IDs that appeared ONLY when XCP was enabled")
    print("══════════════════════════════════════════════════════════════════════")
    new_keys = set(enabled.keys()) - set(baseline.keys())
    if not new_keys:
        print("  (NONE) — DID 0x0501 = 0x01 produced zero new bus traffic.")
        print("  Conclusion: the XCP-enable DID is a no-op coding flag on this rack,")
        print("              or the slave only responds to direct CONNECT (no broadcasts).")
        return
    for src, addr in sorted(new_keys):
        payloads = enabled[(src, addr)]
        print(f"  bus={src} 0x{addr:03X}  payloads_seen={len(payloads)}")
        for p in sorted(payloads)[:3]:
            print(f"      {p}")

    print()
    print("══════════════════════════════════════════════════════════════════════")
    print("  Payloads that CHANGED for shared IDs (XCP enable might have toggled state)")
    print("══════════════════════════════════════════════════════════════════════")
    shared = set(enabled.keys()) & set(baseline.keys())
    changed = 0
    for key in sorted(shared):
        b = baseline[key]
        e = enabled[key]
        if b != e:
            new_only = e - b
            if new_only:
                src, addr = key
                changed += 1
                print(f"  bus={src} 0x{addr:03X}  new payloads with XCP enabled:")
                for p in sorted(new_only)[:3]:
                    print(f"      {p}")
    if changed == 0:
        print("  (NONE)")


def main() -> int:
    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    panda.can_clear(0xFFFF)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, UDS_BUS, timeout=0.2)
    print(f"Started: {time.strftime('%Y-%m-%dT%H:%M:%S')}")

    print("\n──── Phase 1: force XCP disabled ────")
    force_disable_xcp(uds)

    print("\n──── Phase 2: passive baseline listen ────")
    baseline = listen(panda, LISTEN_SECONDS, "XCP disabled")
    print(f"  saw {sum(len(v) for v in baseline.values())} payloads "
          f"across {len(baseline)} (bus, ID) pairs")

    print("\n──── Phase 3: enable XCP (full SA2 ritual) ────")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception:
        pass
    enable_xcp_full(uds)
    print(f"  ✓ DID 0x0501 = 0x01")
    print(f"  sleeping {WARMUP_SECONDS}s for slave warmup")
    time.sleep(WARMUP_SECONDS)

    print("\n──── Phase 4: enabled-state listen ────")
    enabled = listen(panda, LISTEN_SECONDS, "XCP enabled")
    print(f"  saw {sum(len(v) for v in enabled.values())} payloads "
          f"across {len(enabled)} (bus, ID) pairs")

    diff_traffic(baseline, enabled)

    print("\n──── Cleanup: try to disable XCP again ────")
    force_disable_xcp(uds)

    return 0


if __name__ == "__main__":
    sys.exit(main())
