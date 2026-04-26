#!/usr/bin/env python3
"""
Read / write the VW MQB EPS `LKU_Derating` setting (UDS DID 0x0502).

This DID controls how much the Lane-Keep-Unit (= openpilot / HCA_01) torque
is derated by the EPS. Setting it to 0 (= 100%) gives full LKU torque
execution.

Verified universal across the MQB EPS family — present on all observed ECU
variants:
  EV_SteerAssisMQB (008..015), EV_SteerAssisBASGEN1MQB37 (009..017),
  EV_SteerAssisVWBSMQBA (008, 009), EV_SteerAssisVWBSMQBGen2 (002).

Modeled on `vw_mqb_config.py` in this directory (HCA-coding toggle script).
Same security access (`seed + 28183`, level 2), same prerequisite ritual
(PROGRAMMING_DATE + REPAIR_SHOP_CODE), same panda hardware path. Only the
target DID and value semantics differ.

Usage:
    python3 vw_mqb_lku_derating.py show          # read and print current value
    python3 vw_mqb_lku_derating.py set 100       # write 100% (LKU_Derating=0x00)
    python3 vw_mqb_lku_derating.py set 0         # raw value form (also = 100%)
    python3 vw_mqb_lku_derating.py set 80        # 80% derate (= 0x01)

This tool is meant to run directly on a vehicle-installed comma three, with
the openpilot/tmux processes stopped. It should also work on a separate PC
with a USB-attached comma panda.

Vehicle requirements:
  * Ignition ON (engine recommended OFF for writes)
  * On newer vehicles you may need to OPEN THE HOOD to defeat the
    diagnostic firewall before the SecurityAccess + write will be accepted
  * `tmux kill-session -t comma` first if running on a comma3 with
    openpilot up
  * Changes take effect after an ignition cycle
"""

import argparse
import struct
import sys
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
from datetime import date


# Vendor-specific DIDs not in the standard ISO 14229 enum
class VW_DATA_IDENTIFIER(IntEnum):
    LKU_DERATING = 0x0502                 # ★ this script's target
    STEERING_SUPPORT_CHARACTERISTIC = 0x1920
    CODING = 0x0600                       # for read-only display


# Per ISO 14229-1:2020 §10.4, security level N uses subFunction (2N-1, 2N).
# Level 1 = 0x01/0x02, Level 2 = 0x03/0x04. Coding/adaptation writes on MQB
# EPS use Level 2.
class ACCESS_TYPE_LEVEL_2(IntEnum):
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2           # 0x04


# Standard MQB EPS UDS addresses (from openpilot/selfdrive/debug/car/vw_mqb_config.py)
MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x712 + 0x6A   # = 0x77C

# MQB EPS coding/adaptation security-access constant. Same value
# (28183) icanhack documented for the PQ family — VW reused it.
SECURITY_ACCESS_CONSTANT = 28183

# DID 0x0502 value table (per ODIS BV_SteerAssisUDS layer dump)
DERATING_VALUES = {
    0x00: "100% (full LKU power)",
    0x01: "80%",
    0x02: "60%",
    0x03: "40% (likely)",
    0x04: "20% (likely)",
    0x05: "0% (likely)",
}
# Inverse mapping for "set 100" / "set 80" / etc. user-friendly input
PERCENT_TO_RAW = {100: 0, 80: 1, 60: 2, 40: 3, 20: 4, 0: 5}


def parse_value(s: str) -> int:
    """Accept either raw (0..5) or percentage (100/80/60/40/20/0)."""
    if s.startswith("0x"):
        v = int(s, 16)
    else:
        v = int(s)
    if v in DERATING_VALUES:
        return v
    if v in PERCENT_TO_RAW:
        return PERCENT_TO_RAW[v]
    raise argparse.ArgumentTypeError(
        f"invalid value {s!r} — must be raw 0..5 or percentage 0/20/40/60/80/100"
    )


def open_session(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended diagnostic session with EPS")


def show_current(uds: UdsClient) -> int:
    """Read and pretty-print current LKU_Derating; return raw value."""
    # Identify the rack first so the user knows what they're talking to
    try:
        hw_pn = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER
        ).decode("utf-8", errors="replace").strip()
        sw_pn = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER
        ).decode("utf-8", errors="replace").strip()
        sw_ver = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER
        ).decode("utf-8", errors="replace").strip()
        odx_file = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.ODX_FILE
        ).decode("utf-8", errors="replace").rstrip("\x00").strip()
        coding = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.CODING)
    except (NegativeResponseError, MessageTimeoutError) as e:
        sys.exit(f"Error fetching identification from EPS: {e}")

    print("\nEPS identification")
    print(f"   HW part:   {hw_pn}")
    print(f"   SW part:   {sw_pn}")
    print(f"   SW ver:    {sw_ver}")
    print(f"   ODX file:  {odx_file}")
    print(f"   Coding:    {coding.hex()}")

    try:
        raw = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.LKU_DERATING)
    except NegativeResponseError as e:
        sys.exit(f"NRC reading LKU_Derating: {e}")
    except MessageTimeoutError:
        sys.exit("Timeout reading LKU_Derating")

    if len(raw) != 1:
        sys.exit(f"Unexpected LKU_Derating length: {len(raw)} bytes (raw {raw.hex()})")

    val = raw[0]
    label = DERATING_VALUES.get(val, f"INVALID (0x{val:02X} not in 0..5)")
    print(f"\nLKU_Derating: 0x{val:02X} = {label}")
    if val != 0x00:
        print("   ↳ LKU torque is being derated. For full openpilot torque,")
        print("   ↳ run: vw_mqb_lku_derating.py set 100")
    else:
        print("   ↳ LKU is at full power. No derating applied.")
    return val


def write_value(uds: UdsClient, new_value: int) -> None:
    """Run security access + prerequisites + write; verify."""
    if new_value not in DERATING_VALUES:
        sys.exit(f"refusing to write invalid value 0x{new_value:02X}")

    print(f"\nWriting LKU_Derating = 0x{new_value:02X} ({DERATING_VALUES[new_value]})")

    # Security access level 2 (coding/adaptation level)
    try:
        seed = uds.security_access(ACCESS_TYPE_LEVEL_2.REQUEST_SEED)
        # Same key formula icanhack documented (and openpilot's vw_mqb_config.py uses):
        #   key = (seed as big-endian uint32) + 28183
        key = struct.unpack("!I", seed)[0] + SECURITY_ACCESS_CONSTANT
        uds.security_access(ACCESS_TYPE_LEVEL_2.SEND_KEY, struct.pack("!I", key))
    except (NegativeResponseError, MessageTimeoutError) as e:
        print(f"\nSecurityAccess failed: {e}")
        print("   ↳ on newer vehicles, OPEN THE HOOD to defeat the diagnostic firewall and retry")
        sys.exit(1)

    # Prerequisites: must write PROGRAMMING_DATE and REPAIR_SHOP_CODE before
    # any coding/adaptation write, else the actual write fails with a request-
    # sequence-error. Mirror what openpilot's vw_mqb_config.py does.
    try:
        d = date.today()
        uds.write_data_by_identifier(
            DATA_IDENTIFIER_TYPE.PROGRAMMING_DATE,
            bytes([d.year - 2000, d.month, d.day]),
        )
        # Read the calibration tester ID and write it back as the programming
        # tester (we are the same "tester" that calibrated this rack — just
        # claim that)
        tester = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.CALIBRATION_REPAIR_SHOP_CODE_OR_CALIBRATION_EQUIPMENT_SERIAL_NUMBER
        )
        uds.write_data_by_identifier(
            DATA_IDENTIFIER_TYPE.REPAIR_SHOP_CODE_OR_TESTER_SERIAL_NUMBER, tester
        )
    except (NegativeResponseError, MessageTimeoutError) as e:
        print(f"\nFailed to write prerequisites: {e}")
        print("   ↳ make sure openpilot processes are stopped:")
        print("   ↳   tmux kill-session -t comma")
        sys.exit(1)

    # The actual write
    try:
        uds.write_data_by_identifier(VW_DATA_IDENTIFIER.LKU_DERATING, bytes([new_value]))
    except (NegativeResponseError, MessageTimeoutError) as e:
        sys.exit(f"\nWrite of LKU_Derating failed: {e}")

    # Verify
    try:
        readback = uds.read_data_by_identifier(VW_DATA_IDENTIFIER.LKU_DERATING)
    except (NegativeResponseError, MessageTimeoutError) as e:
        sys.exit(f"Failed to read back LKU_Derating after write: {e}")

    if len(readback) == 1 and readback[0] == new_value:
        print(f"\n✓ Write verified: LKU_Derating now 0x{readback[0]:02X} ({DERATING_VALUES[readback[0]]})")
        print("   ↳ ignition cycle to apply the change persistently")
    else:
        print(f"\n⚠ readback mismatch: wrote 0x{new_value:02X}, read back {readback.hex()}")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full vehicle/safety requirements.",
    )
    p.add_argument("--debug", action="store_true", help="enable ISO-TP/UDS debug output")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("show", help="read and print current LKU_Derating value")
    set_p = sub.add_parser("set", help="write a new value (0..5 raw, or 0/20/40/60/80/100 percent)")
    set_p.add_argument("value", type=parse_value)

    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=0.2)

    open_session(uds)

    if args.action == "show":
        show_current(uds)
    elif args.action == "set":
        show_current(uds)
        write_value(uds, args.value)


if __name__ == "__main__":
    main()
