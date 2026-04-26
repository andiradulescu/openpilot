#!/usr/bin/env python3
"""
Read-only diagnostic dump of the VW MQB Electric Power Steering controller
(module address 0x44).

Reads every well-known UDS data identifier this controller exposes:
  * Identification (part numbers, software/hardware versions, ODX label)
  * VW Coding Value 0x0600 (decoded bit-by-bit)
  * Long-coding 0x0407 and subsystem-coding 0x040F
  * All 9 catalogued adaptation DIDs in their CURRENT state
    (LKU_Derating, Characteristic_Line, XCP enable, etc.)
  * A curated set of live-data MWBs (~25 most useful)
  * Stored DTCs (status mask = ALL)

This script NEVER writes. No SecurityAccess required (only $22 reads in
extended diagnostic session $10 03). Safe to run on any vehicle without
side effects.

Usage:
    python3 vw_mqb_eps_dump.py
    python3 vw_mqb_eps_dump.py --debug      # ISO-TP/UDS debug logging

This tool is meant to run directly on a vehicle-installed comma three, with
the openpilot/tmux processes stopped. It also works on a separate PC with
a USB-attached comma panda. Vehicle ignition must be on (engine may run).
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
    DTC_REPORT_TYPE,
    DTC_STATUS_MASK_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


# ----------------------------------------------------------------------------
# CAN addresses (VW MQB direct EPS)
# ----------------------------------------------------------------------------
MQB_EPS_TX = 0x712
RX_OFFSET = 0x6A
MQB_EPS_RX = MQB_EPS_TX + RX_OFFSET   # 0x77C


# ----------------------------------------------------------------------------
# Vendor-specific DIDs not in the standard ISO 14229 enum
# ----------------------------------------------------------------------------
class VW_DID(IntEnum):
    # VW-specific identification (not in standard ISO 14229 DID enum)
    FAZIT_IDENTIFICATION = 0xF17C   # ASCII, e.g. "TT1-BUD17.01.1800033797"
    PARAM_SET_PART_NUMBER = 0xF1A0  # ASCII, e.g. "V03935255DC"
    PARAM_SET_VERSION = 0xF1A1      # ASCII, e.g. "0001"

    # Coding values
    LONG_CODING = 0x0407            # 10 bytes, custom-handler
    SUBSYSTEM_CODING = 0x040F       # 10 bytes, custom-handler
    CODING = 0x0600                 # 7 bytes, the main coding value

    # Writable adaptations (we only READ them — show current state)
    CALIBRATION_PROTOCOL_XCP = 0x0501
    LKU_DERATING = 0x0502
    PROG_NO_RESTBUS = 0x0513
    DEV_MESSAGES = 0x0902
    ASSIST_NO_ENGINE = 0x0930
    SOFTWARE_UPPER_STOP = 0x1921
    DRIVING_MODE_CHANGEOVER = 0x1922
    CHARACTERISTIC_LINE = 0x1920
    STRAIGHT_RUNNING_STABILITY = 0x2BCA


# ----------------------------------------------------------------------------
# Adaptation value tables (raw → human-readable)
# ----------------------------------------------------------------------------
ON_OFF = {0x00: "not active", 0x01: "active"}

LKU_DERATING_TABLE = {
    0x00: "100% (full LKU power)",
    0x01: "80%",
    0x02: "60%",
    0x03: "40%",
    0x04: "20%",
    0x05: "0% (no LKU torque)",
}

CHARACTERISTIC_LINE_TABLE = {
    0x00: "Driving profile selection button",
    0x01: "Comfort",
    0x02: "Automatic",
    0x03: "Dynamic",
    0x04: "Default",
}

DRIVING_MODE_CHANGEOVER_TABLE = {
    0x00: "Incremental, controlled over time (smooth ramp)",
    0x01: "Direct, controlled over threshold value (snappy step)",
}

# (DID, label, value_table_or_None_for_raw)
ADAPTATIONS = [
    (VW_DID.LKU_DERATING,             "LKU_Derating (★ openpilot torque cap)", LKU_DERATING_TABLE),
    (VW_DID.CHARACTERISTIC_LINE,      "Steering_support_Characteristic_Line",  CHARACTERISTIC_LINE_TABLE),
    (VW_DID.CALIBRATION_PROTOCOL_XCP, "Calibration_protocol_XCP",              ON_OFF),
    (VW_DID.ASSIST_NO_ENGINE,         "Steering_assist_without_engine_running",ON_OFF),
    (VW_DID.DEV_MESSAGES,             "Activation of Development Messages",    ON_OFF),
    (VW_DID.PROG_NO_RESTBUS,          "Programming_without_restbus_simulation",ON_OFF),
    (VW_DID.SOFTWARE_UPPER_STOP,      "Software_Upper_Stop",                   ON_OFF),
    (VW_DID.STRAIGHT_RUNNING_STABILITY,"Straight_running_stability",           ON_OFF),
    (VW_DID.DRIVING_MODE_CHANGEOVER,  "Driving_Mode_Changeover",               DRIVING_MODE_CHANGEOVER_TABLE),
]


# ----------------------------------------------------------------------------
# VW Coding Value 0x0600 — 7 bytes, bit-packed
# Format: (byte_index, bit_position, bit_length, label, value_table_or_None)
# ----------------------------------------------------------------------------
CODING_FIELDS = [
    (0, 0, 1, "Counter steer support (DSR)",            ON_OFF),
    (1, 0, 1, "Parallel Parking Assistance (PLA)",      ON_OFF),
    (2, 0, 2, "Pull compensation",
              {0: "not activated",
               1: "active, with learned value",
               2: "active, without learned value"}),
    (3, 0, 1, "Lane Assist (HCA)",                      ON_OFF),
    (3, 4, 1, "Electronic Stability Program",           ON_OFF),
    (4, 0, 1, "Steering angle sensor",                  {0: "internal", 1: "external"}),
    (5, 0, 1, "Hybrid propulsion",                      {0: "not present", 1: "present"}),
    (5, 4, 1, "Start/stop function",                    ON_OFF),
    (5, 6, 1, "Engine start through power steering",    ON_OFF),
    (6, 0, 1, "Driving profile selection (charisma)",   ON_OFF),
    (6, 4, 1, "Yaw rate-dependent mid-shift",           ON_OFF),
]


# ----------------------------------------------------------------------------
# Live-data MWBs to read. Curated subset of the 81 available — most useful
# for openpilot/HCA validation, motor state, vehicle context.
# (DID, label)
# ----------------------------------------------------------------------------
MWBS = [
    # Identification / runtime context
    (0x0288, "Status terminal 15"),
    (0x0286, "Voltage terminal 30"),
    (0x028D, "Control module temperature"),
    (0x0295, "Output stage temperature"),
    (0x1800, "Stator temperature"),
    (0x1801, "Rotor temperature"),
    (0x2B16, "Vehicle speed"),
    (0xF40C, "Engine RPM"),
    (0x1401, "Wheel speed"),
    # Driver torque sensors
    (0x1505, "Steering torque sensor (actual)"),
    (0x1807, "Steering torque sensor signal 1"),
    (0x1808, "Steering torque sensor signal 2"),
    (0x1805, "Steering moment"),
    # Steering angle
    (0x1812, "Steering angle (internal sensor)"),
    (0x1815, "Steering angle angular rate"),
    (0x1480, "Steering angle plausibility"),
    # ★ LKU/HCA path — most relevant for openpilot ★
    (0x1602, "Force_target_steering_support_LKU (HCA target)"),
    (0x180B, "Steering_Support_Engine_Commanded_Torque"),
    (0x180C, "Steering_Support_Engine_Commanded_Power"),
    (0x180D, "Steering_Support_Engine_PWM_Signal"),
    (0x180E, "Steering_Support_Engine_Current"),
    (0x180F, "Steering_Support_Electromotive_Force"),
    (0x2BCB, "Steering_support (total assist)"),
    # ADAS subsystems
    (0x1824, "Driver_Steering_Recommendation (DSR)"),
    (0x1825, "Directional_Stability_Correction"),
    (0x1826, "Lane_Departure_Warning"),
    (0x1827, "Parallel_Parking_Assistant"),
    (0x182E, "Steering_pull_compensation"),
    # System state
    (0x182A, "State_Of_System"),
    (0x182B, "State_Of_Hybrid"),
    (0x1124, "Variant"),
    (0x0102, "Basic Settings Status"),
    (0x02BD, "Standard Freeze Frame"),
]


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _safe_read(uds: UdsClient, did: int, label: str = "") -> bytes | None:
    """Read a DID; return None on error. Swallows ANY exception so the script
    continues even if the rack misbehaves on a single DID."""
    try:
        return uds.read_data_by_identifier(did)
    except NegativeResponseError as e:
        print(f"  [{did:#06x}] NRC: {e}  ({label})")
    except MessageTimeoutError:
        print(f"  [{did:#06x}] timeout  ({label})")
    except Exception as e:  # noqa: BLE001 — debug dump must not abort
        print(f"  [{did:#06x}] {type(e).__name__}: {e}  ({label})")
    return None


def _safe_section(title: str, fn, *args, **kwargs):
    """Run a section function inside a broad try/except. One section
    blowing up should not kill the rest of the dump."""
    _print_section(title)
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        print(f"  section failed: {type(e).__name__}: {e}")


def _print_str_did(uds: UdsClient, did: DATA_IDENTIFIER_TYPE | int, label: str) -> None:
    raw = _safe_read(uds, did, label)
    if raw is None:
        return
    text = raw.decode("utf-8", errors="replace").rstrip("\x00").strip()
    print(f"   {label:<32s} {text}")


def _decode_field(byte_index: int, bit_pos: int, bit_len: int, raw: bytes) -> int:
    """Extract a bit-packed unsigned field from raw bytes."""
    if byte_index >= len(raw):
        return -1
    return (raw[byte_index] >> bit_pos) & ((1 << bit_len) - 1)


def _print_section(title: str) -> None:
    print()
    print(f"=== {title} ===")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true",
                        help="enable ISO-TP/UDS debug output")
    args = parser.parse_args()

    if args.debug:
        carlog.setLevel("DEBUG")

    # Hardware setup — fatal if these fail (no point continuing without panda)
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:  # noqa: BLE001
        print(f"Panda setup failed: {type(e).__name__}: {e}")
        return 1

    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=0.2)

    # Try extended session, but don't abort if it fails — many DIDs are
    # readable in the default session anyway.
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except Exception as e:  # noqa: BLE001
        print(f"Note: failed to enter extended diagnostic session"
              f" ({type(e).__name__}: {e}). Continuing in default session"
              f" — some DIDs may NRC.")

    # Each section is wrapped — one bad call won't kill the rest.
    _safe_section("EPS identification", _section_identification, uds)
    _safe_section("VW Coding Value 0x0600 (7 bytes, decoded)", _section_coding, uds)
    _safe_section("Long coding 0x0407 / Subsystem coding 0x040F", _section_long_coding, uds)
    _safe_section("Adaptations (current values — read-only here)", _section_adaptations, uds)
    _safe_section("Live data (MWB) — raw bytes (no A2L scaling applied)", _section_mwbs, uds)
    _safe_section("Stored DTCs (ReadDTCInformation, status mask=ALL)", _section_dtcs, uds)

    print()
    print("Done. No data was written.")
    return 0


# ----------------------------------------------------------------------------
# Section implementations — each contained so failures isolate
# ----------------------------------------------------------------------------
def _section_identification(uds: UdsClient) -> None:
    for did, label in [
        (DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER,        "Spare part #"),
        (DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER,      "HW part #"),
        (DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER, "SW version"),
        (DATA_IDENTIFIER_TYPE.SYSTEM_NAME_OR_ENGINE_TYPE,                    "System name"),
        (DATA_IDENTIFIER_TYPE.ODX_FILE,                                      "ODX file"),
        (DATA_IDENTIFIER_TYPE.ECU_SERIAL_NUMBER,                             "ECU serial"),
        (DATA_IDENTIFIER_TYPE.BOOT_SOFTWARE_IDENTIFICATION,                  "Boot SW ID"),
        (DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION,           "App SW ID"),
        (DATA_IDENTIFIER_TYPE.APPLICATION_DATA_IDENTIFICATION,               "App data ID"),
        # VW-specific extension DIDs (Car Scanner / VCDS show these)
        (VW_DID.FAZIT_IDENTIFICATION,                                        "FAZIT ID"),
        (VW_DID.PARAM_SET_PART_NUMBER,                                       "Parameter set part #"),
        (VW_DID.PARAM_SET_VERSION,                                           "Parameter set version"),
    ]:
        _print_str_did(uds, did, label)


def _section_coding(uds: UdsClient) -> None:
    coding = _safe_read(uds, VW_DID.CODING, "VW Coding")
    if not coding:
        return
    print(f"   Raw: {coding.hex()}")
    for byte_idx, bit_pos, bit_len, label, table in CODING_FIELDS:
        try:
            val = _decode_field(byte_idx, bit_pos, bit_len, coding)
            meaning = table.get(val, f"value {val}") if table is not None else f"value {val}"
            print(f"   byte {byte_idx} bit {bit_pos}+{bit_len} = {val}  ─ {label:<42s} → {meaning}")
        except Exception as e:  # noqa: BLE001
            print(f"   {label}: decode failed ({type(e).__name__}: {e})")


def _section_long_coding(uds: UdsClient) -> None:
    for did, label in [(VW_DID.LONG_CODING, "0x0407 Long coding (10 B)"),
                       (VW_DID.SUBSYSTEM_CODING, "0x040F Subsystem coding (10 B)")]:
        raw = _safe_read(uds, did, label)
        if raw is not None:
            print(f"   {label}:  {raw.hex()}")


def _section_adaptations(uds: UdsClient) -> None:
    for did, label, table in ADAPTATIONS:
        raw = _safe_read(uds, did, label)
        if raw is None:
            continue
        try:
            if len(raw) == 1:
                val = raw[0]
                meaning = (table.get(val, f"value {val} (out of catalogued range)")
                           if table else f"raw 0x{val:02X}")
                print(f"   {did:#06x} {label:<48s} = 0x{val:02X}  → {meaning}")
            else:
                print(f"   {did:#06x} {label:<48s} = {raw.hex()}")
        except Exception as e:  # noqa: BLE001
            print(f"   {did:#06x} {label}: decode failed ({type(e).__name__}: {e})")


def _section_mwbs(uds: UdsClient) -> None:
    for did, label in MWBS:
        raw = _safe_read(uds, did, label)
        if raw is None:
            continue
        try:
            hex_str = raw.hex()
            decoded = ""
            if len(raw) >= 2:
                u16 = struct.unpack(">H", raw[:2])[0]
                i16 = struct.unpack(">h", raw[:2])[0]
                decoded = f"  (first 2B as u16={u16}, i16={i16})"
            elif len(raw) == 1:
                decoded = f"  (={raw[0]}, signed={raw[0] - 256 if raw[0] > 127 else raw[0]})"
            print(f"   {did:#06x} {label:<46s} {hex_str}{decoded}")
        except Exception as e:  # noqa: BLE001
            print(f"   {did:#06x} {label}: format failed ({type(e).__name__}: {e})")


def _section_dtcs(uds: UdsClient) -> None:
    try:
        resp = uds.read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK,
                                        DTC_STATUS_MASK_TYPE.ALL)
    except NegativeResponseError as e:
        print(f"   ReadDTCInformation NRC: {e}")
        return
    except MessageTimeoutError:
        print("   ReadDTCInformation timeout")
        return
    except Exception as e:  # noqa: BLE001
        print(f"   ReadDTCInformation {type(e).__name__}: {e}")
        return

    if resp is None or len(resp) <= 1:
        print("   (no DTCs reported)")
        return

    avail_mask = resp[0]
    print(f"   status availability mask: 0x{avail_mask:02X}")
    i = 1
    count = 0
    while i + 4 <= len(resp):
        try:
            dtc_hi, dtc_mid, dtc_lo, status = resp[i], resp[i+1], resp[i+2], resp[i+3]
            char_idx = (dtc_hi >> 6) & 0x3
            letter = "PCBU"[char_idx]
            code = ((dtc_hi & 0x3F) << 16) | (dtc_mid << 8) | dtc_lo
            print(f"   {letter}{code:06X}  status=0x{status:02X}")
            count += 1
        except Exception as e:  # noqa: BLE001
            print(f"   DTC parse failed at offset {i}: {type(e).__name__}: {e}")
        i += 4
    if count == 0:
        print("   (no DTCs reported)")


if __name__ == "__main__":
    sys.exit(main())
