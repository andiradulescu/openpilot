#!/usr/bin/env python3
"""
STRICTLY READ-ONLY memory dump of the VW MQB EPS controller (module 0x44).

Attempts UDS `$23 ReadMemoryByAddress` against the documented SRAM and flash
addresses where cal data is known/expected to live, and writes any
successfully-read regions to a binary file under `eps_memdump_<timestamp>/`.

Goal: get the actual cal/parametrization bytes (the contents that the
"V03935255DC" identifier refers to) directly from the live ECU, without
needing to acquire the .zdc / XML file from a paid source.

═════════════════════════════════════════════════════════════════════
SAFETY GUARANTEES
═════════════════════════════════════════════════════════════════════
This script makes ABSOLUTELY NO writes to the ECU. It will NEVER call:
  * `$2E WriteDataByIdentifier`  (writes a DID)
  * `$3D WriteMemoryByAddress`   (writes memory)
  * `$31 RoutineControl`         (could trigger destructive routine)
  * `$34 RequestDownload` / `$36 TransferData` / `$37 TransferExit`
                                  (flash write sequence)
  * `$14 ClearDiagnosticInformation` (clears DTCs — destructive)
  * `$11 ECUReset`               (reboots ECU)
  * `$2F InputOutputControlByIdentifier` (could activate actuator)
  * `$2C DynamicallyDefineDataIdentifier` (modifies ECU state)
  * `$87 LinkControl`            (changes baud rate — could brick comms)
  * `$28 CommunicationControl`   (could disable comms)
  * `$85 ControlDTCSetting`      (modifies DTC behavior)
  * `$86 ResponseOnEvent`        (modifies trigger behavior)
  * `$83 AccessTimingParameter`  (modifies timing)

It will ONLY call:
  * `$10 03 DiagnosticSessionControl`  (extended session — state-only,
                                        no memory or coding modification)
  * `$22 ReadDataByIdentifier`         (read DID — for verification only)
  * `$23 ReadMemoryByAddress`          (read memory — the actual dump)
  * `$3E TesterPresent`                (keepalive — no modification)

It DOES NOT request SecurityAccess. If the ECU denies a `$23` read in the
extended session (which is likely on a production ECU), this script will
log the NRC and continue — NOT escalate to programming session or attempt
auth. Re-running with auth would be a separate, deliberate decision and
would require a different script.

═════════════════════════════════════════════════════════════════════

Usage:
    python3 vw_mqb_eps_memdump.py [--output-dir DIR] [--debug]

Output:
    eps_memdump_<YYYYMMDD_HHMMSS>/
    ├── log.txt                    # human-readable run summary
    ├── 0x4000DC00_RAM_cal.bin     # successful reads written here
    ├── 0x4000E890_motor_struct.bin
    └── ...

Vehicle requirements:
    * Ignition ON, engine may run
    * `tmux kill-session -t comma` if on a comma3 with openpilot up
    * On newer cars: hood may need to be open for some reads
    * No coding/adaptation/flash should be in progress on any ECU
"""

import argparse
import os
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    NegativeResponseError,
    SESSION_TYPE,
)
from opendbc.car.structs import CarParams
from panda import Panda


# ──────────────────────────────────────────────────────────────────────
# CAN addresses (VW MQB direct EPS)
# ──────────────────────────────────────────────────────────────────────
MQB_EPS_TX = 0x712
RX_OFFSET = 0x6A
MQB_EPS_RX = MQB_EPS_TX + RX_OFFSET   # 0x77C


# ──────────────────────────────────────────────────────────────────────
# Memory regions to attempt (in priority order — most useful first)
# Each entry: (address, size, label, why_we_want_it)
# Sizes kept ≤ ~256 B per single $23 to fit comfortably in ISO-TP without
# multi-frame issues. Larger regions are sliced into multiple sequential
# reads in the loop.
# ──────────────────────────────────────────────────────────────────────
class Region(NamedTuple):
    addr: int
    size: int
    label: str
    note: str


REGIONS = [
    # ── SRAM cal RAM-shadow ──
    # Documented in CLAUDE.md as containing the live cal LUTs the EPS uses
    # at runtime. If readable, this IS the V03935255DC cal data currently
    # in effect on this rack.
    Region(0x4000DC00, 0xB64, "RAM_cal_shadow",
           "live cal RAM-shadow region (0x4000DC00..0x4000E764, 2916 B)"),

    # ── SRAM motor command output struct ──
    # Output of fcn.0004f824 — the motor command assembler.
    Region(0x4000E890, 0x100, "motor_cmd_struct",
           "motor command struct populated by fcn.0004f824"),

    # ── HCA pipeline single-value verification points ──
    # Tiny reads to verify a few specific addresses we care about.
    Region(0x40001C90, 0x02, "HCA_input",       "HCA_01 LM_Offset input (signed int16)"),
    Region(0x4000DC30, 0x02, "HCA_scaled_vest", "scaled HCA torque, vestigial path"),
    Region(0x4000EA30, 0x02, "HCA_scaled_live", "scaled HCA torque, live path"),
    Region(0x4000EA82, 0x02, "motor_cmd_halfword", "final motor command halfword"),
    Region(0x4000EAB1, 0x01, "motor_cmd_byte",  "diagnostic byte downsample"),

    # ── EEPROM-shadow coding base ──
    # Per CLAUDE.md, the long-coding bytes (DID 0x0407) live here in
    # ECC-inverted form; reading via $23 may show the raw inverted bytes.
    Region(0x40003700, 0x300, "EEPROM_shadow",
           "EEPROM-shadow at 0x4000_37A8 (coding storage, ECC-inverted)"),

    # ── Flash cal block (in FD_0DATA) ──
    # The 16 KB parametrization base. May be readable if flash $23 is permitted.
    Region(0x00000000, 0x100, "Flash_cal_head",
           "flash 0x00000000 — cal block start (FD_0DATA[0x0])"),
    Region(0x000020E8, 0x100, "Flash_LUT_S65",
           "flash 0x20E8 — candidate LUT (101 entries, table 0x65)"),
    Region(0x00002418, 0x100, "Flash_LUT_S54",
           "flash 0x2418 — candidate LUT (~84 entries, table 0x54)"),

    # ── Flash cal-init descriptor (the elusive 0x76C20 region) ──
    # If $23 can read here, we'd recover the descriptor table that drives
    # the runtime cal init — unlocks the rest of the static-RE chain.
    Region(0x00076C20, 0x200, "Flash_cal_init",
           "flash 0x76C20 — cal-init descriptor table (NOT in our FRF)"),
]

# Maximum bytes per single $23 request. Most VW ECUs accept up to ~256 B
# per ReadMemoryByAddress over ISO-TP. Smaller is safer.
MAX_READ_CHUNK = 0x80


def _read_region(uds: UdsClient, addr: int, size: int, log_fn) -> bytes | None:
    """Read a memory region in MAX_READ_CHUNK-byte chunks. Returns assembled
    bytes on full success, or None on first failure (does not partial-write
    to disk to avoid ambiguous outputs)."""
    out = bytearray()
    cur = addr
    remaining = size
    while remaining > 0:
        chunk_size = min(MAX_READ_CHUNK, remaining)
        try:
            data = uds.read_memory_by_address(
                memory_address=cur,
                memory_size=chunk_size,
                memory_address_bytes=4,
                memory_size_bytes=1,
            )
        except NegativeResponseError as e:
            log_fn(f"      NRC at 0x{cur:08X} +{chunk_size}B: {e}")
            return None
        except MessageTimeoutError:
            log_fn(f"      timeout at 0x{cur:08X} +{chunk_size}B")
            return None
        except Exception as e:  # noqa: BLE001
            log_fn(f"      {type(e).__name__} at 0x{cur:08X}: {e}")
            return None
        if data is None or len(data) == 0:
            log_fn(f"      empty response at 0x{cur:08X}")
            return None
        out.extend(data)
        cur += len(data)
        remaining -= len(data)
        if len(data) < chunk_size:
            log_fn(f"      slave returned {len(data)} of {chunk_size}; continuing")
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("═")[0].strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full safety guarantees.",
    )
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="output directory (default: eps_memdump_<timestamp>/)")
    parser.add_argument("--debug", action="store_true",
                        help="enable ISO-TP/UDS debug output")
    args = parser.parse_args()

    if args.debug:
        carlog.setLevel("DEBUG")

    # Output dir
    out_dir = args.output_dir or Path(f"eps_memdump_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.txt"
    log_file = open(log_path, "w")

    def log(msg: str) -> None:
        print(msg)
        log_file.write(msg + "\n")
        log_file.flush()

    log(f"Output directory: {out_dir.resolve()}")
    log(f"Started: {datetime.now().isoformat()}")
    log("")
    log("STRICTLY READ-ONLY: this script issues only $10 03, $22, $23, $3E.")
    log("                    NO SecurityAccess, NO writes, NO routines.")
    log("")

    # Hardware setup
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:  # noqa: BLE001
        log(f"Panda setup failed: {type(e).__name__}: {e}")
        log_file.close()
        return 1

    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=0.5)

    # Open extended diagnostic session — state change only, no modification
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        log(f"Opened extended diagnostic session ($10 03)")
    except Exception as e:  # noqa: BLE001
        log(f"Note: failed to enter extended session ({type(e).__name__}: {e}). "
            f"Continuing in default session.")

    # Try each region
    n_ok = 0
    n_fail = 0
    for r in REGIONS:
        log("")
        log(f"── 0x{r.addr:08X} +{r.size}B [{r.label}] ──")
        log(f"   {r.note}")
        data = _read_region(uds, r.addr, r.size, log)
        if data is None:
            log(f"   ✗ region NOT readable (likely securityAccessDenied or "
                f"requestOutOfRange)")
            n_fail += 1
            continue
        if len(data) != r.size:
            log(f"   ⚠ partial: got {len(data)} of {r.size} bytes")
        out_file = out_dir / f"0x{r.addr:08X}_{r.label}.bin"
        out_file.write_bytes(data)
        log(f"   ✓ saved {len(data)} bytes → {out_file.name}")
        # Brief preview
        preview = " ".join(f"{b:02x}" for b in data[:16])
        log(f"     first 16 B: {preview}")
        n_ok += 1

    log("")
    log("══════════════════════════════════════════════════════")
    log(f"Regions read OK: {n_ok}")
    log(f"Regions denied:  {n_fail}")
    log("══════════════════════════════════════════════════════")

    if n_ok == 0:
        log("")
        log("$23 ReadMemoryByAddress is locked in extended session on this rack.")
        log("Next options:")
        log("  1. Enable XCP via DID 0x0501 (requires SecurityAccess) and use")
        log("     XCP UPLOAD to read the same addresses — proven cal-tool path.")
        log("  2. Acquire the V03935255DC parameter file from one of the")
        log("     sources in LEADS.md (~$6 USD).")

    log_file.close()
    return 0 if n_ok > 0 else 2


if __name__ == "__main__":
    sys.exit(main())
