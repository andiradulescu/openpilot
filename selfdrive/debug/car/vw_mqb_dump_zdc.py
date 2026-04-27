#!/usr/bin/env python3
"""
Dump VW MQB EPS parametrization (ZDC) regions from the live rack.

Targets three regions documented in PARAMETRIZATION.md:

    0x70    EEPROM short-block — scalar config / login codes (~1.23 KB)
    0x71    EEPROM short-block — 2D-LUT shadow (per-vehicle assist curves) (~1.95 KB)
    0x5E000 8 KB master parametrization image (separate flash bank)

The script tries multiple UDS read services for each region, in order of
likelihood of success:

  1. `$22 ReadDataByIdentifier` — cheapest. Probably fails for 0x0070/0x0071;
     may succeed if the EPS's custom-DID dispatcher (the routine at 0x1CFD0)
     happens to expose them as low DIDs.
  2. `$23 ReadMemoryByAddress` — treat the partition selector as a 1-byte
     memory address (matching how `$34 RequestDownload` writes use 1-byte
     selectors per `eps_flash.py`); 4-byte address for 0x5E000.
  3. `$35 RequestUpload` + `$36 TransferData` + `$37 RequestTransferExit`
     — the read counterpart of the flash-write workflow; how ODIS itself
     would read these. Requires SecurityAccess level 2 first.

Usage:
    python3 vw_mqb_dump_zdc.py 70           # partition selector 0x70
    python3 vw_mqb_dump_zdc.py 71           # partition selector 0x71
    python3 vw_mqb_dump_zdc.py 5e000        # 8 KB blob @ flash 0x5E000
    python3 vw_mqb_dump_zdc.py all          # all three
    python3 vw_mqb_dump_zdc.py 71 -o my.bin # custom output filename

Run from the openpilot tree, same way as `vw_mqb_lku_derating.py`:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 ~/Projects/re-vw/steering/vw_mqb_dump_zdc.py 71

Vehicle requirements: same as `vw_mqb_lku_derating.py` — ignition ON,
hood open if newer model, openpilot stopped (`tmux kill-session -t comma`).
"""

import argparse
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

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


MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x712 + 0x6A   # = 0x77C
SECURITY_ACCESS_CONSTANT = 28183  # SA2 key offset (same as LKU_Derating script)


# Documented in PARAMETRIZATION.md. (selector_value, expected_length, label)
REGIONS = {
    "70":    (0x70,     1226,  "EEPROM block 0x70 (scalar config)",        1, 2),  # 1-byte addr, 2-byte size
    "71":    (0x71,     1950,  "EEPROM block 0x71 (2D-LUT shadow)",        1, 2),
    "5e000": (0x5E000,  0x2000, "Flash-region 8 KB master parametrization", 4, 2),
}


class ACCESS_TYPE_LEVEL_2:
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2           # 0x04


def open_session(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended diagnostic session with EPS")


def identify(uds: UdsClient) -> None:
    """Print rack identification — confirms the dump target before reading."""
    try:
        hw = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER
        ).decode("utf-8", errors="replace").strip()
        sw = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER
        ).decode("utf-8", errors="replace").strip()
        ver = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER
        ).decode("utf-8", errors="replace").strip()
        odx = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.ODX_FILE
        ).decode("utf-8", errors="replace").rstrip("\x00").strip()
    except (NegativeResponseError, MessageTimeoutError) as e:
        sys.exit(f"Error reading rack identification: {e}")

    print("\nEPS identification")
    print(f"  HW part:  {hw}")
    print(f"  SW part:  {sw}")
    print(f"  SW ver:   {ver}")
    print(f"  ODX file: {odx}")
    print()


def security_access_l2(uds: UdsClient) -> bool:
    """Run SA2. Returns True on success."""
    try:
        seed = uds.security_access(ACCESS_TYPE_LEVEL_2.REQUEST_SEED)
        key = struct.unpack("!I", seed)[0] + SECURITY_ACCESS_CONSTANT
        uds.security_access(ACCESS_TYPE_LEVEL_2.SEND_KEY, struct.pack("!I", key))
        return True
    except (NegativeResponseError, MessageTimeoutError) as e:
        print(f"  SecurityAccess L2 failed: {e}")
        return False


def try_rdbi(uds: UdsClient, selector: int) -> bytes | None:
    """Method 1: $22 ReadDataByIdentifier with selector zero-extended to 16 bits."""
    if selector > 0xFFFF:
        return None  # RDBI is 16-bit only
    print(f"  [1/3] $22 {selector:04X} (ReadDataByIdentifier) ...", end=" ", flush=True)
    try:
        data = uds.read_data_by_identifier(selector)
        print(f"OK ({len(data)} bytes)")
        return data
    except NegativeResponseError as e:
        print(f"NRC: {e}")
    except MessageTimeoutError:
        print("timeout")
    return None


def try_rmba(uds: UdsClient, address: int, size: int, addr_bytes: int, size_bytes: int) -> bytes | None:
    """Method 2: $23 ReadMemoryByAddress."""
    print(f"  [2/3] $23 (ReadMemoryByAddress, addr_bytes={addr_bytes}, size_bytes={size_bytes}) ...", end=" ", flush=True)
    try:
        data = uds.read_memory_by_address(address, size, memory_address_bytes=addr_bytes, memory_size_bytes=size_bytes)
        print(f"OK ({len(data)} bytes)")
        return data
    except NegativeResponseError as e:
        print(f"NRC: {e}")
    except MessageTimeoutError:
        print("timeout")
    return None


def try_upload(uds: UdsClient, address: int, size: int, addr_bytes: int, size_bytes: int) -> bytes | None:
    """Method 3: $35 RequestUpload + $36 TransferData* + $37 RequestTransferExit."""
    print(f"  [3/3] $35 RequestUpload (addr_bytes={addr_bytes}, size_bytes={size_bytes}) ...", end=" ", flush=True)
    try:
        max_block = uds.request_upload(address, size,
                                       memory_address_bytes=addr_bytes,
                                       memory_size_bytes=size_bytes)
        print(f"accepted, max_block={max_block}")
    except NegativeResponseError as e:
        print(f"NRC: {e}")
        return None
    except MessageTimeoutError:
        print("timeout")
        return None

    # Pull the data: the $36 response payload size is `max_block` minus 1 PCI/SID byte.
    chunk_payload = max_block - 2  # SID(1) + sequence(1) overhead inside the protocol
    if chunk_payload <= 0:
        print(f"  invalid chunk size derived from max_block={max_block}")
        try:
            uds.request_transfer_exit()
        except Exception:
            pass
        return None

    out = bytearray()
    seq = 1
    expected_total = size
    while len(out) < expected_total:
        try:
            chunk = uds.transfer_data(seq & 0xFF)
        except (NegativeResponseError, MessageTimeoutError) as e:
            print(f"  $36 transfer_data seq={seq} failed: {e}")
            try:
                uds.request_transfer_exit()
            except Exception:
                pass
            return bytes(out) if out else None
        if not chunk:
            break
        out.extend(chunk)
        seq += 1
        if seq % 16 == 0:
            print(f"    transferred {len(out)}/{expected_total} bytes...")

    try:
        uds.request_transfer_exit()
    except (NegativeResponseError, MessageTimeoutError) as e:
        print(f"  $37 request_transfer_exit warning: {e}")

    print(f"  upload complete, got {len(out)}/{expected_total} bytes")
    return bytes(out) if out else None


def dump_one(uds: UdsClient, key: str, output_path: Path) -> bool:
    """Try methods 1-3 against one region. Save first non-None result."""
    selector, size, label, addr_bytes, size_bytes = REGIONS[key]
    print(f"\n=== Dumping {label}  (selector/addr=0x{selector:X}, expected {size} bytes) ===")

    # Method 1 — ReadDataByIdentifier (only valid for 1- or 2-byte selectors)
    data = try_rdbi(uds, selector) if selector <= 0xFFFF else None

    # Method 2 — ReadMemoryByAddress
    if data is None:
        data = try_rmba(uds, selector, size, addr_bytes, size_bytes)

    # Method 3 — RequestUpload (needs SA2 — try once if methods 1+2 both fail)
    if data is None:
        print("  attempting SecurityAccess L2 for upload path ...")
        if security_access_l2(uds):
            data = try_upload(uds, selector, size, addr_bytes, size_bytes)
        else:
            print("  skipping $35 path (SA2 not granted)")

    if data is None:
        print(f"  ✗ all methods failed for {label}")
        return False

    output_path.write_bytes(data)
    print(f"  ✓ wrote {len(data)} bytes to {output_path}")
    return True


def main():
    p = argparse.ArgumentParser(
        description="Dump VW MQB EPS parametrization regions over UDS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See re-vw/steering/PARAMETRIZATION.md for region details.",
    )
    p.add_argument("region", choices=["70", "71", "5e000", "all"],
                   help="region to dump")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="output filename (default: eps_dump_<region>_<timestamp>.bin)")
    p.add_argument("--debug", action="store_true",
                   help="enable ISO-TP/UDS debug output")
    args = p.parse_args()

    if args.debug:
        carlog.setLevel("DEBUG")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=0.5)

    open_session(uds)
    identify(uds)

    regions = list(REGIONS.keys()) if args.region == "all" else [args.region]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = {}
    for key in regions:
        if args.output and len(regions) == 1:
            outpath = args.output
        else:
            outpath = Path(f"eps_dump_{key}_{timestamp}.bin")
        results[key] = dump_one(uds, key, outpath)

    print("\n=== Summary ===")
    for key, ok in results.items():
        print(f"  {key}: {'OK' if ok else 'FAILED'}")
    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
