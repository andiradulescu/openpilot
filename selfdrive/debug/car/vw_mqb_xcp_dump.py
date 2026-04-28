#!/usr/bin/env python3
"""
Dump VW MQB EPS memory regions via XCP.

The 5Q0909143 EPS exposes an XCP slave at TX 0x6B0 / RX 0x6B8 on the bus
where the ECU physically lives (bus 0 on a comma3 + J533 harness). The
slave is gated behind a UDS write to DID 0x0501 = 0x01 — but once that
gate opens, XCP UPLOAD requires no seed/key. Validated 2026-04-28.

This script: enables XCP, CONNECTs, dumps one or more memory regions to
files, then disables XCP cleanly.

Usage from /data/openpilot on a comma three:
  tmux kill-session -t comma   # let the panda go
  source /usr/local/venv/bin/activate
  PYTHONPATH=/data/openpilot \\
    python3 selfdrive/debug/car/vw_mqb_xcp_dump.py zdc

Named targets (run with --list to see):
  zdc           0x0005E000  0x02000  master ZDC parametrization (8 KB)
  cal_shadow    0x40004000  0x10000  RAM-shadowed cal block (64 KB)
  dispatch      0x0007630C  0x02000  off-FRF UDS dispatch region (8 KB)
  perm_matrix   0x40000CDA  0x00400  SRAM per-session permission matrix (1 KB)

Custom region:
  python3 vw_mqb_xcp_dump.py custom --addr 0x40004000 --size 0x100 --out cal.bin

All-at-once:
  python3 vw_mqb_xcp_dump.py all
"""

import argparse
import struct
import sys
import time
from datetime import date
from enum import IntEnum
from pathlib import Path

from opendbc.car.carlog import carlog
from opendbc.car.uds import (
    UdsClient,
    MessageTimeoutError,
    SESSION_TYPE,
    DATA_IDENTIFIER_TYPE,
    ACCESS_TYPE,
)
from opendbc.car.xcp import (
    XcpClient,
    CommandTimeoutError,
    CommandResponseError,
)
from opendbc.car.structs import CarParams
from panda import Panda


# ─── UDS / XCP constants ──────────────────────────────────────────────────────

class VW_DATA_IDENTIFIER(IntEnum):
    CALIBRATION_PROTOCOL_XCP = 0x0501


class ACCESS_TYPE_LEVEL_2(IntEnum):
    REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2  # 0x03
    SEND_KEY = ACCESS_TYPE.SEND_KEY + 2          # 0x04


SECURITY_ACCESS_CONSTANT = 28183  # SA2 — same algorithm as LKU_Derating / config

MQB_EPS_TX = 0x712
MQB_EPS_RX = 0x77C
DEFAULT_UDS_BUS = 1   # comma3 + J533: gateway-routed UDS to EPS
DEFAULT_XCP_BUS = 0   # comma3 + J533: CAN_EXTENDED MITM A — where EPS lives

XCP_TX = 0x6B0  # validated 2026-04-28
XCP_RX = 0x6B8

# After DID 0x0501 = 0x01 the XCP slave needs ~1s before it accepts CONNECT.
# Empirically: 0.3s misses it, 2.0s catches it. Use 1.5s for safety.
XCP_WARMUP_SECONDS = 1.5

# UPLOAD `size` parameter is a single byte (max 255). Keep it under that, and
# leave a little headroom. With slave_block_mode=True the slave will spread
# this across multiple CTOs; we still wait for them all in upload().
UPLOAD_CHUNK_BYTES = 250


# ─── Targets ──────────────────────────────────────────────────────────────────

TARGETS: dict[str, tuple[int, int, str]] = {
    # name           (addr,        size,    description)
    "zdc":          (0x0005E000, 0x02000, "master ZDC parametrization (8 KB flash)"),
    "cal_shadow":   (0x40004000, 0x10000, "RAM-shadowed cal block (64 KB SRAM)"),
    "dispatch":     (0x0007630C, 0x02000, "off-FRF UDS dispatch region (8 KB flash)"),
    "perm_matrix":  (0x40000CDA, 0x00400, "SRAM per-session permission matrix (1 KB)"),
}


# ─── UDS phase ────────────────────────────────────────────────────────────────

def open_extended_session(uds: UdsClient) -> None:
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except MessageTimeoutError:
        sys.exit("Timeout opening extended diagnostic session with EPS")


def enable_xcp(uds: UdsClient) -> None:
    """SA2 + prerequisites + $2E 0501 01. Mirrors vw_mqb_xcp_probe.py:enable_xcp()."""
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
    """Best-effort. After XCP CONNECT, $2E may return NRC 0x7F — accept it.
    The XCP-active flag clears anyway on session timeout / ignition cycle."""
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
        print(f"  ⚠ disable XCP returned: {e}")
        print("  ⚠ XCP-active flag will clear on S3 timeout / ignition cycle — usually fine")


# ─── XCP read loop ────────────────────────────────────────────────────────────

def dump_region(client: XcpClient, addr: int, size: int, out_path: Path,
                progress_every: int = 4096) -> None:
    """SET_MTA(addr) + repeated UPLOAD(chunk) → out_path.

    XCP UPLOAD auto-advances MTA, so a single SET_MTA per region is enough.
    """
    print(f"  → dumping {size} B from 0x{addr:08X} to {out_path}")
    client.set_mta(addr)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    bytes_done = 0
    next_progress = progress_every
    started = time.monotonic()
    with out_path.open("wb") as f:
        while bytes_done < size:
            chunk = min(UPLOAD_CHUNK_BYTES, size - bytes_done)
            data = client.upload(chunk)
            if len(data) != chunk:
                raise RuntimeError(
                    f"short UPLOAD at offset 0x{bytes_done:X}: asked {chunk} got {len(data)}"
                )
            f.write(data)
            bytes_done += chunk
            if bytes_done >= next_progress or bytes_done == size:
                elapsed = time.monotonic() - started
                rate = bytes_done / elapsed if elapsed > 0 else 0
                print(
                    f"    {bytes_done}/{size} B ({100*bytes_done/size:.0f}%) "
                    f"at {rate/1024:.1f} KB/s"
                )
                next_progress += progress_every

    # Sanity: we asked for `size` bytes, got `bytes_done`.
    assert bytes_done == size, f"size mismatch: asked {size} got {bytes_done}"


# ─── Argparse / orchestration ─────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "target", nargs="?", default=None,
        help="named target (zdc / cal_shadow / dispatch / perm_matrix), "
             "'all' for every named target, or 'custom' with --addr/--size/--out",
    )
    p.add_argument("--addr", type=lambda s: int(s, 0),
                   help="address for 'custom' target")
    p.add_argument("--size", type=lambda s: int(s, 0),
                   help="size in bytes for 'custom' target")
    p.add_argument("--out", type=Path,
                   help="output file for 'custom' target")
    p.add_argument("--outdir", type=Path, default=Path.cwd(),
                   help="output directory for named targets (default: cwd)")
    p.add_argument("--list", action="store_true",
                   help="list named targets and exit")
    p.add_argument("--uds-bus", type=int, default=DEFAULT_UDS_BUS, choices=(0, 1, 2),
                   help=f"CAN bus for UDS (default {DEFAULT_UDS_BUS})")
    p.add_argument("--xcp-bus", type=int, default=DEFAULT_XCP_BUS, choices=(0, 1, 2),
                   help=f"CAN bus for XCP (default {DEFAULT_XCP_BUS})")
    p.add_argument("--debug", action="store_true",
                   help="enable XCP / UDS debug logging")
    return p.parse_args()


def expand_targets(args: argparse.Namespace) -> list[tuple[str, int, int, Path]]:
    """Returns list of (label, addr, size, out_path)."""
    if args.target == "custom":
        if args.addr is None or args.size is None or args.out is None:
            sys.exit("'custom' target requires --addr, --size, --out")
        return [("custom", args.addr, args.size, args.out)]
    if args.target == "all":
        return [
            (name, addr, size, args.outdir / f"{name}.bin")
            for name, (addr, size, _) in TARGETS.items()
        ]
    if args.target in TARGETS:
        addr, size, _ = TARGETS[args.target]
        return [(args.target, addr, size, args.outdir / f"{args.target}.bin")]
    sys.exit(f"unknown target {args.target!r} — try --list")


def main() -> int:
    args = parse_args()
    if args.list:
        print("Named targets:")
        for name, (addr, size, desc) in TARGETS.items():
            print(f"  {name:<14} 0x{addr:08X}  0x{size:05X}  {desc}")
        return 0
    if args.target is None:
        sys.exit("a target is required (try --list, or 'all', or 'zdc')")
    if args.debug:
        carlog.setLevel("DEBUG")

    plan = expand_targets(args)
    print("Started:", time.strftime("%Y-%m-%dT%H:%M:%S"))
    print(f"UDS on bus {args.uds_bus}, XCP on bus {args.xcp_bus}")
    print(f"XCP slave: TX 0x{XCP_TX:03X} → RX 0x{XCP_RX:03X}")
    print("Plan:")
    for label, addr, size, path in plan:
        print(f"  • {label}: 0x{addr:08X}+{size} B → {path}")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    panda.can_clear(0xFFFF)

    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, args.uds_bus, timeout=0.2)
    open_extended_session(uds)
    print("Opened extended diagnostic session ($10 03)")

    print("\n──── Enabling XCP slave ────")
    enable_xcp(uds)
    print(f"  ✓ DID 0x0501 = 0x01")
    print(f"  sleeping {XCP_WARMUP_SECONDS}s for slave warmup")
    time.sleep(XCP_WARMUP_SECONDS)

    client = XcpClient(panda, XCP_TX, XCP_RX, bus=args.xcp_bus, timeout=1.0,
                       debug=args.debug)
    failures: list[str] = []
    try:
        info = client.connect()
        print(f"  ✓ XCP CONNECT (max_cto={info['max_cto']}, max_dto={info['max_dto']}, "
              f"block_mode={info['slave_block_mode']})")

        for label, addr, size, out in plan:
            print(f"\n──── Region: {label} ────")
            try:
                dump_region(client, addr, size, out)
                actual = out.stat().st_size
                print(f"  ✓ wrote {actual} B → {out}")
            except (CommandTimeoutError, CommandResponseError, RuntimeError) as e:
                print(f"  ✗ {label} failed: {e}")
                failures.append(label)
                # Try to keep going — re-CONNECT so the next region starts clean
                try:
                    client.disconnect()
                except Exception:
                    pass
                try:
                    client.connect()
                except Exception as recon_err:
                    print(f"  ✗ couldn't reconnect after failure: {recon_err}")
                    break
    finally:
        print("\n──── Disconnecting XCP ────")
        try:
            client.disconnect()
            print("  ✓ XCP DISCONNECT")
        except Exception as e:
            print(f"  ⚠ disconnect failed: {e}")

        print("\n──── Disabling XCP slave ────")
        disable_xcp(uds)

    if failures:
        print(f"\n✗ {len(failures)} region(s) failed: {', '.join(failures)}")
        return 1

    print("\n✓ all regions dumped successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
