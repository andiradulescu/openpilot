#!/usr/bin/env python3
"""CCP dumper for Bosch DSG TCU on a comma panda.

Same approach as VW_Flash/lib/dq500_bosch_read.py (which uses python-can),
re-targeted at panda hardware so it can run on a comma device. CCP protocol
work is delegated to opendbc.car.ccp.CcpClient — the same client comma
ships in production. Inspired by willemmelching/pq-flasher/01_dump.py.

The CCP-without-seed-key idea isn't ours: kippdipp first found UPLOAD/SET_MTA
working without unlock on Audi AL551 (bri3d/VW_Flash#123); bri3d's icanhack
part-4 saw the same pattern on a sibling Bosch ECU. Static confirmation on
AL551 ASW at 0x800ccd5a shows UPLOAD lands in the post-CONNECT permitted
branch with no gate. Candidates on DQ500 0DL ASW (0x8003a886, 0x800f2cda)
are not yet xref-confirmed — first real-hardware run resolves it empirically.

Hardware required:
  * comma panda over USB (any colour). Tested topology: panda CAN0 wired
    directly to TCU CAN-H / CAN-L (bench harness or in-car powertrain tap).
  * The OBD-II gateway only routes 0x7E1/0x7E9 to the TCU, so probing the
    other candidate ID pairs requires a tap past the gateway.

Dependencies (use the vendored panda + opendbc_repo at the openpilot root):
  cd ~/Projects/openpilot
  PYTHONPATH=opendbc_repo:panda python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py ...

  Stop openpilot first so the panda is free for exclusive USB access:
    sudo systemctl stop comma   # on a comma device
  Otherwise Panda() will fight openpilot for the device.

Memory map (DQ500 0DL on Renesas SH72549, 3.75 MB program flash @ 0x80000000):

  Region              VA range                   Size      Status
  ------------------  -------------------------  --------  ----------------------
  SBOOT (BHLR0201)    0x80000000 - 0x80010000      64 KB   No plaintext yet — top RE prize
  CBOOT (b41d0501)    0x80010000 - 0x8002FE00     130 KB   Have plaintext from FRF
  ASW                 0x80030000 - 0x8013FE00    1.09 MB   Have plaintext from FRF
  CAL                 0x80140000 - 0x8017FE00     256 KB   Have plaintext from FRF (stale, pre-adapt)
  Unmapped / unknown  0x80180000 - 0x803C0000    2.25 MB   Empty/mirror/factory — sweep to find out

  On-die data flash (adaptation, immo, mileage) lives in a separate address
  space. SH72546R datasheet §26.5.1 describes the access protocol. The
  typical SH-2A on-chip data-flash mirror is 0xF8000000 — try that base
  via CCP MTA once code-flash dumps work. Not part of the 3.75 MB above.

Usage (run from ~/Projects/openpilot with PYTHONPATH=opendbc_repo:panda):

  # 0. In-car go/no-go — no args. Sniffs CAN traffic, probes ID/station
  #    matrix, calls GET_VERSION + EXCHANGE_ID, then reads 16 bytes from
  #    each known region (sboot/cboot/asw/cal). Prints a full report plus
  #    paste-able next-step commands tailored to which regions answered.
  #    Always start here on a real car.
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py

  # 1. Manual single-shot read at any address. Useful for the data-flash
  #    mirror at 0xF8000000 or other speculative probes.
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --start 0xF8000000 --length 0x10 --out df_smoke.bin -v

  # 2. SBOOT — the only region we don't already have plaintext for. Highest
  #    leverage single dump. ~30 sec on a healthy bus.
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --region sboot --out sboot.bin

  # 3. CAL as installed — diff vs FRF-extracted CAL to see what the running
  #    ASW has persisted (adaptation values written back to CAL flash).
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --region cal --out cal_live.bin

  # 4. ASW + CBOOT for round-trip integrity — CCP returns should match the
  #    FRF-extracted plaintext byte-for-byte.
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --region cboot --out cboot.bin
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --region asw --out asw.bin

  # 5. Sweep the unknown region in 64 KB chunks so a region-whitelist NRC
  #    on one chunk doesn't kill the rest of the sweep.
  for off in $(seq 0x180000 0x10000 0x3B0000); do
      python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py \
              --start $((0x80000000 + off)) --length 0x10000 \
              --out unknown_$(printf '%06x' $off).bin || true
  done

  # 6. One-shot full flash (3.75 MB, ~1-3 hours depending on bus health).
  #    Risky if the Bosch CCP impl region-whitelists — bad regions waste
  #    retries. Prefer the staged sequence above on a first pass.
  python3 selfdrive/debug/car/vw_mqb_dsg_ccp_dump.py --region full --out full_flash.bin

Probe-only is the default — to perform a dump you must pass --start, --length,
and --out together. Passing only some of them is an error.

Operational caveats:
  * Bench is much better than in-car for any multi-MB dump. KL15 drops after
    ~30 min idle on most VAG cars and that will kill the session mid-dump.
  * If the probe lands on 0x7E1/0x7E9, the dump can run via OBD. If it only
    answers on 0x6A1/0x6A9 or 0x6C0/0x6C2, you must tap powertrain CAN past
    the gateway (TCU connector or under-dash).
  * Engine off, vehicle in P, KL15 on — clutches are open and the gearbox
    isn't actuating, so a misbehaving CCP frame is at most a DTC.
  * Don't try to dump RAM or peripherals (0xFFFF????) — likely refused, and
    static contents are zero / undefined when the engine isn't running.
"""

import argparse
import logging
import sys
import time

from panda import Panda
from opendbc.car.ccp import (
    BYTE_ORDER,
    CcpClient,
    CommandResponseError,
    CommandTimeoutError,
)
from opendbc.car.structs import CarParams

log = logging.getLogger(__name__)

# Candidate (CRO, DTO) pairs from static analysis of the AL551 ASW CAN-ID
# table at 0x800446cc. Order matters: 0x7E1/0x7E9 first because it's the
# only pair the OBD gateway forwards to the TCU.
DEFAULT_ID_CANDIDATES: tuple[tuple[int, int], ...] = (
    (0x7E1, 0x7E9),
    (0x6C0, 0x6C2),
    (0x6A1, 0x6A9),  # ASAM CCP defaults
    (0x700, 0x703),
)

DEFAULT_STATION_CANDIDATES: tuple[int, ...] = (0x39, 0x01, 0x00, 0xF1)

# Renesas SH72549 is big-endian. Don't change unless retargeting to an LE MCU.
TCU_BYTE_ORDER = BYTE_ORDER.BIG_ENDIAN

# DQ500 0DL flash regions, keyed by name. Sizes from the FRF block table;
# SBOOT size assumed from the CBOOT load VA (0x10000 below it). Used by
# --region <name> to dump a known partition without having to remember the
# numbers.
REGIONS: dict[str, tuple[int, int]] = {
    "sboot":   (0x80000000, 0x10000),    # 64 KB, no plaintext yet — RE prize
    "cboot":   (0x80010000, 0x1FE00),    # 130560 B, have FRF plaintext
    "asw":     (0x80030000, 0x10FE00),   # 1113600 B, have FRF plaintext
    "cal":     (0x80140000, 0x3FE00),    # 261632 B, FRF copy is pre-adapt
    "full":    (0x80000000, 0x3C0000),   # 3.75 MB — whole program flash
}


def probe_connect(panda, bus, id_candidates=DEFAULT_ID_CANDIDATES,
                  station_candidates=DEFAULT_STATION_CANDIDATES, debug=False):
    """Walk (CRO, DTO, station) until CCP CONNECT succeeds. Returns (client, station)."""
    for cro, dto in id_candidates:
        for station in station_candidates:
            client = CcpClient(panda, cro, dto, bus=bus,
                               byte_order=TCU_BYTE_ORDER, debug=debug)
            try:
                client.connect(station)
                log.info("CCP CONNECT ok: CRO=0x%03x DTO=0x%03x station=0x%04x",
                         cro, dto, station)
                return client, station
            except (CommandTimeoutError, CommandResponseError) as exc:
                log.debug("probe CRO=0x%03x DTO=0x%03x station=0x%04x: %s",
                          cro, dto, station, exc)
    return None, None


def sniff_can(panda, bus: int = 0, sniff_ms: int = 200) -> int:
    """Count CAN frames seen on `bus` over sniff_ms. Use to confirm bus is alive."""
    panda.can_clear(0xFFFF)
    deadline = time.monotonic() + sniff_ms / 1000.0
    seen = 0
    while time.monotonic() < deadline:
        for _addr, _data, msg_bus in panda.can_recv() or []:
            if msg_bus == bus:
                seen += 1
        time.sleep(0.005)
    return seen


def smoke_read_regions(client, regions=("sboot", "cboot", "asw", "cal"),
                       n_bytes: int = 16) -> dict:
    """Read n_bytes from each named region. Returns name → (status, addr, payload-or-error)."""
    out: dict = {}
    for name in regions:
        start, _ = REGIONS[name]
        try:
            client.set_memory_transfer_address(0, 0, start)
            data = b""
            while len(data) < n_bytes:
                want = min(5, n_bytes - len(data))
                data += client.upload(want)
            out[name] = ("ok", start, data)
        except (CommandResponseError, CommandTimeoutError) as exc:
            out[name] = ("err", start, str(exc))
    return out


def dump(client, start, length, out_path, chunk=5, progress_every=4096):
    """SET_MTA once + UPLOAD loop. Re-SET_MTA on UPLOAD failure and retry once."""
    if not 1 <= chunk <= 5:
        raise ValueError("CCP chunk must be 1..5 bytes")

    client.set_memory_transfer_address(0, 0, start)
    read = 0
    last_log = 0
    with open(out_path, "wb") as fh:
        while read < length:
            want = min(chunk, length - read)
            try:
                buf = client.upload(want)
            except CommandResponseError as exc:
                log.warning("UPLOAD failed at 0x%08x (%s), resyncing MTA",
                            start + read, exc)
                client.set_memory_transfer_address(0, 0, start + read)
                buf = client.upload(want)
            fh.write(buf)
            read += want
            if read - last_log >= progress_every:
                log.info("  dumped %d/%d bytes (%.1f%%)",
                         read, length, 100.0 * read / length)
                last_log = read
    log.info("Dump complete: %s (%d bytes from 0x%08x)",
             out_path, length, start)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bus", type=int, default=0,
                    help="panda CAN bus number (default 0)")
    ap.add_argument("--cro", type=lambda x: int(x, 0), default=None,
                    help="override CRO CAN ID (default: probe candidate list)")
    ap.add_argument("--dto", type=lambda x: int(x, 0), default=None,
                    help="override DTO CAN ID (default: probe candidate list)")
    ap.add_argument("--station", type=lambda x: int(x, 0), default=None,
                    help="override station address (default: probe candidates)")
    ap.add_argument("--region", choices=sorted(REGIONS.keys()), default=None,
                    help=f"named flash region (sets --start/--length): {', '.join(sorted(REGIONS.keys()))}")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=None,
                    help="dump start address, e.g. 0x80030000 for ASW load VA")
    ap.add_argument("--length", type=lambda x: int(x, 0), default=None,
                    help="dump length in bytes, e.g. 0x10FE00 for ASW size")
    ap.add_argument("--chunk", type=int, default=5,
                    help="UPLOAD bytes per call, 1..5 (default 5)")
    ap.add_argument("--out", default=None, help="output path")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    if args.region is not None:
        if args.start is not None or args.length is not None:
            ap.error("--region is mutually exclusive with --start/--length")
        args.start, args.length = REGIONS[args.region]

    dump_args = (args.start, args.length, args.out)
    if any(a is not None for a in dump_args) and not all(a is not None for a in dump_args):
        ap.error("dump requires --start+--length+--out (or --region+--out); omit all for probe-only")
    do_dump = all(a is not None for a in dump_args)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose >= 2 else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    panda.can_clear(0xFFFF)

    pre_probe_frames = None
    if not do_dump:
        pre_probe_frames = sniff_can(panda, bus=args.bus, sniff_ms=200)

    if args.cro is not None and args.dto is not None and args.station is not None:
        client = CcpClient(panda, args.cro, args.dto, bus=args.bus,
                           byte_order=TCU_BYTE_ORDER, debug=args.verbose >= 2)
        client.connect(args.station)
        station = args.station
    else:
        client, station = probe_connect(panda, args.bus, debug=args.verbose >= 2)
        if client is None:
            print("CCP CONNECT failed on all candidate IDs", file=sys.stderr)
            return 2

    version_str = "unknown"
    try:
        version = client.get_version(2.1)
        version_str = f"{version}"
    except (CommandResponseError, CommandTimeoutError) as exc:
        log.debug("GET_CCP_VERSION failed: %s", exc)

    exchange_str = "skipped"
    try:
        info = client.exchange_station_ids(b"\x00" * 6)
        exchange_str = (f"id_length={info.id_length} data_type={info.data_type} "
                        f"available={info.available} protected={info.protected}")
    except (CommandResponseError, CommandTimeoutError) as exc:
        log.debug("EXCHANGE_ID failed: %s", exc)

    try:
        if do_dump:
            dump(client, args.start, args.length, args.out, chunk=args.chunk)
        else:
            smoke = smoke_read_regions(client)
            via_obd = (client.tx_addr, client.rx_addr) == (0x7E1, 0x7E9)

            print()
            print("Panda")
            traffic_note = "alive" if pre_probe_frames else "NO TRAFFIC — check wiring/ignition"
            print(f"  CAN bus {args.bus}        : {pre_probe_frames} frames in 200 ms ({traffic_note})")
            print()
            print("CCP CONNECT")
            print(f"  CRO/DTO          : 0x{client.tx_addr:03x} / 0x{client.rx_addr:03x}")
            print(f"  station          : 0x{station:04x}")
            print(f"  reach            : {'OBD-routable (gateway forwards this pair)' if via_obd else 'non-OBD ID — gateway must be bypassed'}")
            print(f"  version          : {version_str}")
            print(f"  exchange         : {exchange_str}")
            print()
            print("Region read (16 bytes via SET_MTA + UPLOAD)")
            for name, (status, addr, payload) in smoke.items():
                if status == "ok":
                    hex_str = " ".join(f"{b:02x}" for b in payload)
                    print(f"  {name:5s} @ 0x{addr:08x}  ok    {hex_str}")
                else:
                    print(f"  {name:5s} @ 0x{addr:08x}  err   {payload}")

            ok_regions = [n for n, (s, _, _) in smoke.items() if s == "ok"]
            print()
            if not ok_regions:
                print("CCP CONNECT works but UPLOAD is denied on every known region.")
                print("Seed/key-less hypothesis fails on this firmware. Options:")
                print("  - Try GET_SEED + UNLOCK (not yet implemented in this script).")
                print("  - Move on to bench-side hardware boot-mode entry on SH72549.")
            else:
                script = sys.argv[0]
                flags = (f"--cro 0x{client.tx_addr:x} --dto 0x{client.rx_addr:x} "
                         f"--station 0x{station:x}")
                print("Next steps — paste-able, panda IDs pinned to skip probe:")
                # Highest leverage first: SBOOT (no plaintext), then CAL (live diff vs FRF),
                # then CBOOT/ASW (round-trip integrity vs FRF plaintext).
                priority = [r for r in ("sboot", "cal", "cboot", "asw") if r in ok_regions]
                for region in priority:
                    note = {
                        "sboot": "no plaintext yet — top RE prize",
                        "cal":   "diff vs FRF to find persisted adaptation",
                        "cboot": "should match FRF plaintext byte-for-byte",
                        "asw":   "should match FRF plaintext byte-for-byte",
                    }[region]
                    print()
                    print(f"  # {region} ({note})")
                    print(f"  python3 {script} {flags} \\")
                    print(f"          --region {region} --out {region}.bin")
    finally:
        try:
            client.disconnect(station, temporary=False)
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
