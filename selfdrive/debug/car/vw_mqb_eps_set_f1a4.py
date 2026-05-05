#!/usr/bin/env python3
"""
Read or write the VW MQB EPS Vehicle Equipment Code (UDS DID 0xF1A4 = $F1A4).

`$F1A4` is the per-ECU equipment-code latch for module 0x44. It encodes
which equipment lines this rack is provisioned for (e.g. LKAS, ACC,
parking-aid handshakes). It is read by the lane-assist orchestration on
neighboring modules to validate the EPS's advertised feature set; a
mismatch with the gateway-broadcast equipment code makes the wheel-button
LKAS toggle bounce back to OFF.

═════════════════════════════════════════════════════════════════════
WHY THIS SCRIPT EXISTS
═════════════════════════════════════════════════════════════════════
Writing a parametrization dataset (block 0x70 / 0x71) via ODIS-E's
"010.01 Writing the Data Set" job ALSO writes $F1A4 from ODIS-E's ODX
catalog default for the dataset's ZDC (e.g. V03935255DC). That default
is `FF FF FF FF FF FF FF FF FF FF FF FE` for V03935255DC — a "template
/ un-personalized" sentinel, NOT the vehicle's real equipment code.

If the live vehicle had a custom $F1A4 from a retrofit (e.g. MQB Codero
activating LKAS+ACC by setting `00 00 00 00 00 00 00 00 00 00 16 DF`),
the dataset write resets it and breaks LKAS-from-button. This script
restores it. The dataset XML does NOT contain $F1A4 — verified empty in
both block 0x70 and block 0x71 payloads of V03935255DC. So patching the
dataset XML cannot prevent the reset; you must $2E F1A4 separately
after every ODIS-E dataset write.

The openpilot-side `vw_mqb_eps_write_block71.py` writes block 0x71 via
$2E DID 0x0071 directly and DOES NOT touch $F1A4 — preferred deployment
path.

═════════════════════════════════════════════════════════════════════
WIRE PROTOCOL
═════════════════════════════════════════════════════════════════════
  - Service: $22 ReadDataByIdentifier (read), $2E WriteDataByIdentifier (write)
  - DID:     0xF1A4 (standard ISO 14229 identification range)
  - Length:  12 bytes
  - Session: $10 03 Extended (NOT programming)
  - SA:      level 2 ($27 03/04), login 44595 (parametrization tier).
             $F1A4 was successfully written under this login during
             the ODIS-E dataset write — corroborated by the post-write
             screenshot diff. Other logins (28183 adaptation, 19249
             coding) untested for $F1A4 on this ECU.
  - Atomic single-frame ($2E + 12B + DID-header fits in one ISO-TP CF
    after the FF; on bus this is 2 frames total).

═════════════════════════════════════════════════════════════════════
SAFETY POSTURE
═════════════════════════════════════════════════════════════════════
Defaults to read. The actual `$2E` write requires --commit AND a 12-byte
hex-string payload as the new value (no auto-default). On any NRC during
SA, script aborts immediately — does NOT retry alternate logins (would
risk SA-counter lockout).

Vehicle requirements:
  * Ignition ON, engine OFF
  * On newer cars: HOOD OPEN to defeat the diagnostic firewall
  * `tmux kill-session -t comma` if on a comma3 with openpilot up

═════════════════════════════════════════════════════════════════════
USAGE
═════════════════════════════════════════════════════════════════════
    # READ — print current $F1A4
    python3 vw_mqb_eps_set_f1a4.py read

    # WRITE dry-run (full handshake, diff, no $2E)
    python3 vw_mqb_eps_set_f1a4.py write 00:00:00:00:00:00:00:00:00:00:16:DF

    # WRITE commit (actually performs $2E + readback)
    python3 vw_mqb_eps_set_f1a4.py write 00:00:00:00:00:00:00:00:00:00:16:DF --commit

    # Restore Andi's pre-2026-05-05-bump $F1A4 (= the value MQB Codero left)
    python3 vw_mqb_eps_set_f1a4.py write 00:00:00:00:00:00:00:00:00:00:16:DF --commit

Run from the openpilot tree:
    cd ~/Projects/openpilot
    PYTHONPATH=opendbc_repo:panda python3 \\
        selfdrive/debug/car/vw_mqb_eps_set_f1a4.py read
"""

import argparse
import struct
import sys
from datetime import datetime

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

PARAM_LOGIN = 44595

SA_REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2   # 0x03
SA_SEND_KEY     = ACCESS_TYPE.SEND_KEY     + 2   # 0x04

DID_F1A4    = 0xF1A4
F1A4_LEN    = 12

# Andi's pre-bump $F1A4 (set by MQB Codero during the LKAS+ACC retrofit).
# Captured from ODIS-E pre-dataset-write Identification screen 2026-05-05.
KNOWN_GOOD_F1A4 = bytes.fromhex("00" * 10 + "16DF")
# ODIS-E's V03935255DC ODX default. Stamped during "010.01 Writing the
# Data Set". This is the "broken" value that triggered the LKAS-toggle
# regression.
ODIS_DEFAULT_F1A4 = bytes.fromhex("FF" * 11 + "FE")
assert len(KNOWN_GOOD_F1A4) == F1A4_LEN
assert len(ODIS_DEFAULT_F1A4) == F1A4_LEN


def parse_payload(s: str) -> bytes:
    """Accept colon-separated, space-separated, or contiguous hex.
    Examples: '00:00:00:...:16:DF', '00 00 00 ... 16 DF', '00000016DF...'."""
    cleaned = s.replace(":", "").replace(" ", "").replace("-", "").lower()
    try:
        b = bytes.fromhex(cleaned)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not valid hex: {e}")
    if len(b) != F1A4_LEN:
        raise argparse.ArgumentTypeError(
            f"$F1A4 payload must be exactly {F1A4_LEN} bytes ({F1A4_LEN*2} hex chars), got {len(b)}"
        )
    return b


def fmt_f1a4(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def _nrc_byte(e: NegativeResponseError) -> int | None:
    for attr in ("code", "response"):
        v = getattr(e, attr, None)
        if isinstance(v, int):
            return v
        c = getattr(v, "code", None)
        if isinstance(c, int):
            return c
    return None


def open_extended(uds: UdsClient) -> bool:
    print("── Open extended session ($10 03) ──")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except (NegativeResponseError, MessageTimeoutError) as e:
        print(f"  ✗ {type(e).__name__}: {e}")
        return False
    print("  ✓ extended session opened")
    return True


def identify(uds: UdsClient) -> None:
    print("\n── ECU identification ──")
    queries = [
        ("HW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_HARDWARE_NUMBER),
        ("SW part",  DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_SPARE_PART_NUMBER),
        ("SW ver",   DATA_IDENTIFIER_TYPE.VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION_NUMBER),
        ("ODX file", DATA_IDENTIFIER_TYPE.ODX_FILE),
    ]
    for label, did in queries:
        try:
            v = uds.read_data_by_identifier(did)
            print(f"  {label:>9}: {v.decode('utf-8', errors='replace').rstrip(chr(0)).strip()}")
        except (NegativeResponseError, MessageTimeoutError):
            print(f"  {label:>9}: <error>")


def read_f1a4(uds: UdsClient) -> bytes | None:
    print(f"\n── $22 F1 A4 ReadDataByIdentifier ──")
    try:
        v = uds.read_data_by_identifier(DID_F1A4)
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        print(f"  ✗ NRC 0x{nrc:02X}" if nrc is not None else f"  ✗ {e}")
        return None
    except MessageTimeoutError:
        print("  ✗ timeout")
        return None
    if len(v) != F1A4_LEN:
        print(f"  ⚠ unexpected length {len(v)} (expected {F1A4_LEN}): {v.hex()}")
        return v
    print(f"  ✓ $F1A4 = {fmt_f1a4(v)}")
    if v == KNOWN_GOOD_F1A4:
        print("     ↳ matches Andi's pre-bump value (LKAS-from-button should work)")
    elif v == ODIS_DEFAULT_F1A4:
        print("     ↳ this is the ODIS-E V03935255DC ODX default (LKAS toggle WILL bounce)")
        print("     ↳ run: vw_mqb_eps_set_f1a4.py write " + ":".join(f"{x:02X}" for x in KNOWN_GOOD_F1A4) + " --commit")
    return v


def security_access(uds: UdsClient, login: int) -> bool:
    print(f"\n── SecurityAccess L2 (login {login}) ──")
    try:
        seed = uds.security_access(SA_REQUEST_SEED)
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        print(f"  ✗ requestSeed NRC 0x{nrc:02X}" if nrc is not None else f"  ✗ {e}")
        if nrc == 0x36:
            print("     exceededNumberOfAttempts — wait the SA delay (~10 s) before retry.")
        elif nrc == 0x37:
            print("     requiredTimeDelayNotExpired — wait then retry.")
        return False
    except MessageTimeoutError as e:
        print(f"  ✗ requestSeed timeout: {e}")
        return False
    if len(seed) != 4:
        print(f"  ✗ unexpected seed length {len(seed)}: {seed.hex()}")
        return False
    seed_int = struct.unpack("!I", seed)[0]
    key_int = (seed_int + login) & 0xFFFFFFFF
    print(f"  seed=0x{seed_int:08X}, login={login}, key=0x{key_int:08X} (formula: seed + login)")
    try:
        uds.security_access(SA_SEND_KEY, struct.pack("!I", key_int))
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        print(f"  ✗ sendKey NRC 0x{nrc:02X}" if nrc is not None else f"  ✗ {e}")
        if nrc == 0x35:
            print("     invalidKey — formula wrong. Try login 28183 (adaptation) or 19249 (coding).")
        elif nrc == 0x33:
            print("     securityAccessDenied — session/precondition issue, not key formula.")
        return False
    except MessageTimeoutError as e:
        print(f"  ✗ sendKey timeout: {e}")
        return False
    print("  ✓ authenticated")
    return True


def write_f1a4(uds: UdsClient, payload: bytes) -> bool:
    print(f"\n── $2E F1 A4 WriteDataByIdentifier ({len(payload)} bytes) ──")
    print(f"  payload: {fmt_f1a4(payload)}")
    try:
        uds.write_data_by_identifier(DID_F1A4, payload)
    except NegativeResponseError as e:
        nrc = _nrc_byte(e)
        print(f"  ✗ NRC 0x{nrc:02X}" if nrc is not None else f"  ✗ {e}")
        if nrc == 0x33:
            print("     securityAccessDenied — SA didn't take or wore off.")
        elif nrc == 0x31:
            print("     requestOutOfRange — $F1A4 not writable in current session/SA tier.")
        elif nrc == 0x13:
            print("     incorrectMessageLength — payload size wrong.")
        elif nrc == 0x72:
            print("     generalProgrammingFailure — ECU rejected the write.")
        return False
    except MessageTimeoutError:
        print("  ✗ timeout — write did not get a response.")
        return False
    print("  ✓ write accepted (positive response)")
    return True


def cmd_read(args) -> int:
    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=2.0)

    if not open_extended(uds):
        return 1
    identify(uds)
    v = read_f1a4(uds)
    return 0 if v is not None else 1


def cmd_write(args) -> int:
    payload: bytes = args.payload
    print(f"Mode: {'COMMIT (will write)' if args.commit else 'DRY-RUN (no writes)'}")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"New $F1A4: {fmt_f1a4(payload)}")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    uds = UdsClient(panda, MQB_EPS_TX, MQB_EPS_RX, 1, timeout=2.0)

    if not open_extended(uds):
        return 1
    identify(uds)
    current = read_f1a4(uds)
    if current is None:
        print("\n  ✗ aborting — could not read current $F1A4.")
        return 1
    if current == payload:
        print("\n  Current value already matches intended. Nothing to do.")
        return 0

    if not args.commit:
        print("\n── DRY-RUN — no write performed. ──")
        print("To actually write, re-run with --commit.")
        return 0

    if not security_access(uds, args.login):
        return 1

    if not write_f1a4(uds, payload):
        print("\n  ✗ write failed — see NRC above.")
        return 1

    print("\n── Read-back verification ──")
    readback = read_f1a4(uds)
    if readback is None:
        print("  ✗ readback failed; write may still be intact — ignition cycle and re-run `read`.")
        return 1
    if readback != payload:
        print(f"  ✗ readback mismatch: got {fmt_f1a4(readback)}, expected {fmt_f1a4(payload)}")
        return 1
    print(f"  ✓ readback matches intended bytes exactly: {fmt_f1a4(readback)}")
    print("\n══════════════════════════════════════════════════════════════")
    print("DONE. $F1A4 written and verified.")
    print("Cycle ignition (key off ~30 s, then on) and retry the LKAS toggle.")
    print("══════════════════════════════════════════════════════════════")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--login", type=int, default=PARAM_LOGIN,
                   help=f"SA L2 login constant (default {PARAM_LOGIN} = parametrization tier; "
                        f"alternatives: 28183 adaptation, 19249 coding).")
    p.add_argument("--debug", action="store_true",
                   help="enable ISO-TP / UDS debug output")

    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("read", help="$22 F1 A4 — read and display current Vehicle Equipment Code")

    sp_w = sub.add_parser("write", help="$2E F1 A4 — write a new Vehicle Equipment Code")
    sp_w.add_argument("payload", type=parse_payload,
                      help=f"new {F1A4_LEN}-byte payload, colon/space/contiguous hex "
                           f"(e.g. '00:00:00:00:00:00:00:00:00:00:16:DF')")
    sp_w.add_argument("--commit", action="store_true",
                      help="actually write. Default is dry-run (read + diff, no $2E).")

    args = p.parse_args()
    if args.debug:
        carlog.setLevel("DEBUG")

    if args.action == "read":
        return cmd_read(args)
    elif args.action == "write":
        return cmd_write(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
