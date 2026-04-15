#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path

from openpilot.system.ui.lib.wifi_manager import NetworkStore
from openpilot.system.ui.lib.wpa_ctrl import (
  SecurityType,
  dbm_to_percent,
  flags_to_security_type,
  parse_scan_results,
  parse_status,
)


NM_CONNECTIONS_DIR = Path("/data/etc/NetworkManager/system-connections")


@dataclass(frozen=True)
class Checkpoint:
  checkpoint_id: str
  title: str
  goal: str
  steps: list[str]
  pass_criteria: list[str]


CHECKPOINTS = [
  Checkpoint(
    checkpoint_id="failover_ab",
    title="Saved Failover A to B",
    goal="Forgetting the current saved network should roam to another saved network in range.",
    steps=[
      "Make sure two saved networks are available and in range, for example systeam and systeam5.",
      "Connect to the first network from the UI.",
      "Confirm both saved profiles exist on disk before you start.",
      "Hit Forget on the current network from the UI.",
      "Wait for the device to roam to the second saved network.",
    ],
    pass_criteria=[
      "The forgotten network disappears from the saved profile list on disk.",
      "The device reconnects to the second saved network without manual selection.",
      "wpa_state ends at COMPLETED and the daemon snapshot matches it.",
    ],
  ),
  Checkpoint(
    checkpoint_id="failover_ba",
    title="Saved Failover B to A",
    goal="Verify failover works in the reverse direction too.",
    steps=[
      "Connect to the second saved network from the UI.",
      "Hit Forget on the current network from the UI.",
      "Wait for the device to roam back to the first saved network.",
    ],
    pass_criteria=[
      "The forgotten network is removed from disk.",
      "The device reconnects to the other saved network without manual selection.",
      "The final state is COMPLETED with an IP address.",
    ],
  ),
  Checkpoint(
    checkpoint_id="tethering",
    title="Tethering End to End",
    goal="Tethering should start, hand out DHCP, provide internet, and recover back to station mode.",
    steps=[
      "Start from a working station-mode WiFi connection.",
      "Enable tethering in the UI.",
      "Join the AP from another device and wait for DHCP.",
      "Verify internet access through the tether.",
      "Disable tethering in the UI.",
      "Wait for the device to return to station mode.",
    ],
    pass_criteria=[
      "A client receives an IP address from the AP.",
      "Internet access works through the tether.",
      "Disabling tethering returns the device to a saved WiFi network automatically.",
    ],
  ),
  Checkpoint(
    checkpoint_id="reboot_pre",
    title="Reboot Precheck",
    goal="Capture state before a reboot-based auto-connect test.",
    steps=[
      "Leave at least one valid saved WiFi network available and in range.",
      "Run this checkpoint to capture the pre-reboot state.",
      "Reboot the device.",
      "After the reboot, rerun this script with --only reboot_post.",
    ],
    pass_criteria=[
      "The pre-reboot state is captured for comparison after boot.",
    ],
  ),
  Checkpoint(
    checkpoint_id="reboot_post",
    title="Reboot Auto-Connect",
    goal="After a cold boot, WiFi should reconnect without opening the network UI.",
    steps=[
      "Do not open the network settings immediately after boot.",
      "Wait for the WiFi daemon to settle.",
      "Capture the post-reboot state with this checkpoint.",
    ],
    pass_criteria=[
      "The device auto-connects to a saved WiFi network after boot.",
      "The daemon snapshot and wpa_cli both show the same connected SSID and IP state.",
    ],
  ),
  Checkpoint(
    checkpoint_id="ui_restart_connected",
    title="UI Restart While Connected",
    goal="Restarting the UI while connected should not interrupt WiFi.",
    steps=[
      "Start from a stable WiFi connection.",
      "Kill selfdrive.ui.ui from another shell.",
      "Wait for manager to respawn the UI.",
      "Confirm the UI returns showing the same network state.",
    ],
    pass_criteria=[
      "WiFi stays up during the UI restart.",
      "The UI comes back and shows the correct connected SSID.",
    ],
  ),
  Checkpoint(
    checkpoint_id="ui_restart_connecting",
    title="UI Restart While Connecting",
    goal="Restarting the UI during an in-flight connect should not wedge the WiFi daemon.",
    steps=[
      "Begin a WiFi connect attempt from the UI.",
      "While it is still connecting, kill selfdrive.ui.ui from another shell.",
      "Wait for the UI to respawn.",
      "Confirm the connect attempt either succeeds or fails cleanly instead of hanging forever.",
    ],
    pass_criteria=[
      "The WiFi daemon survives the UI restart.",
      "The final state resolves to CONNECTED or DISCONNECTED plus need-auth, not a stuck CONNECTING.",
    ],
  ),
  Checkpoint(
    checkpoint_id="hidden_network",
    title="Hidden Network",
    goal="Hidden SSIDs should connect, persist, and reconnect.",
    steps=[
      "Add a hidden SSID with the correct password from the UI.",
      "Connect successfully.",
      "Confirm the profile is saved on disk.",
      "Optionally reboot and rerun reboot_post if you want a boot validation for the hidden network.",
      "Forget the hidden network and confirm removal.",
    ],
    pass_criteria=[
      "The hidden network connects successfully.",
      "The hidden network persists to a .nmconnection file after success.",
      "Forgetting it removes the saved profile from disk.",
    ],
  ),
  Checkpoint(
    checkpoint_id="password_update",
    title="Password Update",
    goal="A wrong password attempt must not poison a good saved entry.",
    steps=[
      "Start with a working saved network.",
      "Try that same SSID with an intentionally wrong password.",
      "Confirm the connection fails cleanly.",
      "Retry with the correct password.",
      "Confirm the connection succeeds and the saved profile stays valid.",
    ],
    pass_criteria=[
      "The wrong-password attempt does not leave a bad .nmconnection on disk.",
      "The correct retry reconnects successfully.",
      "The network remains saved with working credentials afterward.",
    ],
  ),
  Checkpoint(
    checkpoint_id="route_sanity",
    title="Route Sanity",
    goal="Station and tether transitions should leave sane routing state behind.",
    steps=[
      "Capture state while connected on WiFi.",
      "If testing tethering, enable tethering and later disable it before this checkpoint finishes.",
      "Capture state again after returning to station mode.",
      "Compare default routes and interface state.",
    ],
    pass_criteria=[
      "A usable default route exists when WiFi is connected.",
      "No bad tethering leftovers remain after returning to station mode.",
    ],
  ),
  Checkpoint(
    checkpoint_id="timing",
    title="Connect Timing",
    goal="Record connect-to-IP timings over five runs for the bonus target.",
    steps=[
      "Pick one stable WPA2 network.",
      "From a disconnected state, connect to that network five times.",
      "For each run, measure from the connect action until ip_address appears in wpa_cli status.",
      "Enter the measured times in the notes field.",
    ],
    pass_criteria=[
      "Five runs are recorded with times in seconds.",
      "If you have a NetworkManager baseline, compare each run against it.",
    ],
  ),
]

CHECKPOINTS_BY_ID = {cp.checkpoint_id: cp for cp in CHECKPOINTS}


def run_command(cmd: list[str], timeout: float = 5.0) -> str:
  try:
    result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout)
  except Exception as e:
    return f"<error: {e}>"

  stdout = result.stdout.strip()
  stderr = result.stderr.strip()
  if result.returncode == 0:
    return stdout
  if stdout and stderr:
    return f"{stdout}\n<stderr>\n{stderr}"
  return stdout or stderr or f"<exit {result.returncode}>"


def collect_nmconnections() -> list[dict[str, str | int]]:
  entries: list[dict[str, str | int]] = []
  if not NM_CONNECTIONS_DIR.exists():
    return entries

  for path in sorted(NM_CONNECTIONS_DIR.glob("*.nmconnection")):
    stat = path.stat()
    entries.append({
      "name": path.name,
      "mode": oct(stat.st_mode & 0o777),
      "uid": stat.st_uid,
      "gid": stat.st_gid,
      "size": stat.st_size,
      "mtime": int(stat.st_mtime),
    })
  return entries


def collect_daemon_snapshot() -> dict:
  """Snapshot the live wifi state without instantiating a WifiManager.

  WifiManager.__init__ kicks off _initialize(), which can reconfigure
  wlan0/wpa_supplicant and then stop() tears it back down. For a
  validation tool that is supposed to *measure* state, constructing a
  second manager would perturb the thing under test and return stale
  defaults. Read wpa_supplicant directly via wpa_cli and the filesystem.
  """
  try:
    status_raw = run_command(["wpa_cli", "-i", "wlan0", "status"])
    try:
      status = parse_status(status_raw)
    except Exception:
      status = {}

    wpa_state = status.get("wpa_state", "")
    mode = status.get("mode", "")
    ssid = status.get("ssid")

    if mode == "AP":
      tethering_active = True
      wifi_state_ssid = ssid
      wifi_state_status = 2  # ConnectStatus.CONNECTED
    else:
      tethering_active = False
      if wpa_state == "COMPLETED" and ssid:
        wifi_state_ssid = ssid
        wifi_state_status = 2
      elif wpa_state in ("ASSOCIATING", "AUTHENTICATING", "4WAY_HANDSHAKE",
                         "GROUP_HANDSHAKE", "SCANNING"):
        wifi_state_ssid = ssid
        wifi_state_status = 1  # CONNECTING
      else:
        wifi_state_ssid = None
        wifi_state_status = 0  # DISCONNECTED

    ipv4_address = ""
    addr_raw = run_command(["ip", "-4", "-o", "addr", "show", "dev", "wlan0"])
    for line in addr_raw.splitlines():
      parts = line.split()
      if "inet" in parts:
        cidr = parts[parts.index("inet") + 1]
        ipv4_address = cidr.split("/", 1)[0]
        break

    scan_raw = run_command(["wpa_cli", "-i", "wlan0", "scan_results"])
    try:
      scan_results = parse_scan_results(scan_raw)
    except Exception:
      scan_results = []
    seen_ssids: set[str] = set()
    networks: list[dict] = []
    for result in scan_results:
      if not result.ssid or result.ssid in seen_ssids:
        continue
      seen_ssids.add(result.ssid)
      try:
        security = flags_to_security_type(result.flags)
      except Exception:
        security = SecurityType.UNSUPPORTED
      networks.append({
        "ssid": result.ssid,
        "strength": dbm_to_percent(result.signal),
        "security_type": int(security),
        "is_tethering": False,
      })

    try:
      saved_ssids = sorted(NetworkStore().saved_ssids())
    except Exception:
      saved_ssids = []

    return {
      "wifi_state": {
        "ssid": wifi_state_ssid,
        "status": wifi_state_status,
      },
      "ipv4_address": ipv4_address,
      "saved_ssids": saved_ssids,
      "networks": networks,
      "tethering_active": tethering_active,
    }
  except Exception as e:
    return {"error": str(e)}


def collect_snapshot() -> dict:
  wpa_status_raw = run_command(["wpa_cli", "-i", "wlan0", "status"])
  try:
    parsed_status = parse_status(wpa_status_raw)
  except Exception:
    parsed_status = {"raw": wpa_status_raw}

  return {
    "timestamp": datetime.now(UTC).isoformat(),
    "wpa_status": parsed_status,
    "wpa_status_raw": wpa_status_raw,
    "wpa_networks_raw": run_command(["wpa_cli", "-i", "wlan0", "list_networks"]),
    "routes_raw": run_command(["ip", "route", "show", "table", "main"]),
    "nmconnections": collect_nmconnections(),
    "daemon": collect_daemon_snapshot(),
  }


def append_log(log_path: Path, payload: dict):
  with log_path.open("a") as f:
    f.write(json.dumps(payload, sort_keys=True) + "\n")


def print_header(checkpoint: Checkpoint):
  print()
  print(f"[{checkpoint.checkpoint_id}] {checkpoint.title}")
  print(f"Goal: {checkpoint.goal}")
  print("Steps:")
  for step in checkpoint.steps:
    print(f"  - {step}")
  print("Pass criteria:")
  for item in checkpoint.pass_criteria:
    print(f"  - {item}")


def prompt(message: str, default: str | None = None) -> str:
  suffix = f" [{default}]" if default is not None else ""
  value = input(f"{message}{suffix}: ").strip()
  return value if value else (default or "")


def summarize_snapshot(snapshot: dict):
  daemon_state = snapshot.get("daemon", {})
  wpa_state = snapshot.get("wpa_status", {})
  keyfiles = [entry["name"] for entry in snapshot.get("nmconnections", [])]
  print("Snapshot summary:")
  print(f"  - daemon ssid/status: {daemon_state.get('wifi_state', {}).get('ssid')} / {daemon_state.get('wifi_state', {}).get('status')}")
  print(f"  - daemon ip: {daemon_state.get('ipv4_address')}")
  print(f"  - wpa ssid/state: {wpa_state.get('ssid')} / {wpa_state.get('wpa_state')}")
  print(f"  - wpa ip: {wpa_state.get('ip_address')}")
  print(f"  - saved profiles: {', '.join(keyfiles) if keyfiles else '<none>'}")


def run_checkpoint(checkpoint: Checkpoint, log_path: Path):
  print_header(checkpoint)
  input("Press Enter to capture the BEFORE snapshot...")
  before = collect_snapshot()
  summarize_snapshot(before)
  append_log(log_path, {
    "type": "before",
    "checkpoint": checkpoint.checkpoint_id,
    "snapshot": before,
  })

  input("Perform the manual steps, then press Enter to capture the AFTER snapshot...")
  after = collect_snapshot()
  summarize_snapshot(after)
  append_log(log_path, {
    "type": "after",
    "checkpoint": checkpoint.checkpoint_id,
    "snapshot": after,
  })

  while True:
    outcome = prompt("Outcome: pass / fail / skip / quit", "pass").lower()
    if outcome in {"pass", "fail", "skip"}:
      break
    if outcome == "quit":
      raise KeyboardInterrupt

  notes = prompt("Notes", "")
  append_log(log_path, {
    "type": "result",
    "checkpoint": checkpoint.checkpoint_id,
    "result": outcome,
    "notes": notes,
    "completed_at": datetime.now(UTC).isoformat(),
  })

  print(f"Recorded {checkpoint.checkpoint_id} as {outcome}.")


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Interactive WiFi checkpoint runner.")
  parser.add_argument(
    "--only",
    help="Comma-separated checkpoint ids to run. Use --list to see the available ids.",
  )
  parser.add_argument(
    "--list",
    action="store_true",
    help="List available checkpoint ids and exit.",
  )
  parser.add_argument(
    "--log",
    help="Path to a JSONL log file. Default: /tmp/wifi_test_checkpoints_<timestamp>.jsonl",
  )
  return parser.parse_args()


def main() -> int:
  args = parse_args()

  if args.list:
    for checkpoint in CHECKPOINTS:
      print(f"{checkpoint.checkpoint_id}: {checkpoint.title}")
    return 0

  if args.only:
    requested_ids = [item.strip() for item in args.only.split(",") if item.strip()]
    unknown_ids = [item for item in requested_ids if item not in CHECKPOINTS_BY_ID]
    if unknown_ids:
      print(f"Unknown checkpoint ids: {', '.join(unknown_ids)}", file=sys.stderr)
      return 2
    checkpoints = [CHECKPOINTS_BY_ID[item] for item in requested_ids]
  else:
    checkpoints = CHECKPOINTS

  if args.log:
    log_path = Path(args.log)
  else:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_path = Path(f"/tmp/wifi_test_checkpoints_{timestamp}.jsonl")

  print(f"Logging to {log_path}")
  append_log(log_path, {
    "type": "session_start",
    "started_at": datetime.now(UTC).isoformat(),
    "hostname": os.uname().nodename,
    "checkpoint_ids": [checkpoint.checkpoint_id for checkpoint in checkpoints],
  })

  try:
    for checkpoint in checkpoints:
      run_checkpoint(checkpoint, log_path)
  except KeyboardInterrupt:
    print("\nStopped early.")
    append_log(log_path, {
      "type": "session_stop",
      "stopped_at": datetime.now(UTC).isoformat(),
    })
    return 130

  append_log(log_path, {
    "type": "session_complete",
    "completed_at": datetime.now(UTC).isoformat(),
  })
  print(f"Done. Log saved to {log_path}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
