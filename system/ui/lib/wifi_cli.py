#!/usr/bin/env python3
"""CLI helper for testing WifiManager on-device.

Usage:
  python3 system/ui/lib/wifi_cli.py status          # show current state
  python3 system/ui/lib/wifi_cli.py scan             # scan and list networks
  python3 system/ui/lib/wifi_cli.py connect SSID PSK # connect to network
  python3 system/ui/lib/wifi_cli.py forget SSID      # forget a network
  python3 system/ui/lib/wifi_cli.py saved             # list saved networks
  python3 system/ui/lib/wifi_cli.py tethering on|off  # toggle tethering
  python3 system/ui/lib/wifi_cli.py monitor           # monitor events
"""
import sys
import time

from openpilot.system.ui.lib.wifi_manager import WifiManager
from openpilot.system.ui.lib.wpa_ctrl import WpaCtrl, WpaCtrlMonitor, parse_scan_results, parse_status, dbm_to_percent, flags_to_security_type


def cmd_status():
  ctrl = WpaCtrl()
  ctrl.open()
  status = parse_status(ctrl.request("STATUS"))
  ctrl.close()

  wpa_state = status.get("wpa_state", "UNKNOWN")
  ssid = status.get("ssid", "N/A")
  ip = status.get("ip_address", "N/A")
  bssid = status.get("bssid", "N/A")
  freq = status.get("freq", "?")
  key_mgmt = status.get("key_mgmt", "?")

  print(f"State:    {wpa_state}")
  print(f"SSID:     {ssid}")
  print(f"BSSID:    {bssid}")
  print(f"Freq:     {freq} MHz")
  print(f"Security: {key_mgmt}")
  print(f"IP:       {ip}")


def cmd_scan():
  ctrl = WpaCtrl()
  ctrl.open()
  ctrl.request("SCAN")
  print("Scanning...", flush=True)
  time.sleep(3)
  raw = ctrl.request("SCAN_RESULTS")
  ctrl.close()

  results = parse_scan_results(raw)

  # Group by SSID
  ssid_map: dict[str, list] = {}
  for r in results:
    if not r.ssid:
      continue
    ssid_map.setdefault(r.ssid, []).append(r)

  print(f"\n{'SSID':35s} {'Signal':>8s} {'Security':>12s} {'Freq':>6s} {'APs':>4s}")
  print("-" * 70)

  entries = []
  for ssid, aps in ssid_map.items():
    best = max(aps, key=lambda a: a.signal)
    pct = dbm_to_percent(best.signal)
    sec = flags_to_security_type(best.flags)
    entries.append((ssid, pct, sec, best.freq, len(aps)))

  for ssid, pct, sec, freq, n in sorted(entries, key=lambda e: -e[1]):
    print(f"{ssid:35s} {pct:5d}%   {sec.name:>12s} {freq:5d}  {n:4d}")

  print(f"\nTotal: {len(entries)} networks ({len(results)} APs)")


def cmd_connect(ssid, psk=""):
  print(f"Connecting to '{ssid}'...")
  wm = WifiManager()
  time.sleep(3)

  connected = [False]
  auth_failed = [False]

  def on_activated():
    connected[0] = True

  def on_need_auth(s):
    auth_failed[0] = True
    print(f"Authentication failed for '{s}'")

  wm.add_callbacks(activated=on_activated, need_auth=on_need_auth)
  wm.connect_to_network(ssid, psk)

  for _ in range(30):
    wm.process_callbacks()
    if connected[0]:
      print(f"Connected to '{ssid}'")
      print(f"IP: {wm.ipv4_address}")
      break
    if auth_failed[0]:
      break
    time.sleep(1)
  else:
    print("Timeout waiting for connection")

  wm.stop()


def cmd_forget(ssid):
  wm = WifiManager()
  time.sleep(3)

  done = [False]
  def on_forgotten(s):
    done[0] = True
    print(f"Forgot '{s}'")

  wm.add_callbacks(forgotten=on_forgotten)
  wm.forget_connection(ssid)

  for _ in range(5):
    wm.process_callbacks()
    if done[0]:
      break
    time.sleep(1)

  wm.stop()


def cmd_saved():
  from openpilot.system.ui.lib.wifi_manager import NetworkStore
  store = NetworkStore()
  networks = store.get_all()
  if not networks:
    print("No saved networks")
    return
  print(f"{'SSID':35s} {'PSK':>20s} {'Metered':>8s} {'Hidden':>7s}")
  print("-" * 75)
  for ssid, entry in networks.items():
    psk = entry.get("psk", "")
    psk_display = psk[:4] + "..." if len(psk) > 4 else psk if psk else "(none)"
    metered = entry.get("metered", 0)
    hidden = entry.get("hidden", False)
    print(f"{ssid:35s} {psk_display:>20s} {metered:>8d} {str(hidden):>7s}")


def cmd_tethering(state):
  wm = WifiManager()
  time.sleep(3)

  active = state.lower() in ("on", "true", "1")
  print(f"{'Starting' if active else 'Stopping'} tethering...")
  wm.set_tethering_active(active)
  time.sleep(10 if active else 5)

  print(f"Tethering active: {wm.is_tethering_active()}")
  print(f"State: {wm.wifi_state}")
  wm.stop()


def cmd_monitor():
  print("Monitoring wpa_supplicant events (Ctrl+C to stop)...")
  mon = WpaCtrlMonitor()
  mon.open()
  try:
    while True:
      event = mon.recv(timeout=1.0)
      if event:
        print(f"[{time.strftime('%H:%M:%S')}] {event}")
  except KeyboardInterrupt:
    print("\nStopped")
  finally:
    mon.close()


def main():
  if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

  cmd = sys.argv[1]

  if cmd == "status":
    cmd_status()
  elif cmd == "scan":
    cmd_scan()
  elif cmd == "connect":
    if len(sys.argv) < 3:
      print("Usage: wifi_cli.py connect SSID [PSK]")
      sys.exit(1)
    ssid = sys.argv[2]
    psk = sys.argv[3] if len(sys.argv) > 3 else ""
    cmd_connect(ssid, psk)
  elif cmd == "forget":
    if len(sys.argv) < 3:
      print("Usage: wifi_cli.py forget SSID")
      sys.exit(1)
    cmd_forget(sys.argv[2])
  elif cmd == "saved":
    cmd_saved()
  elif cmd == "tethering":
    if len(sys.argv) < 3:
      print("Usage: wifi_cli.py tethering on|off")
      sys.exit(1)
    cmd_tethering(sys.argv[2])
  elif cmd == "monitor":
    cmd_monitor()
  else:
    print(f"Unknown command: {cmd}")
    print(__doc__)
    sys.exit(1)


if __name__ == "__main__":
  main()
