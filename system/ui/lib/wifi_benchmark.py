#!/usr/bin/env python3
"""Benchmark WiFi operations: wpa_supplicant (direct) vs NetworkManager.

Measures wall-clock time for real user-visible outcomes:
  - Scan:       command issued → fresh results available
  - Connect:    command issued → IP address assigned on wlan0
  - Disconnect: command issued → wpa_state no longer COMPLETED + IP gone

Usage (on device):
  # Run backends separately for clean measurement:
  # 1. NM benchmark (while NM manages wlan0):
  python3 wifi_benchmark.py --backend nm --ssid SSID --psk PSK -n 5

  # 2. WPA benchmark (after: nmcli device set wlan0 managed no + restart wpa_supplicant standalone):
  python3 wifi_benchmark.py --backend wpa --ssid SSID --psk PSK -n 5
"""
import argparse
import json
import math
import os
import subprocess
import time


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_wlan0_ip() -> str:
  """Get IPv4 address of wlan0, empty string if none."""
  try:
    out = subprocess.check_output(
      ["ip", "-4", "-o", "addr", "show", "wlan0"],
      timeout=2, stderr=subprocess.DEVNULL
    ).decode().strip()
    if out:
      for part in out.split():
        if "/" in part and "." in part:
          return part.split("/")[0]
  except Exception:
    pass
  return ""


def wait_for_ip(timeout: float = 30.0, poll: float = 0.1) -> tuple[bool, float]:
  """Wait until wlan0 has an IP. Returns (success, elapsed_seconds)."""
  t0 = time.monotonic()
  while time.monotonic() - t0 < timeout:
    if get_wlan0_ip():
      return True, time.monotonic() - t0
    time.sleep(poll)
  return False, time.monotonic() - t0


def wait_for_no_ip(timeout: float = 15.0, poll: float = 0.1) -> tuple[bool, float]:
  """Wait until wlan0 has no IP. Returns (success, elapsed_seconds)."""
  t0 = time.monotonic()
  while time.monotonic() - t0 < timeout:
    if not get_wlan0_ip():
      return True, time.monotonic() - t0
    time.sleep(poll)
  return False, time.monotonic() - t0


def run_cmd(cmd: list[str], timeout: float = 30.0) -> str:
  return subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL).decode().strip()


def stats(times: list[float]) -> dict:
  n = len(times)
  if n == 0:
    return {"n": 0, "min": 0, "max": 0, "avg": 0, "std": 0}
  avg = sum(times) / n
  variance = sum((t - avg) ** 2 for t in times) / n if n > 1 else 0
  return {
    "n": n,
    "min": round(min(times), 2),
    "max": round(max(times), 2),
    "avg": round(avg, 2),
    "std": round(math.sqrt(variance), 2),
  }


# ---------------------------------------------------------------------------
# wpa_supplicant backend
# ---------------------------------------------------------------------------

class WpaBenchmark:
  """Benchmark using wpa_cli commands directly."""

  def __init__(self, ssid: str, psk: str):
    self.ssid = ssid
    self.psk = psk

  def _wpa_cli(self, *args) -> str:
    return run_cmd(["wpa_cli", "-i", "wlan0", *args])

  def _wpa_state(self) -> str:
    status = self._wpa_cli("status")
    for line in status.split("\n"):
      if line.startswith("wpa_state="):
        return line.split("=", 1)[1]
    return "UNKNOWN"

  def _ensure_fully_disconnected(self):
    """Disconnect, flush IP, verify wpa_state is not COMPLETED."""
    self._wpa_cli("disconnect")
    subprocess.run(["killall", "-q", "udhcpc"], timeout=5,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "flush", "dev", "wlan0"], timeout=5,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # Wait for wpa_state to leave COMPLETED
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
      state = self._wpa_state()
      if state != "COMPLETED":
        break
      time.sleep(0.1)

    wait_for_no_ip(timeout=5.0)
    # Extra settle time to ensure clean state
    time.sleep(0.5)

    # Verify
    state = self._wpa_state()
    if state == "COMPLETED":
      raise RuntimeError(f"Failed to disconnect (wpa_state={state})")

  def _ensure_network_configured(self) -> str:
    """Make sure our SSID is configured in wpa_supplicant, return network id."""
    networks = self._wpa_cli("list_networks")
    for line in networks.split("\n")[1:]:
      parts = line.split("\t")
      if len(parts) >= 2 and parts[1] == self.ssid:
        return parts[0]

    net_id = self._wpa_cli("add_network").strip()
    self._wpa_cli("set_network", net_id, "ssid", f'"{self.ssid}"')
    self._wpa_cli("set_network", net_id, "psk", f'"{self.psk}"')
    return net_id

  def scan(self) -> float:
    """Time from SCAN command to fresh results available.

    Snapshots existing results, issues SCAN, polls until results change.
    """
    old_results = self._wpa_cli("scan_results")

    t0 = time.monotonic()
    self._wpa_cli("scan")

    deadline = t0 + 15.0
    while time.monotonic() < deadline:
      new_results = self._wpa_cli("scan_results")
      if new_results != old_results:
        return time.monotonic() - t0
      time.sleep(0.1)

    raise TimeoutError("scan_results never changed")

  def connect(self) -> float:
    """Time from SELECT_NETWORK to having an IP on wlan0.

    Includes WPA handshake + DHCP. Fair comparison with NM which also
    includes both in its connect time.
    """
    self._ensure_fully_disconnected()
    net_id = self._ensure_network_configured()

    t0 = time.monotonic()
    self._wpa_cli("select_network", net_id)

    # Wait for wpa_state=COMPLETED (WPA handshake done)
    deadline = t0 + 30.0
    while time.monotonic() < deadline:
      if self._wpa_state() == "COMPLETED":
        break
      time.sleep(0.1)
    else:
      raise TimeoutError("wpa_state never reached COMPLETED")

    # Start DHCP and wait for IP (this is what the user actually waits for)
    dhcp = subprocess.Popen(
      ["udhcpc", "-i", "wlan0", "-f", "-q", "-t", "5", "-n"],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    ok, _ = wait_for_ip(timeout=15.0)
    try:
      dhcp.wait(timeout=1)
    except subprocess.TimeoutExpired:
      dhcp.kill()

    if not ok:
      raise TimeoutError("never got IP after connect")

    return time.monotonic() - t0

  def disconnect(self) -> float:
    """Time from DISCONNECT to wpa_state leaving COMPLETED + IP gone."""
    if self._wpa_state() != "COMPLETED":
      raise RuntimeError("not connected, can't benchmark disconnect")

    t0 = time.monotonic()
    self._wpa_cli("disconnect")
    subprocess.run(["killall", "-q", "udhcpc"], timeout=5,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "flush", "dev", "wlan0"], timeout=5,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # Wait for both: wpa_state != COMPLETED AND no IP
    deadline = t0 + 10.0
    while time.monotonic() < deadline:
      state = self._wpa_state()
      ip = get_wlan0_ip()
      if state != "COMPLETED" and not ip:
        return time.monotonic() - t0
      time.sleep(0.05)

    raise TimeoutError("disconnect didn't complete")

  def cleanup(self):
    self._wpa_cli("enable_network", "all")
    self._wpa_cli("reassociate")


# ---------------------------------------------------------------------------
# NetworkManager backend
# ---------------------------------------------------------------------------

class NmBenchmark:
  """Benchmark using nmcli commands."""

  def __init__(self, ssid: str, psk: str):
    self.ssid = ssid
    self.psk = psk

  def _ensure_disconnected(self):
    subprocess.run(
      ["nmcli", "device", "disconnect", "wlan0"],
      timeout=15, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
    )
    wait_for_no_ip(timeout=10.0)
    time.sleep(0.5)

  def scan(self) -> float:
    """Time for nmcli to perform a fresh scan and return results.

    Uses --rescan yes to force a real scan, not cached results.
    """
    t0 = time.monotonic()
    # --rescan yes forces NM to trigger a new scan and wait for it
    subprocess.check_output(
      ["nmcli", "-t", "device", "wifi", "list", "--rescan", "yes"],
      timeout=30, stderr=subprocess.DEVNULL
    )
    return time.monotonic() - t0

  def connect(self) -> float:
    """Time from nmcli connect to having an IP on wlan0.

    nmcli connection up blocks until connected+DHCP complete.
    """
    self._ensure_disconnected()

    t0 = time.monotonic()
    result = subprocess.run(
      ["nmcli", "connection", "up", self.ssid],
      timeout=60, capture_output=True
    )
    if result.returncode != 0:
      subprocess.check_call(
        ["nmcli", "device", "wifi", "connect", self.ssid, "password", self.psk],
        timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
      )

    ok, _ = wait_for_ip(timeout=15.0)
    if not ok:
      raise TimeoutError("never got IP after nmcli connect")

    return time.monotonic() - t0

  def disconnect(self) -> float:
    """Time from nmcli disconnect to IP being gone."""
    ip = get_wlan0_ip()
    if not ip:
      raise RuntimeError("not connected, can't benchmark disconnect")

    t0 = time.monotonic()
    subprocess.run(
      ["nmcli", "device", "disconnect", "wlan0"],
      timeout=30, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
    )

    ok, _ = wait_for_no_ip(timeout=10.0)
    if not ok:
      raise TimeoutError("IP never went away after disconnect")

    return time.monotonic() - t0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_benchmark(bench, iterations: int, label: str) -> dict:
  results = {"scan": [], "connect": [], "disconnect": []}

  print(f"\n{'=' * 60}")
  print(f"  Benchmarking: {label} ({iterations} iterations)")
  print(f"{'=' * 60}")

  print("\n  Scan:")
  for i in range(iterations):
    try:
      t = bench.scan()
      results["scan"].append(t)
      print(f"    [{i+1}/{iterations}] {t:.2f}s")
    except Exception as e:
      print(f"    [{i+1}/{iterations}] FAILED: {e}")
    time.sleep(1)

  print("\n  Connect → Disconnect:")
  for i in range(iterations):
    try:
      t = bench.connect()
      results["connect"].append(t)
      print(f"    [{i+1}/{iterations}] connect: {t:.2f}s", end="")
    except Exception as e:
      print(f"    [{i+1}/{iterations}] connect FAILED: {e}")
      continue

    time.sleep(1)

    try:
      t = bench.disconnect()
      results["disconnect"].append(t)
      print(f"  disconnect: {t:.2f}s")
    except Exception as e:
      print(f"  disconnect FAILED: {e}")

    time.sleep(1)

  if hasattr(bench, 'cleanup'):
    bench.cleanup()

  return results


def print_comparison(wpa_results: dict | None, nm_results: dict | None):
  print(f"\n{'=' * 60}")
  print("  RESULTS")
  print(f"{'=' * 60}")

  operations = ["scan", "connect", "disconnect"]
  header = f"\n{'Operation':15s}"
  if wpa_results:
    header += f"  {'wpa_supplicant':>28s}"
  if nm_results:
    header += f"  {'NetworkManager':>28s}"
  if wpa_results and nm_results:
    header += f"  {'Ratio':>7s}"
  print(header)
  print("-" * len(header))

  for op in operations:
    line = f"{op:15s}"
    ws = stats(wpa_results[op]) if wpa_results else None
    ns = stats(nm_results[op]) if nm_results else None

    if ws and ws["n"] > 0:
      line += f"  {ws['avg']:5.2f}s ±{ws['std']:.2f} [{ws['min']:.2f}-{ws['max']:.2f}]"
    elif ws:
      line += f"  {'N/A':>28s}"

    if ns and ns["n"] > 0:
      line += f"  {ns['avg']:5.2f}s ±{ns['std']:.2f} [{ns['min']:.2f}-{ns['max']:.2f}]"
    elif ns:
      line += f"  {'N/A':>28s}"

    if ws and ns and ws["n"] > 0 and ns["n"] > 0:
      ratio = ns["avg"] / ws["avg"] if ws["avg"] > 0 else float("inf")
      line += f"  {ratio:5.1f}x"

    print(line)

  print("\n--- Raw data (JSON) ---")
  raw = {}
  if wpa_results:
    raw["wpa_supplicant"] = wpa_results
  if nm_results:
    raw["networkmanager"] = nm_results
  print(json.dumps(raw, indent=2))


def main():
  parser = argparse.ArgumentParser(description="Benchmark WiFi operations")
  parser.add_argument("--backend", choices=["wpa", "nm", "both"], default="both")
  parser.add_argument("--ssid", required=True)
  parser.add_argument("--psk", required=True)
  parser.add_argument("--iterations", "-n", type=int, default=5)
  args = parser.parse_args()

  if os.geteuid() != 0:
    print("WARNING: not running as root, some operations may fail")

  print(f"SSID: {args.ssid}, Iterations: {args.iterations}")
  print(f"Backend: {args.backend}")

  wpa_results = None
  nm_results = None

  if args.backend in ("wpa", "both"):
    bench = WpaBenchmark(args.ssid, args.psk)
    wpa_results = run_benchmark(bench, args.iterations, "wpa_supplicant (direct)")

  if args.backend in ("nm", "both"):
    bench = NmBenchmark(args.ssid, args.psk)
    nm_results = run_benchmark(bench, args.iterations, "NetworkManager (nmcli)")

  if args.backend == "wpa":
    print("\nRe-enabling networks in wpa_supplicant...")
    subprocess.run(["wpa_cli", "-i", "wlan0", "enable_network", "all"],
                   timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["wpa_cli", "-i", "wlan0", "reassociate"],
                   timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  print_comparison(wpa_results, nm_results)


if __name__ == "__main__":
  main()
