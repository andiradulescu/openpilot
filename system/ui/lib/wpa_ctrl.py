"""wpa_supplicant control socket wrapper and parsing helpers."""
import os
import socket
import select
from dataclasses import dataclass
from enum import IntEnum


class SecurityType(IntEnum):
  OPEN = 0
  WPA = 1
  WPA2 = 2
  WPA3 = 3
  UNSUPPORTED = 4


@dataclass(frozen=True)
class ScanResult:
  bssid: str
  freq: int
  signal: int  # dBm
  flags: str
  ssid: str


class WpaCtrl:
  """Synchronous command/response wrapper for wpa_supplicant control socket."""

  _counter = 0

  def __init__(self, ctrl_path: str = "/var/run/wpa_supplicant/wlan0"):
    self._ctrl_path = ctrl_path
    self._sock: socket.socket | None = None
    self._local_path: str = ""

  def open(self):
    WpaCtrl._counter += 1
    self._local_path = f"/tmp/wpa_ctrl_{os.getpid()}_{WpaCtrl._counter}"
    try:
      os.unlink(self._local_path)
    except OSError:
      pass
    self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    self._sock.bind(self._local_path)
    self._sock.connect(self._ctrl_path)
    self._sock.settimeout(10)

  def close(self):
    if self._sock is not None:
      try:
        self._sock.close()
      except OSError:
        pass
      self._sock = None
    if self._local_path:
      try:
        os.unlink(self._local_path)
      except OSError:
        pass
      self._local_path = ""

  def request(self, cmd: str) -> str:
    """Send command, return response string."""
    assert self._sock is not None, "WpaCtrl not opened"
    self._sock.send(cmd.encode())
    return self._sock.recv(4096).decode("utf-8", "replace")

  def __enter__(self):
    self.open()
    return self

  def __exit__(self, *_):
    self.close()

  def __del__(self):
    self.close()


class WpaCtrlMonitor:
  """Async event stream from wpa_supplicant (ATTACH/DETACH protocol)."""

  _counter = 0

  def __init__(self, ctrl_path: str = "/var/run/wpa_supplicant/wlan0"):
    self._ctrl_path = ctrl_path
    self._sock: socket.socket | None = None
    self._local_path: str = ""

  def open(self):
    WpaCtrlMonitor._counter += 1
    self._local_path = f"/tmp/wpa_mon_{os.getpid()}_{WpaCtrlMonitor._counter}"
    try:
      os.unlink(self._local_path)
    except OSError:
      pass
    self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    self._sock.bind(self._local_path)
    self._sock.connect(self._ctrl_path)
    self._sock.settimeout(10)
    resp = self._raw_request("ATTACH")
    if not resp.startswith("OK"):
      raise RuntimeError(f"ATTACH failed: {resp}")

  def _raw_request(self, cmd: str) -> str:
    assert self._sock is not None
    self._sock.send(cmd.encode())
    return self._sock.recv(4096).decode("utf-8", "replace")

  def pending(self, timeout: float = 0) -> bool:
    if self._sock is None:
      return False
    r, _, _ = select.select([self._sock], [], [], timeout)
    return len(r) > 0

  def recv(self, timeout: float = 1.0) -> str | None:
    if self._sock is None:
      return None
    r, _, _ = select.select([self._sock], [], [], timeout)
    if not r:
      return None
    data = self._sock.recv(4096).decode("utf-8", "replace")
    # Strip priority prefix like <3>
    if data.startswith("<") and ">" in data[:4]:
      data = data[data.index(">") + 1:]
    return data

  def close(self):
    if self._sock is not None:
      try:
        self._raw_request("DETACH")
      except OSError:
        pass
      try:
        self._sock.close()
      except OSError:
        pass
      self._sock = None
    if self._local_path:
      try:
        os.unlink(self._local_path)
      except OSError:
        pass
      self._local_path = ""

  def __enter__(self):
    self.open()
    return self

  def __exit__(self, *_):
    self.close()

  def __del__(self):
    self.close()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_scan_results(raw: str) -> list[ScanResult]:
  """Parse wpa_supplicant SCAN_RESULTS output (tab-separated, first line is header)."""
  results = []
  lines = raw.strip().split("\n")
  if len(lines) < 2:
    return results
  for line in lines[1:]:
    parts = line.split("\t")
    if len(parts) < 5:
      continue
    try:
      results.append(ScanResult(
        bssid=parts[0],
        freq=int(parts[1]),
        signal=int(parts[2]),
        flags=parts[3],
        ssid=parts[4] if len(parts) > 4 else "",
      ))
    except (ValueError, IndexError):
      continue
  return results


def flags_to_security_type(flags: str) -> SecurityType:
  """Convert wpa_supplicant flags string to SecurityType.

  Examples: [WPA2-PSK-CCMP][WPA-PSK-CCMP], [ESS], [WPA2-PSK-CCMP+TKIP]
  """
  flags_upper = flags.upper()

  # Enterprise / 802.1X → unsupported
  if "EAP" in flags_upper or "802.1X" in flags_upper:
    return SecurityType.UNSUPPORTED

  if "WPA2-PSK" in flags_upper or "RSN-PSK" in flags_upper:
    return SecurityType.WPA
  if "WPA-PSK" in flags_upper:
    return SecurityType.WPA
  if "SAE" in flags_upper:
    return SecurityType.WPA  # WPA3-SAE, treat as WPA for connection purposes

  # No security flags → open
  if "WPA" not in flags_upper and "RSN" not in flags_upper and "SAE" not in flags_upper:
    return SecurityType.OPEN

  return SecurityType.UNSUPPORTED


def parse_status(raw: str) -> dict[str, str]:
  """Parse wpa_supplicant STATUS output (key=value lines)."""
  result = {}
  for line in raw.strip().split("\n"):
    if "=" in line:
      key, _, value = line.partition("=")
      result[key] = value
  return result


def dbm_to_percent(dbm: int) -> int:
  """Convert dBm to percentage [0, 100], matching NetworkManager's scale."""
  return max(0, min(100, 2 * (dbm + 100)))
