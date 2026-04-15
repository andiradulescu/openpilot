"""wpa_supplicant control socket wrapper and parsing helpers."""
import os
import socket
import select
import threading
from dataclasses import dataclass
from enum import IntEnum


RECV_BUF_SIZE = 32768


class SecurityType(IntEnum):
  OPEN = 0
  WPA = 1
  UNSUPPORTED = 2


@dataclass(frozen=True)
class ScanResult:
  bssid: str
  freq: int
  signal: int  # dBm
  flags: str
  ssid: str


class _WpaCtrlBase:
  """Shared socket lifecycle for wpa_supplicant control connections."""

  _counter = 0
  _counter_lock = threading.Lock()

  def __init__(self, ctrl_path: str = "/var/run/wpa_supplicant/wlan0"):
    self._ctrl_path = ctrl_path
    self._sock: socket.socket | None = None
    self._local_path: str = ""

  def _open_socket(self, prefix: str):
    with _WpaCtrlBase._counter_lock:
      _WpaCtrlBase._counter += 1
      idx = _WpaCtrlBase._counter
    self._local_path = f"/tmp/{prefix}_{os.getpid()}_{idx}"
    try:
      os.unlink(self._local_path)
    except OSError:
      pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
      sock.bind(self._local_path)
      sock.connect(self._ctrl_path)
    except Exception:
      sock.close()
      try:
        os.unlink(self._local_path)
      except OSError:
        pass
      self._local_path = ""
      raise
    self._sock = sock

  def _ensure_sock(self) -> socket.socket:
    if self._sock is None:
      raise RuntimeError("not opened")
    return self._sock

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

  def __enter__(self):
    self.open()
    return self

  def __exit__(self, *_):
    self.close()

  def __del__(self):
    self.close()


class WpaCtrl(_WpaCtrlBase):
  """Synchronous command/response wrapper for wpa_supplicant control socket."""

  def __init__(self, ctrl_path: str = "/var/run/wpa_supplicant/wlan0"):
    super().__init__(ctrl_path)
    self._request_lock = threading.Lock()

  def open(self):
    self._open_socket("wpa_ctrl")
    self._sock.settimeout(10)

  def request(self, cmd: str) -> str:
    """Send command, return response string."""
    with self._request_lock:
      sock = self._ensure_sock()
      sock.send(cmd.encode())
      return sock.recv(RECV_BUF_SIZE).decode("utf-8", "replace")

  def close(self):
    # Serialize against request() so a concurrent caller can't be mid-send/
    # recv while we close the underlying fd. Without this, the other thread
    # observes a closed socket and raises OSError (EBADF); callers swallow
    # that today, but the cleaner contract is "close waits for in-flight
    # requests to drain".
    with self._request_lock:
      super().close()


class WpaCtrlMonitor(_WpaCtrlBase):
  """Async event stream from wpa_supplicant (ATTACH/DETACH protocol)."""

  def open(self):
    self._open_socket("wpa_mon")
    self._sock.settimeout(10)
    resp = self._raw_request("ATTACH")
    if not resp.startswith("OK"):
      self.close()
      raise RuntimeError(f"ATTACH failed: {resp}")

  def _raw_request(self, cmd: str) -> str:
    sock = self._ensure_sock()
    sock.send(cmd.encode())
    return sock.recv(RECV_BUF_SIZE).decode("utf-8", "replace")

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
    data = self._sock.recv(RECV_BUF_SIZE).decode("utf-8", "replace")
    # Strip priority prefix like <3>
    if data.startswith("<") and ">" in data[:4]:
      data = data[data.index(">") + 1:]
    return data

  def close(self):
    if self._sock is not None:
      try:
        self._raw_request("DETACH")
      except (OSError, RuntimeError):
        pass
    super().close()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_HEX = "0123456789abcdefABCDEF"


def decode_ssid(encoded: str) -> str:
  """Decode a wpa_supplicant printf_encode'd SSID (hostap common.c:526).

  This branch talks to wpa_supplicant over the text control socket (no
  D-Bus), so SSIDs arrive with escapes: `\\\\`, `\\"`, `\\e/n/r/t`,
  `\\xNN`/`\\xN`, octal `\\0..\\777`. Unknown escapes drop the
  backslash, trailing `\\` is dropped.

  Byte stream is reinterpreted as UTF-8 (errors="replace"), not
  one-codepoint-per-byte: a `\\xc3\\xa9` AP ("é") decoded as Latin-1
  becomes "Ã©", which re-encodes to 7 bytes on SET_NETWORK and can't
  match the 5-byte AP. All-null SSIDs (hidden APs) normalize to "" so
  the wifi_manager empty-SSID filter drops them.
  """
  out = bytearray()
  i = 0
  n = len(encoded)
  while i < n:
    c = encoded[i]
    if c != "\\":
      out.append(ord(c) & 0xff)
      i += 1
      continue

    i += 1  # consume backslash
    if i >= n:
      break  # trailing backslash: dropped

    nxt = encoded[i]
    if nxt == "\\":
      out.append(ord("\\"))
      i += 1
    elif nxt == '"':
      out.append(ord('"'))
      i += 1
    elif nxt == "n":
      out.append(ord("\n"))
      i += 1
    elif nxt == "r":
      out.append(ord("\r"))
      i += 1
    elif nxt == "t":
      out.append(ord("\t"))
      i += 1
    elif nxt == "e":
      out.append(0x1b)
      i += 1
    elif nxt == "x":
      i += 1  # consume 'x'
      if i + 1 < n and encoded[i] in _HEX and encoded[i + 1] in _HEX:
        out.append(int(encoded[i:i + 2], 16))
        i += 2
      elif i < n and encoded[i] in _HEX:
        out.append(int(encoded[i], 16))
        i += 1
      # else: malformed \x — drop the escape, continue parsing at i
    elif "0" <= nxt <= "7":
      val = ord(nxt) - ord("0")
      i += 1
      if i < n and "0" <= encoded[i] <= "7":
        val = val * 8 + (ord(encoded[i]) - ord("0"))
        i += 1
        if i < n and "0" <= encoded[i] <= "7":
          val = val * 8 + (ord(encoded[i]) - ord("0"))
          i += 1
      out.append(val & 0xff)
    # else: unknown escape — the backslash is consumed, the char falls
    # through to the next iteration and is appended as a literal.

  if not out or all(b == 0 for b in out):
    return ""
  return out.decode("utf-8", errors="replace")


def parse_scan_results(raw: str) -> list[ScanResult]:
  """Parse wpa_supplicant SCAN_RESULTS output (tab-separated, first line is header)."""
  results = []
  lines = raw.strip().split("\n")
  if len(lines) < 2:
    return results
  for line in lines[1:]:
    parts = line.split("\t")
    if len(parts) < 4:
      continue
    try:
      results.append(ScanResult(
        bssid=parts[0],
        freq=int(parts[1]),
        signal=int(parts[2]),
        flags=parts[3],
        ssid=decode_ssid(parts[4]) if len(parts) > 4 else "",
      ))
    except (ValueError, IndexError):
      continue
  return results


def flags_to_security_type(flags: str) -> SecurityType:
  """Convert wpa_supplicant flags string to SecurityType.

  Examples: [WPA2-PSK-CCMP][WPA-PSK-CCMP], [ESS], [WPA2-PSK-CCMP+TKIP]
  """
  flags_upper = flags.upper()

  # Enterprise / 802.1X / WEP → unsupported
  if "EAP" in flags_upper or "802.1X" in flags_upper:
    return SecurityType.UNSUPPORTED
  if "WEP" in flags_upper:
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
  """Parse wpa_supplicant STATUS output (key=value lines).

  The `ssid` field is emitted via `wpa_ssid_txt()` (printf_encode'd), so
  decode it here; every caller gets a raw, usable SSID.
  """
  result = {}
  for line in raw.strip().split("\n"):
    if "=" in line:
      key, _, value = line.partition("=")
      if key == "ssid":
        value = decode_ssid(value)
      result[key] = value
  return result


def dbm_to_percent(dbm: int) -> int:
  """Convert dBm to percentage [0, 100], matching NetworkManager's scale."""
  return max(0, min(100, 2 * (dbm + 100)))
