import os
import re
import select
import socket
import threading
from dataclasses import dataclass
from enum import IntEnum


RECV_BUF_SIZE = 32768
WPA_CTRL_PATH = "/run/openpilot-wpa/wlan0"
IEEE80211_MAX_SSID_BYTES = 32

_HEX = "0123456789abcdefABCDEF"
_EVENT_ID_RE = re.compile(r"\bid=(\d+)\b")
_EVENT_SSID_RE = re.compile(r'\bssid="((?:\\.|[^"])*)"')


class SecurityType(IntEnum):
  OPEN = 0
  WPA = 1
  UNSUPPORTED = 2


@dataclass(frozen=True)
class ScanResult:
  bssid: str
  freq: int
  signal: int
  flags: str
  ssid: str


def decode_ssid(encoded: str) -> str:
  out = bytearray()
  i = 0
  while i < len(encoded):
    char = encoded[i]
    if char != "\\":
      out.append(ord(char) & 0xff)
      i += 1
      continue

    i += 1
    if i >= len(encoded):
      break

    escaped = encoded[i]
    if escaped == "\\":
      out.append(ord("\\"))
      i += 1
    elif escaped == '"':
      out.append(ord('"'))
      i += 1
    elif escaped == "n":
      out.append(ord("\n"))
      i += 1
    elif escaped == "r":
      out.append(ord("\r"))
      i += 1
    elif escaped == "t":
      out.append(ord("\t"))
      i += 1
    elif escaped == "e":
      out.append(0x1b)
      i += 1
    elif escaped == "x":
      i += 1
      if i + 1 < len(encoded) and encoded[i] in _HEX and encoded[i + 1] in _HEX:
        out.append(int(encoded[i:i + 2], 16))
        i += 2
      elif i < len(encoded) and encoded[i] in _HEX:
        out.append(int(encoded[i], 16))
        i += 1
    elif "0" <= escaped <= "7":
      value = ord(escaped) - ord("0")
      i += 1
      for _ in range(2):
        if i >= len(encoded) or not "0" <= encoded[i] <= "7":
          break
        value = value * 8 + ord(encoded[i]) - ord("0")
        i += 1
      out.append(value & 0xff)

  if not out or all(byte == 0 for byte in out):
    return ""
  return out.decode("utf-8", errors="surrogateescape")


def normalize_ssid(ssid: str) -> str:
  display_ssid = ssid.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")
  return display_ssid.replace("’", "'")


def parse_scan_results(raw: str) -> list[ScanResult]:
  results = []
  lines = raw.splitlines()
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
    except ValueError:
      continue
  return results


def flags_to_security_type(flags: str) -> SecurityType:
  flags_upper = flags.upper()
  groups = re.findall(r"\[([^\]]+)\]", flags_upper)

  if "WEP" in flags_upper:
    return SecurityType.UNSUPPORTED
  if any(re.search(r"(?:^|\+)(?:(?:WPA2|RSN|WPA)-)?PSK(?!-SHA256)(?:[-+]|$)", group) for group in groups):
    return SecurityType.WPA
  if any(mode in flags_upper for mode in ("EAP", "802.1X", "SAE", "OWE", "DPP", "OSEN", "FILS")):  # codespell:ignore fils
    return SecurityType.UNSUPPORTED
  if "WPA" not in flags_upper and "RSN" not in flags_upper:
    return SecurityType.OPEN
  return SecurityType.UNSUPPORTED


def parse_status(raw: str) -> dict[str, str]:
  status = {}
  for line in raw.strip().split("\n"):
    if "=" not in line:
      continue
    key, _, value = line.partition("=")
    status[key] = decode_ssid(value) if key == "ssid" else value
  return status


def parse_event_network_id(event: str) -> str | None:
  match = _EVENT_ID_RE.search(event)
  return match.group(1) if match is not None else None


def parse_event_ssid(event: str) -> str | None:
  match = _EVENT_SSID_RE.search(event)
  return decode_ssid(match.group(1)) if match is not None else None


def dbm_to_percent(dbm: int) -> int:
  value = abs(max(-100, min(-40, dbm)) + 40)
  return 100 - (100 * value) // 60


def is_valid_ssid(ssid: str) -> bool:
  try:
    return 0 < len(ssid.encode("utf-8", errors="surrogateescape")) <= IEEE80211_MAX_SSID_BYTES
  except UnicodeEncodeError:
    return False


class _WpaCtrlSocket:
  _counter = 0
  _counter_lock = threading.Lock()

  def __init__(self, ctrl_path: str = WPA_CTRL_PATH):
    self._ctrl_path = ctrl_path
    self._sock: socket.socket | None = None
    self._local_path = ""

  def _open(self, prefix: str, timeout: float | None = None):
    with self._counter_lock:
      type(self)._counter += 1
      idx = type(self)._counter

    self._local_path = f"/tmp/{prefix}_{os.getpid()}_{idx}"
    try:
      os.unlink(self._local_path)
    except OSError:
      pass

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
      sock.bind(self._local_path)
      sock.connect(self._ctrl_path)
      sock.settimeout(timeout)
    except Exception:
      sock.close()
      self._unlink()
      raise
    self._sock = sock

  def _unlink(self):
    if not self._local_path:
      return
    try:
      os.unlink(self._local_path)
    except OSError:
      pass
    self._local_path = ""

  def close(self):
    if self._sock is not None:
      try:
        self._sock.close()
      except OSError:
        pass
      self._sock = None
    self._unlink()

  def interrupt(self):
    if self._sock is not None:
      try:
        self._sock.shutdown(socket.SHUT_RDWR)
      except OSError:
        pass

  def _request(self, command: str) -> str:
    if self._sock is None:
      raise RuntimeError("not opened")
    self._sock.send(command.encode())
    return self._sock.recv(RECV_BUF_SIZE).decode("utf-8", "replace")


class WpaCtrl(_WpaCtrlSocket):
  def __init__(self, ctrl_path: str = WPA_CTRL_PATH):
    super().__init__(ctrl_path)
    self._lock = threading.Lock()

  def open(self):
    self._open("wpa_ctrl", 2.0)

  def request(self, command: str) -> str:
    with self._lock:
      return self._request(command)

  def close(self):
    with self._lock:
      super().close()


class WpaCtrlMonitor(_WpaCtrlSocket):
  def open(self):
    self._open("wpa_mon", 2.0)
    if not self._request("ATTACH").startswith("OK"):
      self.close()
      raise RuntimeError("ATTACH failed")
    assert self._sock is not None
    self._sock.settimeout(None)

  def recv(self, timeout: float = 1.0) -> str | None:
    if self._sock is None:
      return None
    readable, _, _ = select.select([self._sock], [], [], timeout)
    if not readable:
      return None
    data = self._sock.recv(RECV_BUF_SIZE).decode("utf-8", "replace")
    if data.startswith("<") and ">" in data[:4]:
      data = data[data.index(">") + 1:]
    return data

  def close(self):
    if self._sock is not None:
      try:
        self._sock.settimeout(2.0)
        self._request("DETACH")
      except (OSError, RuntimeError):
        pass
    super().close()
