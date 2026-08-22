import configparser
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, replace
from enum import IntEnum
from pathlib import Path

from openpilot.common.utils import sudo_read
from openpilot.system.ui.lib.wpa_ctrl import SecurityType, is_valid_ssid
from openpilot.system.ui.lib.wpa_supplicant import WpaNetwork


NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"
RUNTIME_CONNECTIONS_DIR = "/run/NetworkManager/system-connections"


class MeteredType(IntEnum):
  UNKNOWN = 0
  YES = 1
  NO = 2


@dataclass(frozen=True)
class NetworkProfile:
  uuid: str
  ssid: str
  security: SecurityType
  psk: str = ""
  hidden: bool = False
  priority: int = 0
  bssid: str = ""
  metered: MeteredType = MeteredType.UNKNOWN
  ipv6_enabled: bool = True
  path: str = ""
  persistent: bool = True

  def as_wpa_network(self) -> WpaNetwork:
    return WpaNetwork(
      ssid=self.ssid,
      security=self.security,
      psk=self.psk,
      hidden=self.hidden,
      profile_uuid=self.uuid,
      priority=self.priority,
      bssid=self.bssid,
    )


def _parse_uuid(value: str) -> str | None:
  try:
    return str(uuid.UUID(value))
  except ValueError:
    return None


def _decode_keyfile_string(value: str) -> str:
  escapes = {"s": " ", "n": "\n", "r": "\r", "t": "\t", "\\": "\\", ";": ";"}
  out = []
  i = 0
  while i < len(value):
    if value[i] == "\\" and i + 1 < len(value) and value[i + 1] in escapes:
      out.append(escapes[value[i + 1]])
      i += 2
    else:
      out.append(value[i])
      i += 1
  return "".join(out)


def _decode_ssid(value: str) -> str:
  if re.fullmatch(r"(?:[0-9]{1,3};)+", value):
    parts = [int(part) for part in value[:-1].split(";")]
    if parts and all(part <= 255 for part in parts):
      return bytes(parts).decode("utf-8", errors="surrogateescape")
  return _decode_keyfile_string(value)


def _encode_ssid(value: str) -> str:
  return ";".join(str(byte) for byte in value.encode("utf-8", errors="surrogateescape")) + ";"


def _encode_keyfile_string(value: str) -> str:
  out = []
  for char in value:
    out.append({"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(char, char))
  return "".join(out)


def _section(cp: configparser.ConfigParser, *names: str) -> str | None:
  return next((name for name in names if cp.has_section(name)), None)


def _valid_psk(psk: str) -> bool:
  try:
    size = len(psk.encode("utf-8"))
  except UnicodeEncodeError:
    return False
  return 8 <= size <= 63 or len(psk) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk)


def parse_profile(raw: str, path: str = "", persistent: bool = True) -> NetworkProfile | None:
  cp = configparser.ConfigParser(interpolation=None)
  try:
    cp.read_string(raw)
  except configparser.Error:
    return None

  wifi = _section(cp, "wifi", "802-11-wireless")
  if wifi is None or not cp.has_section("connection"):
    return None

  profile_uuid = _parse_uuid(cp.get("connection", "uuid", fallback=""))
  ssid = _decode_ssid(cp.get(wifi, "ssid", fallback=""))
  if profile_uuid is None or not is_valid_ssid(ssid):
    return None
  if cp.get("connection", "type", fallback="wifi") not in ("wifi", "802-11-wireless"):
    return None
  if cp.get("connection", "interface-name", fallback="") not in ("", "wlan0"):
    return None
  if not cp.getboolean("connection", "autoconnect", fallback=True):
    return None
  if cp.get(wifi, "mode", fallback="infrastructure") != "infrastructure":
    return None

  supported_connection = {"id", "uuid", "type", "interface-name", "autoconnect", "autoconnect-priority", "timestamp", "metered"}
  supported_wifi = {"ssid", "mode", "hidden", "bssid"}
  if {key for key, value in cp.items("connection") if value} - supported_connection:
    return None
  if {key for key, value in cp.items(wifi) if value} - supported_wifi:
    return None

  bssid = cp.get(wifi, "bssid", fallback="")
  if bssid and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid) is None:
    return None

  security = SecurityType.OPEN
  psk = ""
  security_section = _section(cp, "wifi-security", "802-11-wireless-security")
  if security_section is not None:
    supported_security = {"key-mgmt", "psk", "psk-flags", "auth-alg"}
    if {key for key, value in cp.items(security_section) if value} - supported_security:
      return None
    key_mgmt = cp.get(security_section, "key-mgmt", fallback="none").lower()
    if key_mgmt == "wpa-psk":
      psk = _decode_keyfile_string(cp.get(security_section, "psk", fallback=""))
      if not _valid_psk(psk) or cp.getint(security_section, "psk-flags", fallback=0) != 0:
        return None
      security = SecurityType.WPA
    elif key_mgmt != "none":
      return None
    elif cp.get(security_section, "psk", fallback=""):
      return None

  ipv4 = dict(cp["ipv4"]) if cp.has_section("ipv4") else {"method": "auto"}
  ipv6 = dict(cp["ipv6"]) if cp.has_section("ipv6") else {"method": "auto"}
  if ipv4.get("method", "auto") != "auto" or set(k for k, v in ipv4.items() if v) - {"method", "dns-priority"}:
    return None
  if ipv4.get("dns-priority", "600") != "600":
    return None
  if ipv6.get("method", "auto") not in ("auto", "ignore") or set(k for k, v in ipv6.items() if v) - {"method", "addr-gen-mode"}:
    return None

  metered_value = cp.getint("connection", "metered", fallback=0)
  metered = MeteredType.YES if metered_value == 1 else MeteredType.NO if metered_value == 2 else MeteredType.UNKNOWN
  return NetworkProfile(
    uuid=profile_uuid,
    ssid=ssid,
    security=security,
    psk=psk,
    hidden=cp.getboolean(wifi, "hidden", fallback=False),
    priority=cp.getint("connection", "autoconnect-priority", fallback=0),
    bssid=bssid.lower(),
    metered=metered,
    ipv6_enabled=ipv6.get("method", "auto") != "ignore",
    path=path,
    persistent=persistent,
  )


def render_profile(profile: NetworkProfile) -> str:
  lines = [
    "[connection]",
    f"id={_encode_keyfile_string(profile.ssid)}",
    f"uuid={profile.uuid}",
    "type=wifi",
    "autoconnect=true",
    f"autoconnect-priority={profile.priority}",
    f"metered={int(profile.metered)}",
    "",
    "[wifi]",
    "mode=infrastructure",
    f"ssid={_encode_ssid(profile.ssid)}",
  ]
  if profile.hidden:
    lines.append("hidden=true")
  if profile.bssid:
    lines.append(f"bssid={profile.bssid}")
  if profile.security == SecurityType.WPA:
    lines += ["", "[wifi-security]", "key-mgmt=wpa-psk", f"psk={_encode_keyfile_string(profile.psk)}"]
  lines += ["", "[ipv4]", "method=auto", "dns-priority=600", "", "[ipv6]", f"method={'auto' if profile.ipv6_enabled else 'ignore'}", ""]
  return "\n".join(lines)


class NetworkStore:
  def __init__(self, directory: str = NM_CONNECTIONS_DIR, runtime_directory: str | None = None):
    self._directory = directory
    self._runtime_directory = RUNTIME_CONNECTIONS_DIR if runtime_directory is None and directory == NM_CONNECTIONS_DIR else runtime_directory
    self._profiles: dict[str, NetworkProfile] = {}
    self.reload()

  def reload(self) -> None:
    profiles: dict[str, NetworkProfile] = {}
    for directory, persistent in ((self._directory, True), (self._runtime_directory, False)):
      if directory is None:
        continue
      try:
        filenames = sorted(os.listdir(directory))
      except OSError:
        continue
      for filename in filenames:
        if not filename.endswith(".nmconnection"):
          continue
        path = os.path.join(directory, filename)
        raw = sudo_read(path)
        profile = parse_profile(raw, path, persistent) if raw else None
        if profile is not None and (profile.uuid not in profiles or persistent):
          profiles[profile.uuid] = profile
    self._profiles = profiles

  def profiles(self) -> list[NetworkProfile]:
    return list(self._profiles.values())

  def profiles_for_ssid(self, ssid: str) -> list[NetworkProfile]:
    return [profile for profile in self._profiles.values() if profile.ssid == ssid]

  def get(self, profile_uuid: str) -> NetworkProfile | None:
    parsed_uuid = _parse_uuid(profile_uuid)
    return self._profiles.get(parsed_uuid) if parsed_uuid is not None else None

  def metered(self, profile_uuid: str) -> MeteredType:
    profile = self.get(profile_uuid)
    return profile.metered if profile is not None else MeteredType.UNKNOWN

  def _path(self, profile: NetworkProfile) -> str:
    safe_ssid = profile.ssid.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace").replace("/", "_")
    return os.path.join(self._directory, f"{profile.uuid}-{safe_ssid}.nmconnection")

  def write(self, profile: NetworkProfile) -> NetworkProfile:
    path = self._path(profile)
    Path(self._directory).mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["sudo", "tee", path], input=render_profile(profile), text=True, stdout=subprocess.DEVNULL)
    if result.returncode != 0:
      raise OSError(f"failed to write {path}")
    subprocess.run(["sudo", "chmod", "600", path], check=True)
    stored = replace(profile, path=path, persistent=True)
    self._profiles[stored.uuid] = stored
    return stored
