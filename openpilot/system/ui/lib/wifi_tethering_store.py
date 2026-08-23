import configparser
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, replace

from openpilot.common.utils import sudo_read


NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"
RUNTIME_CONNECTIONS_DIR = "/run/NetworkManager/system-connections"


@dataclass(frozen=True)
class TetheringProfile:
  uuid: str
  ssid: str
  password: str
  path: str = ""
  persistent: bool = True
  raw: str = ""


def _decode_string(value: str) -> str:
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


def _encode_string(value: str) -> str:
  return "".join({"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(char, char) for char in value)


def _decode_ssid(value: str) -> str:
  if re.fullmatch(r"(?:[0-9]{1,3};)+", value):
    parts = [int(part) for part in value[:-1].split(";")]
    if parts and all(part <= 255 for part in parts):
      return bytes(parts).decode("utf-8", errors="surrogateescape")
  return _decode_string(value)


def _encode_ssid(value: str) -> str:
  return ";".join(str(byte) for byte in value.encode("utf-8")) + ";"


def _valid_password(password: str) -> bool:
  try:
    size = len(password.encode("utf-8"))
  except UnicodeEncodeError:
    return False
  return 8 <= size <= 63 or len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password)


def parse_tethering_profile(raw: str, path: str = "", persistent: bool = True) -> TetheringProfile | None:
  cp = configparser.ConfigParser(interpolation=None)
  try:
    cp.read_string(raw)
  except configparser.Error:
    return None

  wifi = "wifi" if cp.has_section("wifi") else "802-11-wireless" if cp.has_section("802-11-wireless") else None
  security = "wifi-security" if cp.has_section("wifi-security") else "802-11-wireless-security" if cp.has_section("802-11-wireless-security") else None
  if wifi is None or security is None or not cp.has_section("connection"):
    return None

  try:
    profile_uuid = str(uuid.UUID(cp.get("connection", "uuid", fallback="")))
    autoconnect = cp.getboolean("connection", "autoconnect", fallback=False)
  except (ValueError, configparser.Error):
    return None

  ssid = _decode_ssid(cp.get(wifi, "ssid", fallback=""))
  password = _decode_string(cp.get(security, "psk", fallback=""))
  if (
    not ssid
    or cp.get("connection", "type", fallback="wifi") not in ("wifi", "802-11-wireless")
    or cp.get("connection", "interface-name", fallback="") not in ("", "wlan0")
    or autoconnect
    or cp.get(wifi, "mode", fallback="") != "ap"
    or cp.get(security, "key-mgmt", fallback="").lower() != "wpa-psk"
    or not _valid_password(password)
    or cp.get("ipv4", "method", fallback="") != "shared"
  ):
    return None

  return TetheringProfile(profile_uuid, ssid, password, path, persistent, raw)


def render_tethering_profile(profile: TetheringProfile) -> str:
  return f"""[connection]
id=Hotspot
uuid={profile.uuid}
type=wifi
interface-name=wlan0
autoconnect=false
autoconnect-retries=0

[wifi]
band=bg
mode=ap
ssid={_encode_ssid(profile.ssid)}

[wifi-security]
group=ccmp;
key-mgmt=wpa-psk
pairwise=ccmp;
proto=rsn;
psk={_encode_string(profile.password)}

[ipv4]
method=shared
address1=192.168.43.1/24,192.168.43.1
never-default=true

[ipv6]
method=ignore
"""


class TetheringStore:
  def __init__(self, directory: str = NM_CONNECTIONS_DIR, runtime_directory: str | None = None):
    self._directory = directory
    self._runtime_directory = RUNTIME_CONNECTIONS_DIR if runtime_directory is None and directory == NM_CONNECTIONS_DIR else runtime_directory
    self._profiles: dict[str, TetheringProfile] = {}
    self._runtime_uuids: set[str] = set()
    self.reload()

  def reload(self):
    profiles: dict[str, TetheringProfile] = {}
    runtime_uuids: set[str] = set()
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
        profile = parse_tethering_profile(raw, path, persistent) if raw else None
        if profile is None:
          continue
        if not persistent:
          runtime_uuids.add(profile.uuid)
        if profile.uuid not in profiles or persistent:
          profiles[profile.uuid] = profile
    self._profiles = profiles
    self._runtime_uuids = runtime_uuids

  def get(self, ssid: str) -> TetheringProfile | None:
    matches = [profile for profile in self._profiles.values() if profile.ssid == ssid]
    return matches[0] if len(matches) == 1 else None

  def can_mutate(self, profile: TetheringProfile) -> bool:
    return profile.persistent and profile.uuid not in self._runtime_uuids and profile.path.startswith(self._directory + os.sep)

  def ensure(self, ssid: str, password: str) -> TetheringProfile | None:
    profile = self.get(ssid)
    if profile is not None:
      return profile
    if any(item.ssid == ssid for item in self._profiles.values()):
      return None
    profile = TetheringProfile(str(uuid.uuid4()), ssid, password)
    return self._write(profile, render_tethering_profile(profile))

  def set_password(self, ssid: str, password: str) -> TetheringProfile | None:
    profile = self.get(ssid)
    if profile is None or not self.can_mutate(profile) or not _valid_password(password):
      return None

    cp = configparser.ConfigParser(interpolation=None)
    try:
      cp.read_string(profile.raw)
    except configparser.Error:
      return None
    security = "wifi-security" if cp.has_section("wifi-security") else "802-11-wireless-security"
    cp.set(security, "psk", _encode_string(password))
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
      cp.write(f, space_around_delimiters=False)
      temp_path = f.name
    try:
      with open(temp_path) as f:
        raw = f.read()
      return self._write(replace(profile, password=password), raw)
    finally:
      os.unlink(temp_path)

  def _write(self, profile: TetheringProfile, raw: str) -> TetheringProfile:
    path = profile.path or os.path.join(self._directory, f"{profile.uuid}-Hotspot.nmconnection")
    subprocess.run(["sudo", "install", "-d", "-m", "700", self._directory], check=True)
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
      f.write(raw)
      temp_path = f.name
    try:
      subprocess.run(["sudo", "install", "-m", "600", temp_path, path], check=True)
    finally:
      os.unlink(temp_path)
    stored = replace(profile, path=path, persistent=True, raw=raw)
    self._profiles[stored.uuid] = stored
    return stored
