import configparser
import os
import re
import subprocess
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from openpilot.common.utils import sudo_read
from openpilot.system.ui.lib import wpa_supplicant


NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"
RUNTIME_CONNECTIONS_DIR = "/run/NetworkManager/system-connections"
_UPDATE_RE = re.compile(r"^(?P<name>.+\.nmconnection)\.openpilot-update-(?P<token>[0-9a-f]{32})$")
_RUNTIME_SHADOW_RE = re.compile(r"^(?P<name>.+\.nmconnection)\.openpilot-shadow-(?P<token>[0-9a-f]{32})$")


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
  leading_spaces = len(value) - len(value.lstrip(" "))
  trailing_start = len(value.rstrip(" "))
  escapes = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
  return "".join(
    "\\s" if char == " " and (index < leading_spaces or index >= trailing_start) else escapes.get(char, char)
    for index, char in enumerate(value)
  )


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
    if any(unicodedata.category(char) == "Cc" for char in password):
      return False
    size = len(password.encode("utf-8"))
  except UnicodeEncodeError:
    return False
  return 8 <= size <= 63 or len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password)


def _decode_wpa_psk(value: str) -> str | None:
  if len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value):
    return value
  if len(value) < 2 or value[0] != '"' or value[-1] != '"':
    return None

  out = []
  i = 1
  end = len(value) - 1
  while i < end:
    char = value[i]
    if char == "\\":
      i += 1
      if i >= end or value[i] not in ('\\', '"'):
        return None
      char = value[i]
    out.append(char)
    i += 1
  return "".join(out)


def _live_ap_password(ssid: str) -> str | None:
  if not wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF):
    return None
  try:
    raw = Path(wpa_supplicant.WPA_AP_CONF).read_text()
  except OSError:
    return None

  values: dict[str, str] = {}
  in_network = False
  for raw_line in raw.splitlines():
    line = raw_line.strip()
    if not in_network:
      if line == "network={":
        in_network = True
      continue
    if line == "}":
      break
    key, separator, value = line.partition("=")
    if separator:
      values[key] = value

  if values.get("ssid") != ssid.encode("utf-8", errors="surrogateescape").hex():
    return None
  password = _decode_wpa_psk(values.get("psk", ""))
  return password if password is not None and _valid_password(password) else None


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
    self._runtime_paths: dict[str, str] = {}
    self.reload()

  def recover(self):
    self._recover_updates()
    self.reload()

  def _recover_updates(self):
    try:
      filenames = sorted(os.listdir(self._directory))
    except OSError:
      return
    updates = {
      match.group("token"): os.path.join(self._directory, filename)
      for filename in filenames
      if (match := _UPDATE_RE.fullmatch(filename)) is not None
    }

    restore_failed: set[str] = set()
    if self._runtime_directory is not None:
      try:
        runtime_filenames = sorted(os.listdir(self._runtime_directory))
      except FileNotFoundError:
        runtime_filenames = []
      except OSError:
        return
      for filename in runtime_filenames:
        match = _RUNTIME_SHADOW_RE.fullmatch(filename)
        if match is None:
          continue
        token = match.group("token")
        staged = os.path.join(self._runtime_directory, filename)
        original = os.path.join(self._runtime_directory, match.group("name"))
        command = ["sudo", "mv", "-f", staged, original] if token in updates else ["sudo", "rm", "-f", staged]
        if subprocess.run(command, check=False).returncode != 0 and token in updates:
          restore_failed.add(token)

    for token, path in updates.items():
      if token not in restore_failed:
        subprocess.run(["sudo", "rm", "-f", path], check=False)

  def _has_pending_update(self) -> bool:
    try:
      return any(_UPDATE_RE.fullmatch(filename) for filename in os.listdir(self._directory))
    except OSError as e:
      raise OSError("failed to inspect pending tethering updates") from e

  def _recover_pending_update(self) -> None:
    if not self._has_pending_update():
      return
    self.recover()
    if self._has_pending_update():
      raise OSError("tethering update recovery is still pending")

  def reload(self):
    profiles: dict[str, TetheringProfile] = {}
    runtime_paths: dict[str, str] = {}
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
        if raw and not persistent:
          cp = configparser.ConfigParser(interpolation=None)
          try:
            cp.read_string(raw)
          except configparser.Error:
            pass
          else:
            if cp.has_section("connection"):
              try:
                profile_uuid = str(uuid.UUID(cp.get("connection", "uuid", fallback="")))
              except ValueError:
                pass
              else:
                runtime_paths[profile_uuid] = path
        profile = parse_tethering_profile(raw, path, persistent) if raw else None
        if profile is None:
          continue
        if profile.uuid not in profiles or persistent:
          profiles[profile.uuid] = profile
    self._profiles = profiles
    self._runtime_paths = runtime_paths

  def get(self, ssid: str) -> TetheringProfile | None:
    matches = [profile for profile in self._profiles.values() if profile.ssid == ssid]
    persistent = [profile for profile in matches if profile.persistent]
    if len(persistent) == 1:
      return persistent[0]
    if len(persistent) > 1:
      return None
    return matches[0] if len(matches) == 1 else None

  def can_mutate(self, profile: TetheringProfile) -> bool:
    return profile.persistent and profile.path.startswith(self._directory + os.sep)

  def _stage_runtime_shadow(self, profile_uuid: str, token: str) -> tuple[str, str] | None:
    path = self._runtime_paths.get(profile_uuid)
    if path is None:
      return None
    staged_path = f"{path}.openpilot-shadow-{token}"
    if subprocess.run(["sudo", "mv", "-f", path, staged_path], check=False).returncode != 0:
      raise OSError(f"failed to stage runtime shadow for tethering profile {profile_uuid}")
    self._runtime_paths.pop(profile_uuid, None)
    return path, staged_path

  def _restore_runtime_shadow(self, profile_uuid: str, staged: tuple[str, str] | None) -> bool:
    if staged is None:
      return True
    path, staged_path = staged
    try:
      result = subprocess.run(["sudo", "mv", "-f", staged_path, path], check=False)
    except OSError:
      return False
    if result.returncode != 0:
      return False
    self._runtime_paths[profile_uuid] = path
    return True

  def _persistent_path(self, profile: TetheringProfile) -> str:
    if profile.persistent and profile.path.startswith(self._directory + os.sep):
      return profile.path
    return os.path.join(self._directory, f"{profile.uuid}-Hotspot.nmconnection")

  def ensure(self, ssid: str, password: str) -> TetheringProfile | None:
    profile = self.get(ssid)
    if profile is not None:
      if profile.persistent:
        live_password = _live_ap_password(ssid)
        if live_password is not None and live_password != profile.password:
          updated = self.set_password(ssid, live_password)
          return updated if updated is not None else replace(profile, password=live_password)
        return profile
      try:
        promoted = replace(profile, path="", persistent=True)
        return self._write(promoted, render_tethering_profile(promoted))
      except (OSError, subprocess.SubprocessError):
        return None
    if any(item.ssid == ssid for item in self._profiles.values()) or not _valid_password(password):
      return None
    profile = TetheringProfile(str(uuid.uuid4()), ssid, password)
    try:
      return self._write(profile, render_tethering_profile(profile))
    except (OSError, subprocess.SubprocessError):
      return None

  def set_password(self, ssid: str, password: str) -> TetheringProfile | None:
    profile = self.get(ssid)
    if profile is None or not _valid_password(password):
      return None
    if not profile.persistent:
      return self.ensure(ssid, password)
    if not self.can_mutate(profile):
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
      try:
        return self._write(replace(profile, password=password), raw)
      except (OSError, subprocess.SubprocessError):
        return None
    finally:
      os.unlink(temp_path)

  def _write(self, profile: TetheringProfile, raw: str) -> TetheringProfile:
    self._recover_pending_update()
    path = self._persistent_path(profile)
    subprocess.run(["sudo", "install", "-d", "-m", "700", self._directory], check=True)
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
      f.write(raw)
      temp_path = f.name
    token = uuid.uuid4().hex
    stage_path = f"{path}.openpilot-update-{token}"
    runtime_shadow: tuple[str, str] | None = None
    keep_stage = False
    try:
      subprocess.run(["sudo", "install", "-m", "600", temp_path, stage_path], check=True)
      runtime_shadow = self._stage_runtime_shadow(profile.uuid, token)
      try:
        subprocess.run(["sudo", "mv", "-f", stage_path, path], check=True)
      except (OSError, subprocess.SubprocessError):
        if not self._restore_runtime_shadow(profile.uuid, runtime_shadow):
          keep_stage = True
        raise
      if runtime_shadow is not None:
        subprocess.run(["sudo", "rm", "-f", runtime_shadow[1]], check=False)
    finally:
      os.unlink(temp_path)
      if not keep_stage:
        subprocess.run(["sudo", "rm", "-f", stage_path], check=False)
    stored = replace(profile, path=path, persistent=True, raw=raw)
    self._profiles[stored.uuid] = stored
    return stored