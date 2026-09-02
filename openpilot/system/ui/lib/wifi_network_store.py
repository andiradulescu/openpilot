import configparser
import os
import re
import subprocess
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass, replace
from enum import IntEnum

from openpilot.common.utils import sudo_read
from openpilot.system.ui.lib.wpa_ctrl import SecurityType, is_valid_ssid
from openpilot.system.ui.lib.wpa_supplicant import WpaNetwork


NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"
RUNTIME_CONNECTIONS_DIR = "/run/NetworkManager/system-connections"
_FORGET_RE = re.compile(r"^(?P<name>.+\.nmconnection)\.openpilot-forget-(?P<token>[0-9a-f]{32})$")
_FORGET_MARKER_RE = re.compile(r"^\.openpilot-forget-committed-(?P<token>[0-9a-f]{32})$")
_UPDATE_RE = re.compile(r"^(?P<name>.+\.nmconnection)\.openpilot-update-(?P<token>[0-9a-f]{32})$")
_RUNTIME_SHADOW_RE = re.compile(r"^(?P<name>.+\.nmconnection)\.openpilot-shadow-(?P<token>[0-9a-f]{32})$")


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
  read_only: bool = False
  autoconnect: bool = True

  def as_wpa_network(self) -> WpaNetwork:
    return WpaNetwork(self.ssid, self.security, self.psk, self.hidden, self.uuid, self.priority, self.bssid, disabled=not self.autoconnect)


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


def _display_ssid(value: str) -> str:
  return value.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace").replace("\x00", "�")


def _encode_keyfile_string(value: str) -> str:
  leading_spaces = len(value) - len(value.lstrip(" "))
  trailing_start = len(value.rstrip(" "))
  escapes = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
  return "".join(
    "\\s" if char == " " and (index < leading_spaces or index >= trailing_start) else escapes.get(char, char)
    for index, char in enumerate(value)
  )


def _section(cp: configparser.ConfigParser, *names: str) -> str | None:
  return next((name for name in names if cp.has_section(name)), None)


def _getint(cp: configparser.ConfigParser, section: str, option: str, fallback: int) -> int | None:
  try:
    return cp.getint(section, option, fallback=fallback)
  except ValueError:
    return None


def _getbool(cp: configparser.ConfigParser, section: str, option: str, fallback: bool) -> bool | None:
  try:
    return cp.getboolean(section, option, fallback=fallback)
  except ValueError:
    return None


def _valid_psk(psk: str) -> bool:
  try:
    if any(unicodedata.category(char) == "Cc" for char in psk):
      return False
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
  connection_id = _decode_keyfile_string(cp.get("connection", "id", fallback=""))
  autoconnect = _getbool(cp, "connection", "autoconnect", True)
  retries = _getint(cp, "connection", "autoconnect-retries", 0)
  priority = _getint(cp, "connection", "autoconnect-priority", 0)
  hidden = _getbool(cp, wifi, "hidden", False)
  metered_value = _getint(cp, "connection", "metered", 0)
  if autoconnect is None or retries is None or priority is None or hidden is None or metered_value is None:
    return None

  if profile_uuid is None or not is_valid_ssid(ssid):
    return None
  if cp.get("connection", "type", fallback="wifi") not in ("wifi", "802-11-wireless"):
    return None
  if cp.get("connection", "interface-name", fallback="") not in ("", "wlan0"):
    return None
  if retries != 0 or not 0 <= priority <= 255:
    return None
  if cp.get(wifi, "mode", fallback="infrastructure") != "infrastructure":
    return None

  supported_connection = {
    "id", "uuid", "type", "interface-name", "autoconnect", "autoconnect-priority", "autoconnect-retries", "timestamp", "metered",
  }
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
    psk_flags = _getint(cp, security_section, "psk-flags", 0)
    if psk_flags is None:
      return None
    if key_mgmt == "wpa-psk":
      psk = _decode_keyfile_string(cp.get(security_section, "psk", fallback=""))
      if not _valid_psk(psk) or psk_flags != 0:
        return None
      security = SecurityType.WPA
    elif key_mgmt != "none" or cp.get(security_section, "psk", fallback=""):
      return None

  ipv4 = dict(cp["ipv4"]) if cp.has_section("ipv4") else {"method": "auto"}
  ipv6 = dict(cp["ipv6"]) if cp.has_section("ipv6") else {"method": "auto"}
  if ipv4.get("method", "auto") != "auto" or {key for key, value in ipv4.items() if value} - {"method", "dns-priority"}:
    return None
  if ipv4.get("dns-priority", "600") != "600":
    return None
  if ipv6.get("method", "auto") not in ("auto", "ignore") or {key for key, value in ipv6.items() if value} - {"method", "addr-gen-mode"}:
    return None

  represented_sections = {"connection", wifi, "ipv4", "ipv6"}
  if security_section is not None:
    represented_sections.add(security_section)
  display_id = _display_ssid(ssid)
  read_only = (
    not cp.has_option("connection", "autoconnect-retries")
    or not cp.has_option("ipv4", "dns-priority")
    or (cp.has_option("connection", "id") and connection_id not in (display_id, f"openpilot connection {display_id}"))
    or bool(cp.get("connection", "timestamp", fallback=""))
    or bool(cp.get("connection", "interface-name", fallback=""))
    or bool(ipv6.get("addr-gen-mode"))
    or metered_value not in (0, 1, 2)
    or any(
      section not in represented_sections and any(value for _, value in cp.items(section))
      for section in cp.sections()
    )
  )

  metered = MeteredType.YES if metered_value == 1 else MeteredType.NO if metered_value == 2 else MeteredType.UNKNOWN
  return NetworkProfile(
    uuid=profile_uuid,
    ssid=ssid,
    security=security,
    psk=psk,
    hidden=hidden,
    priority=priority,
    bssid=bssid.lower(),
    metered=metered,
    ipv6_enabled=ipv6.get("method", "auto") != "ignore",
    path=path,
    persistent=persistent,
    read_only=read_only,
    autoconnect=autoconnect,
  )


def render_profile(profile: NetworkProfile) -> str:
  lines = [
    "[connection]",
    f"id={_encode_keyfile_string(_display_ssid(profile.ssid))}",
    f"uuid={profile.uuid}",
    "type=wifi",
    f"autoconnect={'true' if profile.autoconnect else 'false'}",
    "autoconnect-retries=0",
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
    self._runtime_paths: dict[str, str] = {}
    self.reload()

  def _ensure_directory_access(self) -> None:
    if self._directory == NM_CONNECTIONS_DIR:
      subprocess.run(["sudo", "install", "-d", "-m", "755", self._directory], check=True)

  def recover(self) -> None:
    self._ensure_directory_access()
    self._recover_forgets()
    self._recover_updates()
    self.reload()

  def _recover_updates(self) -> None:
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
      raise OSError("failed to inspect pending profile updates") from e

  def _recover_pending_update(self) -> None:
    if not self._has_pending_update():
      return
    self.recover()
    if self._has_pending_update():
      raise OSError("profile update recovery is still pending")

  def _recover_forgets(self) -> None:
    try:
      filenames = sorted(os.listdir(self._directory))
    except OSError:
      return

    markers = {
      match.group("token"): os.path.join(self._directory, filename)
      for filename in filenames
      if (match := _FORGET_MARKER_RE.fullmatch(filename)) is not None
    }
    forget_tokens = {
      match.group("token")
      for filename in filenames
      if (match := _FORGET_RE.fullmatch(filename)) is not None
    } | set(markers)

    runtime_failed: set[str] = set()
    if self._runtime_directory is not None:
      try:
        runtime_filenames = sorted(os.listdir(self._runtime_directory))
      except FileNotFoundError:
        runtime_filenames = []
      except OSError:
        return
      for filename in runtime_filenames:
        match = _RUNTIME_SHADOW_RE.fullmatch(filename)
        if match is None or match.group("token") not in forget_tokens:
          continue
        token = match.group("token")
        staged = os.path.join(self._runtime_directory, filename)
        original = os.path.join(self._runtime_directory, match.group("name"))
        command = ["sudo", "rm", "-f", staged] if token in markers else ["sudo", "mv", "-f", staged, original]
        if subprocess.run(command, check=False).returncode != 0:
          runtime_failed.add(token)

    cleanup_failed = set(runtime_failed)
    for filename in filenames:
      match = _FORGET_RE.fullmatch(filename)
      if match is None:
        continue
      token = match.group("token")
      if token not in markers and token in runtime_failed:
        continue
      staged = os.path.join(self._directory, filename)
      original = os.path.join(self._directory, match.group("name"))
      command = ["sudo", "rm", "-f", staged] if token in markers else ["sudo", "mv", "-f", staged, original]
      if subprocess.run(command, check=False).returncode != 0:
        cleanup_failed.add(token)

    for token, marker in markers.items():
      if token not in cleanup_failed:
        subprocess.run(["sudo", "rm", "-f", marker], check=False)

  def reload(self) -> None:
    profiles: dict[str, NetworkProfile] = {}
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
              profile_uuid = _parse_uuid(cp.get("connection", "uuid", fallback=""))
              if profile_uuid is not None:
                runtime_paths[profile_uuid] = path
        profile = parse_profile(raw, path, persistent) if raw else None
        if profile is None:
          continue
        if profile.uuid not in profiles or persistent:
          profiles[profile.uuid] = profile
    self._profiles = profiles
    self._runtime_paths = runtime_paths

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

  def can_mutate(self, profile_uuid: str) -> bool:
    profile = self.get(profile_uuid)
    return (
      profile is not None
      and not profile.read_only
      and profile.persistent
      and profile.path.startswith(self._directory + os.sep)
    )

  def _can_remove(self, profile: NetworkProfile) -> bool:
    return profile.persistent and profile.path.startswith(self._directory + os.sep)

  def _clear_runtime_shadow(self, profile_uuid: str) -> bool:
    path = self._runtime_paths.get(profile_uuid)
    if path is None:
      return True
    if subprocess.run(["sudo", "rm", "-f", path], check=False).returncode != 0:
      return False
    self._runtime_paths.pop(profile_uuid, None)
    return True

  def _stage_runtime_shadow(self, profile_uuid: str, token: str) -> tuple[str, str] | None:
    path = self._runtime_paths.get(profile_uuid)
    if path is None:
      return None
    staged_path = f"{path}.openpilot-shadow-{token}"
    if subprocess.run(["sudo", "mv", "-f", path, staged_path], check=False).returncode != 0:
      raise OSError(f"failed to stage runtime shadow for profile {profile_uuid}")
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

  def _path(self, profile: NetworkProfile) -> str:
    safe_ssid = profile.ssid.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace").replace("/", "_").replace("\x00", "_")
    return os.path.join(self._directory, f"{profile.uuid}-{safe_ssid}.nmconnection")

  def write(self, profile: NetworkProfile) -> NetworkProfile:
    self._ensure_directory_access()
    self._recover_pending_update()
    existing = self.get(profile.uuid)
    if existing is not None and not self.can_mutate(profile.uuid):
      raise OSError(f"profile {profile.uuid} is read-only")

    path = existing.path if existing is not None else self._path(profile)
    subprocess.run(["sudo", "install", "-d", "-m", "755", self._directory], check=True)
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
      f.write(render_profile(profile))
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
    stored = replace(profile, path=path, persistent=True)
    self._profiles[stored.uuid] = stored
    return stored

  def set_metered(self, profile_uuid: str, metered: MeteredType) -> NetworkProfile | None:
    profile = self.get(profile_uuid)
    if profile is None or not self.can_mutate(profile_uuid):
      return None
    try:
      return self.write(replace(profile, metered=metered))
    except (OSError, subprocess.SubprocessError):
      return None

  def remove_ssid(self, ssid: str) -> bool:
    try:
      self._ensure_directory_access()
      self._recover_pending_update()
    except (OSError, subprocess.SubprocessError):
      return False
    profiles = self.profiles_for_ssid(ssid)
    if not profiles:
      return True
    if any(not self._can_remove(profile) for profile in profiles):
      return False

    token = uuid.uuid4().hex
    staged: list[tuple[str, str]] = []
    for profile in profiles:
      staged_path = f"{profile.path}.openpilot-forget-{token}"
      result = subprocess.run(["sudo", "mv", "-f", profile.path, staged_path], check=False)
      if result.returncode != 0:
        for original, staged_file in reversed(staged):
          subprocess.run(["sudo", "mv", "-f", staged_file, original], check=False)
        return False
      staged.append((profile.path, staged_path))

    runtime_shadows: list[tuple[str, tuple[str, str]]] = []
    try:
      for profile in profiles:
        runtime_shadow = self._stage_runtime_shadow(profile.uuid, token)
        if runtime_shadow is not None:
          runtime_shadows.append((profile.uuid, runtime_shadow))
    except (OSError, subprocess.SubprocessError):
      shadows_restored = all(self._restore_runtime_shadow(profile_uuid, runtime_shadow) for profile_uuid, runtime_shadow in reversed(runtime_shadows))
      if shadows_restored:
        for original, staged_file in reversed(staged):
          subprocess.run(["sudo", "mv", "-f", staged_file, original], check=False)
      return False

    marker = os.path.join(self._directory, f".openpilot-forget-committed-{token}")
    if subprocess.run(["sudo", "touch", marker], check=False).returncode != 0:
      shadows_restored = all(self._restore_runtime_shadow(profile_uuid, runtime_shadow) for profile_uuid, runtime_shadow in reversed(runtime_shadows))
      if shadows_restored:
        for original, staged_file in reversed(staged):
          subprocess.run(["sudo", "mv", "-f", staged_file, original], check=False)
      return False

    cleanup_failed = False
    for _, runtime_shadow in runtime_shadows:
      cleanup_failed |= subprocess.run(["sudo", "rm", "-f", runtime_shadow[1]], check=False).returncode != 0
    for _, staged_file in staged:
      cleanup_failed |= subprocess.run(["sudo", "rm", "-f", staged_file], check=False).returncode != 0
    if not cleanup_failed:
      subprocess.run(["sudo", "rm", "-f", marker], check=False)
    for profile in profiles:
      self._profiles.pop(profile.uuid, None)
    return True
