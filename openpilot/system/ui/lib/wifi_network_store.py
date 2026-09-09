import configparser
import json
import os
import re
import subprocess
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass, replace
from enum import IntEnum
from pathlib import Path

from openpilot.common.utils import sudo_read
from openpilot.system.ui.lib.wpa_ctrl import SecurityType, is_valid_ssid
from openpilot.system.ui.lib.wpa_supplicant import WpaNetwork


NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"
RUNTIME_CONNECTIONS_DIR = "/run/NetworkManager/system-connections"
NETPLAN_DIR = "/data/etc/netplan"
_FORGET_RE = re.compile(r"^(?P<name>.+\.(?:nmconnection|yaml))\.openpilot-forget-(?P<token>[0-9a-f]{32})$")
_FORGET_MARKER_RE = re.compile(r"^\.openpilot-forget-committed-(?P<token>[0-9a-f]{32})$")
_NETPLAN_UPDATE_RE = re.compile(r"^.+\.yaml\.openpilot-netplan-update-(?P<token>[0-9a-f]{32})$")
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
  def __init__(self, directory: str = NM_CONNECTIONS_DIR, runtime_directory: str | None = None, netplan_directory: str | None = None):
    self._directory = directory
    self._runtime_directory = RUNTIME_CONNECTIONS_DIR if runtime_directory is None and directory == NM_CONNECTIONS_DIR else runtime_directory
    self._netplan_directory = NETPLAN_DIR if netplan_directory is None and directory == NM_CONNECTIONS_DIR else netplan_directory
    self._profiles: dict[str, NetworkProfile] = {}
    self._runtime_paths: dict[str, str] = {}
    self._reload_failed = False
    self.reload()

  def _ensure_directory_access(self) -> None:
    if self._directory == NM_CONNECTIONS_DIR:
      subprocess.run(["sudo", "install", "-d", "-m", "755", self._directory], check=True)

  def recover(self) -> None:
    self._ensure_directory_access()
    self._recover_forgets()
    self._recover_updates()
    if self._has_pending_update():
      raise OSError("profile update recovery is still pending")
    self.reload()

  def _require_complete_reload(self) -> None:
    if not self._reload_failed:
      return
    self.reload()
    if self._reload_failed:
      raise OSError("Wi-Fi profile reload is incomplete")

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
    forget_tokens = {
      match.group("token")
      for filename in filenames
      if (match := _FORGET_RE.fullmatch(filename)) is not None
    } | {
      match.group("token")
      for filename in filenames
      if (match := _FORGET_MARKER_RE.fullmatch(filename)) is not None
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
        if match is None or match.group("token") in forget_tokens:
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

  def _has_pending_forget(self) -> bool:
    return bool(self._forget_paths())

  def _forget_paths(self) -> list[str]:
    paths = []
    try:
      for directory in (self._directory, self._netplan_directory):
        if directory is None:
          continue
        try:
          filenames = os.listdir(directory)
        except FileNotFoundError:
          continue
        paths.extend(os.path.join(directory, filename) for filename in sorted(filenames)
                     if (_FORGET_RE.fullmatch(filename) or _FORGET_MARKER_RE.fullmatch(filename)
                         or _NETPLAN_UPDATE_RE.fullmatch(filename) or _RUNTIME_SHADOW_RE.fullmatch(filename)))
    except OSError as e:
      raise OSError("failed to inspect pending profile forgets") from e
    return paths

  def _recover_pending_transactions(self) -> None:
    if not self._has_pending_update() and not self._has_pending_forget():
      return
    self.recover()
    if self._has_pending_update() or self._has_pending_forget():
      raise OSError("profile transaction recovery is still pending")

  def _recover_forgets(self) -> None:
    paths = self._forget_paths()
    markers = {
      match.group("token"): path
      for path in paths
      if (match := _FORGET_MARKER_RE.fullmatch(os.path.basename(path))) is not None
    }
    runtime_backups = {
      path: (match.group("name"), match.group("token"))
      for path in paths
      if (match := _RUNTIME_SHADOW_RE.fullmatch(os.path.basename(path))) is not None
    }
    forget_tokens = {
      match.group("token")
      for path in paths
      if (match := _FORGET_RE.fullmatch(path)) is not None
    } | set(markers) | {token for _, token in runtime_backups.values()}

    runtime_failed: set[str] = set()
    for backup, (name, token) in runtime_backups.items():
      if token in markers:
        continue
      if self._runtime_directory is None:
        runtime_failed.add(token)
        continue
      staged = os.path.join(self._runtime_directory, f"{name}.openpilot-shadow-{token}")
      try:
        subprocess.run(["sudo", "install", "-d", "-m", "755", self._runtime_directory], check=True)
        subprocess.run(["sudo", "install", "-m", "600", backup, staged], check=True)
      except (OSError, subprocess.SubprocessError):
        runtime_failed.add(token)
    if self._runtime_directory is not None:
      try:
        runtime_filenames = sorted(os.listdir(self._runtime_directory))
      except FileNotFoundError:
        runtime_filenames = []
      except OSError as e:
        raise OSError("failed to inspect runtime profile forget recovery") from e
      for filename in runtime_filenames:
        match = _RUNTIME_SHADOW_RE.fullmatch(filename)
        if match is None or match.group("token") not in forget_tokens or match.group("token") in runtime_failed:
          continue
        token = match.group("token")
        staged = os.path.join(self._runtime_directory, filename)
        original = os.path.join(self._runtime_directory, match.group("name"))
        command = ["sudo", "rm", "-f", staged] if token in markers else ["sudo", "mv", "-f", staged, original]
        if subprocess.run(command, check=False).returncode != 0:
          runtime_failed.add(token)

    cleanup_failed = set(runtime_failed)
    for staged in paths:
      if match := _NETPLAN_UPDATE_RE.fullmatch(staged):
        if subprocess.run(["sudo", "rm", "-f", staged], check=False).returncode != 0:
          cleanup_failed.add(match.group("token"))
        continue
      match = _FORGET_RE.fullmatch(staged)
      if match is None:
        continue
      token = match.group("token")
      if token not in markers and token in cleanup_failed:
        continue
      original = match.group("name")
      unchanged = os.path.exists(original) and os.path.samefile(staged, original)
      command = ["sudo", "rm", "-f", staged] if token in markers or unchanged else ["sudo", "mv", "-f", staged, original]
      if subprocess.run(command, check=False).returncode != 0:
        cleanup_failed.add(token)

    for backup, (_, token) in runtime_backups.items():
      if token not in cleanup_failed and subprocess.run(["sudo", "rm", "-f", backup], check=False).returncode != 0:
        cleanup_failed.add(token)

    for token, marker in markers.items():
      if token not in cleanup_failed:
        subprocess.run(["sudo", "rm", "-f", marker], check=False)

    if any(token not in markers for token in cleanup_failed):
      raise OSError("profile forget recovery is still pending")

  def reload(self) -> None:
    profiles: dict[str, NetworkProfile] = {}
    runtime_paths: dict[str, str] = {}
    load_failed = False
    for directory, persistent in ((self._directory, True), (self._runtime_directory, False)):
      if directory is None:
        continue
      try:
        filenames = sorted(os.listdir(directory))
      except FileNotFoundError:
        continue
      except OSError:
        load_failed = True
        continue
      for filename in filenames:
        if not filename.endswith(".nmconnection"):
          continue
        path = os.path.join(directory, filename)
        raw = sudo_read(path)
        if not raw:
          load_failed = True
          continue
        if not persistent:
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
        profile = parse_profile(raw, path, persistent)
        if profile is None:
          continue
        if profile.uuid not in profiles or persistent:
          profiles[profile.uuid] = profile
    self._reload_failed = load_failed
    if not load_failed:
      self._profiles = profiles
      self._runtime_paths = runtime_paths

  def profiles(self) -> list[NetworkProfile]:
    self._require_complete_reload()
    return list(self._profiles.values())

  def profiles_for_ssid(self, ssid: str) -> list[NetworkProfile]:
    self._require_complete_reload()
    return [profile for profile in self._profiles.values() if profile.ssid == ssid]

  def get(self, profile_uuid: str) -> NetworkProfile | None:
    self._require_complete_reload()
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

  def _netplan_removals(self, ssid: str) -> tuple[set[str], dict[str, tuple[str, str | None]]]:
    if self._netplan_directory is None:
      return set(), {}
    try:
      paths = [Path(self._netplan_directory) / name for name in sorted(os.listdir(self._netplan_directory)) if name.endswith(".yaml")]
    except FileNotFoundError:
      return set(), {}
    if not paths:
      return set(), {}
    raw = [subprocess.run(["sudo", "cat", "--", str(path)], capture_output=True, text=True, check=True).stdout for path in paths]
    # Netplan's YAML dependency belongs to the system Python, outside the openpilot venv.
    parser = "import json, sys, yaml; json.dump([yaml.load(s, Loader=yaml.BaseLoader) for s in json.load(sys.stdin)], sys.stdout)"
    try:
      with tempfile.TemporaryDirectory(prefix="openpilot-netplan-") as root:
        def get_config():
          result = subprocess.run(["netplan", "get", "--root-dir", root], capture_output=True, text=True, check=True)
          # Netplan can report validation errors with exit status 0.
          if not result.stdout.strip() and result.stderr:
            raise OSError("failed to read Netplan configuration")
          return result.stdout

        directory = Path(root) / "etc/netplan"
        directory.mkdir(parents=True)
        for path, content in zip(paths, raw, strict=True):
          target = directory / path.name
          target.touch(mode=0o600)
          target.write_text(content)
        merged = get_config()
        result = subprocess.run(["/usr/bin/python3", "-c", parser], input=json.dumps([*raw, merged]), capture_output=True, text=True, check=True)
        configs = json.loads(result.stdout)
        config = configs.pop()
        remaining_aps = {}
        profile_uuids = set()
        for name, definition in (config or {}).get("network", {}).get("wifis", {}).items():
          aps = definition.get("access-points", {})
          if ssid in aps:
            nm = aps[ssid].get("networkmanager", {})
            profile_uuid = _parse_uuid(nm.get("uuid", definition.get("networkmanager", {}).get("uuid", "")))
            if profile_uuid is not None:
              profile_uuids.add(profile_uuid)
            remaining_aps[name] = next((ap for ap in aps if ap != ssid), None)
        if not remaining_aps:
          return set(), {}

        seen = set()

        def remove(config):
          if config is None:
            return False
          network = config.get("network", {})
          wifis = network.get("wifis", {})
          changed = False
          for name, remaining_ap in remaining_aps.items():
            if name not in wifis:
              continue
            if remaining_ap is None:
              del wifis[name]
              changed = True
            elif ssid in wifis[name].get("access-points", {}):
              aps = wifis[name]["access-points"]
              del aps[ssid]
              # The first definition needs an AP before Netplan loads the later files.
              if not aps and name not in seen:
                aps[remaining_ap] = {}
              changed = True
            seen.add(name)
          if not wifis:
            network.pop("wifis", None)
          return changed

        pending = {}
        for path, before, source in zip(paths, raw, configs, strict=True):
          if remove(source):
            after = json.dumps(source, indent=2) + "\n" if set(source["network"]) - {"version"} else None
            pending[str(path)] = (before, after)
        remove(config)
        if set(config["network"]) == {"version"}:
          config = None
        removals: dict[str, tuple[str, str | None]] = {}
        # Remove later overrides first; recovery restores the files in load order.
        for path, (before, after) in reversed(pending.items()):
          target = directory / Path(path).name
          if after is None:
            target.unlink()
          else:
            target.write_text(after)
          merged = get_config()
          removals[path] = (before, after)
        result = subprocess.run(["/usr/bin/python3", "-c", parser], input=json.dumps([merged]), capture_output=True, text=True, check=True)
        if json.loads(result.stdout)[0] != config:
          raise OSError("Netplan removal changed unrelated settings")
        return profile_uuids, removals
    except (subprocess.SubprocessError, ValueError, TypeError, AttributeError) as e:
      raise OSError("failed to prepare Netplan profile removal") from e

  def can_remove_ssid(self, ssid: str) -> bool:
    try:
      self._recover_pending_transactions()
      profiles = self.profiles_for_ssid(ssid)
      netplan_uuids, _ = self._netplan_removals(ssid)
      return all(self._can_remove(profile) or not profile.persistent and profile.uuid in netplan_uuids for profile in profiles)
    except (OSError, subprocess.SubprocessError):
      return False

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
    self._recover_pending_transactions()
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
    try:
      profile = self.get(profile_uuid)
      if profile is None or not self.can_mutate(profile_uuid):
        return None
      return self.write(replace(profile, metered=metered))
    except (OSError, subprocess.SubprocessError):
      return None

  def remove_ssid(self, ssid: str) -> bool:
    try:
      self._ensure_directory_access()
      self._recover_pending_transactions()
      self._require_complete_reload()
      netplan_uuids, netplan = self._netplan_removals(ssid)
    except (OSError, subprocess.SubprocessError):
      return False
    profiles = self.profiles_for_ssid(ssid)
    if not profiles:
      return True
    if any(not (self._can_remove(profile) or not profile.persistent and profile.uuid in netplan_uuids) for profile in profiles):
      return False

    token = uuid.uuid4().hex
    staged: list[tuple[str, str]] = []
    runtime_shadows: list[tuple[str, tuple[str, str]]] = []
    marker = os.path.join(self._directory, f".openpilot-forget-committed-{token}")
    try:
      # Runtime profiles must survive a reboot until the forget transaction commits.
      for profile in profiles:
        if not profile.persistent:
          path = os.path.join(self._directory, os.path.basename(profile.path))
          temporary = f"{path}.openpilot-update-{token}"
          backup = f"{path}.openpilot-shadow-{token}"
          subprocess.run(["sudo", "install", "-m", "600", profile.path, temporary], check=True)
          subprocess.run(["sudo", "mv", "-f", temporary, backup], check=True)
          staged.append((profile.path, backup))
      for path, (before, after) in netplan.items():
        if subprocess.run(["sudo", "cat", "--", path], capture_output=True, text=True, check=True).stdout != before:
          raise OSError("Netplan profile changed during forget")
        staged_path = f"{path}.openpilot-forget-{token}"
        if subprocess.run(["sudo", "ln", path, staged_path], check=False).returncode != 0:
          raise OSError("failed to stage Netplan profile")
        staged.append((path, staged_path))
        if after is None:
          command = ["sudo", "rm", "-f", path]
        else:
          replacement = f"{path}.openpilot-netplan-update-{token}"
          with tempfile.NamedTemporaryFile("w") as f:
            f.write(after)
            f.flush()
            subprocess.run(["sudo", "install", "-m", "600", f.name, replacement], check=True)
          command = ["sudo", "mv", "-f", replacement, path]
        if subprocess.run(command, check=False).returncode != 0:
          raise OSError("failed to remove Netplan profile")
      for profile in profiles:
        if profile.persistent:
          staged_path = f"{profile.path}.openpilot-forget-{token}"
          if subprocess.run(["sudo", "mv", "-f", profile.path, staged_path], check=False).returncode != 0:
            raise OSError("failed to stage saved profile")
          staged.append((profile.path, staged_path))
      for profile in profiles:
        runtime_shadow = self._stage_runtime_shadow(profile.uuid, token)
        if runtime_shadow is not None:
          runtime_shadows.append((profile.uuid, runtime_shadow))
      if subprocess.run(["sudo", "touch", marker], check=False).returncode != 0:
        raise OSError("failed to commit profile forget")
    except (OSError, subprocess.SubprocessError):
      try:
        self.recover()
      except (OSError, subprocess.SubprocessError):
        pass
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
