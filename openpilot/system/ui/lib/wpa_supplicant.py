import os
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from openpilot.common.utils import atomic_write
from openpilot.system.ui.lib.wpa_ctrl import SecurityType, WpaCtrl, parse_status


WPA_CTRL_DIR = "/run/openpilot-wpa"
WPA_CTRL_PATH = os.path.join(WPA_CTRL_DIR, "wlan0")
WPA_PID_FILE = os.path.join(WPA_CTRL_DIR, "wpa_supplicant.pid")
WPA_SUPPLICANT_CONF = "/tmp/wpa_supplicant.conf"
WPA_AP_CONF = "/tmp/wpa_supplicant_ap.conf"
WPA_CTRL_INTERFACE = f"ctrl_interface=DIR={WPA_CTRL_DIR} GROUP=netdev"
_ACQUISITION_READY = "READY\n"
_ACQUISITION_COMMIT = "COMMIT\n"
_ACQUISITION_READY_TIMEOUT = 10.0
_ACQUISITION_STOP_TIMEOUT = 1.0
_NETWORKMANAGER_RESTORE_ATTEMPTS = 3
_NETWORKMANAGER_RESTORE_RETRY_SECONDS = 0.1


class _StationAcquisition:
  def __init__(self, proc: subprocess.Popen[str]):
    self._proc = proc
    self._finished = False

  def _finish(self, commit: bool) -> bool:
    if self._finished:
      return False
    self._finished = True

    if self._proc.stdin is None:
      return False
    sent = True
    try:
      if commit:
        self._proc.stdin.write(_ACQUISITION_COMMIT)
        self._proc.stdin.flush()
    except OSError:
      sent = False
    try:
      self._proc.stdin.close()
    except OSError:
      sent = False
    try:
      returncode = self._proc.wait()
    except (OSError, subprocess.SubprocessError):
      return False
    return sent and returncode == 0

  def commit(self) -> bool:
    return self._finish(True)

  def rollback(self) -> bool:
    return self._finish(False)


@dataclass(frozen=True)
class WpaNetwork:
  ssid: str
  security: SecurityType
  psk: str = ""
  hidden: bool = False
  profile_uuid: str = ""
  priority: int = 0
  bssid: str = ""
  disabled: bool = False


def _format_ssid(ssid: str) -> str:
  return ssid.encode("utf-8", errors="surrogateescape").hex()


def _format_psk(psk: str) -> str:
  if len(psk) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk):
    return psk
  return '"' + psk.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_station_config(networks: list[WpaNetwork], path: str = WPA_SUPPLICANT_CONF) -> None:
  live_profile_uuid = _active_station_profile_uuid()
  lines = [WPA_CTRL_INTERFACE, "update_config=0", "p2p_disabled=1", ""]
  for network in networks:
    lines += ["network={", f"  ssid={_format_ssid(network.ssid)}"]
    if network.security == SecurityType.WPA:
      lines += [f"  psk={_format_psk(network.psk)}", "  key_mgmt=WPA-PSK"]
    else:
      lines.append("  key_mgmt=NONE")
    if network.hidden:
      lines.append("  scan_ssid=1")
    if network.bssid:
      lines.append(f"  bssid={network.bssid}")
    if network.profile_uuid:
      lines.append(f'  id_str="{network.profile_uuid}"')
    if network.disabled and network.profile_uuid != live_profile_uuid:
      lines.append("  disabled=1")
    lines += [f"  priority={network.priority}", "}", ""]

  with atomic_write(path, overwrite=True) as f:
    f.write("\n".join(lines))


def write_ap_config(ssid: str, password: str, path: str = WPA_AP_CONF) -> None:
  lines = [
    WPA_CTRL_INTERFACE,
    "update_config=0",
    "p2p_disabled=1",
    "network={",
    f"  ssid={_format_ssid(ssid)}",
    "  mode=2",
    "  frequency=2412",
    "  key_mgmt=WPA-PSK",
    f"  psk={_format_psk(password)}",
    "  proto=RSN",
    "  pairwise=CCMP",
    "  group=CCMP",
    "}",
    "",
  ]
  with atomic_write(path, overwrite=True) as f:
    f.write("\n".join(lines))


def _owned_pid(conf: str | None = None) -> int | None:
  try:
    pid_text = Path(WPA_PID_FILE).read_text().strip()
  except FileNotFoundError:
    return None
  try:
    pid = int(pid_text)
  except ValueError as e:
    raise OSError("invalid wpa_supplicant ownership PID file") from e
  try:
    args = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if arg]
  except FileNotFoundError:
    return None

  def arg_after(flag: str) -> str | None:
    try:
      return args[args.index(flag) + 1]
    except (ValueError, IndexError):
      return None

  active_conf = arg_after("-c")
  if pid <= 1 or not args or os.path.basename(args[0]) != "wpa_supplicant":
    return None
  if arg_after("-i") != "wlan0" or arg_after("-P") != WPA_PID_FILE:
    return None
  if active_conf not in (WPA_SUPPLICANT_CONF, WPA_AP_CONF):
    return None
  if conf is not None and active_conf != conf:
    return None
  return pid


def is_running(conf: str) -> bool:
  return _owned_pid(conf) is not None


def _active_station_profile_uuid() -> str | None:
  if not is_running(WPA_SUPPLICANT_CONF):
    return None
  ctrl = WpaCtrl()
  try:
    ctrl.open()
    status = parse_status(ctrl.request("STATUS"))
  except RuntimeError as e:
    raise OSError("failed to inspect live station profile") from e
  finally:
    ctrl.close()
  if status.get("wpa_state") != "COMPLETED":
    return None
  profile_uuid = status.get("id_str", "").strip('"')
  return profile_uuid or None


def _set_networkmanager_managed(managed: bool) -> bool:
  nmcli = shutil.which("nmcli")
  if nmcli is None:
    return True
  value = "yes" if managed else "no"
  try:
    result = subprocess.run(["sudo", nmcli, "dev", "set", "wlan0", "managed", value], capture_output=True)
  except OSError:
    return False
  return result.returncode == 0


def _reload_networkmanager_connections() -> bool:
  nmcli = shutil.which("nmcli")
  if nmcli is None:
    return True
  try:
    result = subprocess.run(["sudo", nmcli, "connection", "reload"], capture_output=True)
  except OSError:
    return False
  return result.returncode == 0


def release_networkmanager() -> bool:
  return _set_networkmanager_managed(False)


def restore_networkmanager() -> bool:
  try:
    if _owned_pid() is not None:
      return False
  except OSError:
    return False
  for attempt in range(_NETWORKMANAGER_RESTORE_ATTEMPTS):
    if _reload_networkmanager_connections() and _set_networkmanager_managed(True):
      return True
    if attempt + 1 < _NETWORKMANAGER_RESTORE_ATTEMPTS:
      time.sleep(_NETWORKMANAGER_RESTORE_RETRY_SECONDS)
  return False


def prepare_runtime() -> None:
  subprocess.run(["sudo", "install", "-d", "-o", "root", "-g", "netdev", "-m", "775", WPA_CTRL_DIR], check=True)


def start(conf: str) -> bool:
  try:
    if is_running(conf):
      return True
    if _owned_pid() is not None:
      return False
  except OSError:
    return False

  try:
    prepare_runtime()
    subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=True)
  except (OSError, subprocess.SubprocessError):
    return False

  if not release_networkmanager():
    return False

  try:
    result = subprocess.run([
      "sudo", "wpa_supplicant", "-B", "-i", "wlan0", "-c", conf, "-P", WPA_PID_FILE,
    ], capture_output=True)
  except OSError:
    restore_networkmanager()
    return False

  try:
    running = is_running(conf)
  except OSError:
    return False
  if result.returncode == 0 and running:
    return True

  if running and not stop(conf):
    return False
  try:
    owner = _owned_pid()
  except OSError:
    return False
  if owner is None:
    restore_networkmanager()
  return False


def _wait_for_acquisition_ready(proc: subprocess.Popen[str], timeout: float = _ACQUISITION_READY_TIMEOUT) -> bool:
  assert proc.stdout is not None
  target = _ACQUISITION_READY.encode()
  ready = b""
  deadline = time.monotonic() + timeout
  fd = proc.stdout.fileno()
  while len(ready) < len(target):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      return False
    try:
      readable, _, _ = select.select([fd], [], [], remaining)
      if not readable:
        return False
      chunk = os.read(fd, len(target) - len(ready))
    except (OSError, ValueError):
      return False
    if not chunk:
      return False
    ready += chunk
  return ready == target


def _terminate_station_acquisition(proc: subprocess.Popen[str], timeout: float = _ACQUISITION_STOP_TIMEOUT) -> None:
  pgid = proc.pid
  for signal_name in ("-TERM", "-KILL"):
    try:
      subprocess.run(["sudo", "kill", signal_name, "--", f"-{pgid}"], check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
      pass
    try:
      proc.wait(timeout=timeout)
    except (OSError, subprocess.SubprocessError):
      pass
    try:
      os.killpg(pgid, 0)
    except ProcessLookupError:
      return
    except PermissionError:
      pass


def begin_station() -> _StationAcquisition | None:
  try:
    was_running = is_running(WPA_SUPPLICANT_CONF)
  except OSError:
    return None
  try:
    proc = subprocess.Popen(
      [sys.executable, "-m", __name__, "--station-acquisition"],
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      text=True,
      start_new_session=True,
    )
  except OSError:
    return None

  assert proc.stdin is not None and proc.stdout is not None
  if not _wait_for_acquisition_ready(proc):
    if proc.poll() is None:
      _terminate_station_acquisition(proc)
      if not was_running:
        _rollback_station()
    try:
      proc.stdin.close()
    except OSError:
      pass
    try:
      proc.stdout.close()
    except OSError:
      pass
    return None
  proc.stdout.close()
  return _StationAcquisition(proc)


def _rollback_station() -> bool:
  if not stop(WPA_SUPPLICANT_CONF):
    return False
  return restore_networkmanager()


def _run_station_acquisition(input_stream: TextIO, output_stream: TextIO) -> int:
  try:
    was_running = is_running(WPA_SUPPLICANT_CONF)
  except OSError:
    return 1
  if not start(WPA_SUPPLICANT_CONF):
    try:
      running = is_running(WPA_SUPPLICANT_CONF)
    except OSError:
      return 1
    if not was_running and running:
      _rollback_station()
    return 1

  try:
    output_stream.write(_ACQUISITION_READY)
    output_stream.flush()
    if input_stream.readline() == _ACQUISITION_COMMIT:
      return 0
  except OSError:
    pass

  if was_running:
    return 0
  return 0 if _rollback_station() else 1


def stop(conf: str, timeout: float = 2.0) -> bool:
  try:
    pid = _owned_pid(conf)
  except OSError:
    return False
  if pid is None:
    return True

  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    try:
      remaining_pid = _owned_pid(conf)
    except OSError:
      return False
    if remaining_pid is not None:
      return False
    subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
    return True

  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    try:
      remaining_pid = _owned_pid(conf)
    except OSError:
      return False
    if remaining_pid != pid:
      subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
      return True
    time.sleep(0.05)

  return False


if __name__ == "__main__":
  if sys.argv[1:] != ["--station-acquisition"]:
    sys.exit(2)
  sys.exit(_run_station_acquisition(sys.stdin, sys.stdout))
