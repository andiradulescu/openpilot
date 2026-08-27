import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from openpilot.common.utils import atomic_write
from openpilot.system.ui.lib.wpa_ctrl import SecurityType


WPA_CTRL_DIR = "/run/openpilot-wpa"
WPA_CTRL_PATH = os.path.join(WPA_CTRL_DIR, "wlan0")
WPA_PID_FILE = os.path.join(WPA_CTRL_DIR, "wpa_supplicant.pid")
WPA_SUPPLICANT_CONF = "/tmp/wpa_supplicant.conf"
WPA_AP_CONF = "/tmp/wpa_supplicant_ap.conf"
WPA_CTRL_INTERFACE = f"ctrl_interface=DIR={WPA_CTRL_DIR} GROUP=netdev"
_ACQUISITION_READY = "READY\n"
_ACQUISITION_COMMIT = "COMMIT\n"


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


def _format_ssid(ssid: str) -> str:
  return ssid.encode("utf-8", errors="surrogateescape").hex()


def _format_psk(psk: str) -> str:
  if len(psk) == 64 and all(c in "0123456789abcdefABCDEF" for c in psk):
    return psk
  return '"' + psk.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_station_config(networks: list[WpaNetwork], path: str = WPA_SUPPLICANT_CONF) -> None:
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
    pid = int(Path(WPA_PID_FILE).read_text().strip())
    args = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if arg]
  except (OSError, ValueError):
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


def release_networkmanager() -> bool:
  return _set_networkmanager_managed(False)


def restore_networkmanager() -> bool:
  return _set_networkmanager_managed(True)


def prepare_runtime() -> None:
  subprocess.run(["sudo", "install", "-d", "-o", "root", "-g", "netdev", "-m", "775", WPA_CTRL_DIR], check=True)


def start(conf: str) -> bool:
  if is_running(conf):
    return True
  if _owned_pid() is not None:
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

  if result.returncode == 0 and is_running(conf):
    return True

  if is_running(conf) and not stop(conf):
    return False
  if _owned_pid() is None:
    restore_networkmanager()
  return False


def begin_station() -> _StationAcquisition | None:
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
  try:
    ready = proc.stdout.readline()
  except OSError:
    ready = ""
  if ready != _ACQUISITION_READY:
    proc.stdin.close()
    proc.wait()
    return None
  proc.stdout.close()
  return _StationAcquisition(proc)


def _rollback_station() -> bool:
  if not stop(WPA_SUPPLICANT_CONF):
    return False
  return restore_networkmanager()


def _run_station_acquisition(input_stream: TextIO, output_stream: TextIO) -> int:
  was_running = is_running(WPA_SUPPLICANT_CONF)
  if not start(WPA_SUPPLICANT_CONF):
    if not was_running and is_running(WPA_SUPPLICANT_CONF):
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
  pid = _owned_pid(conf)
  if pid is None:
    return True

  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    if _owned_pid(conf) is not None:
      return False
    subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
    return True

  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if _owned_pid(conf) != pid:
      subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
      return True
    time.sleep(0.05)

  return False


if __name__ == "__main__":
  if sys.argv[1:] != ["--station-acquisition"]:
    sys.exit(2)
  sys.exit(_run_station_acquisition(sys.stdin, sys.stdout))
