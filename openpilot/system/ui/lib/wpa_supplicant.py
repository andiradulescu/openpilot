import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from openpilot.common.utils import atomic_write
from openpilot.system.ui.lib.wpa_ctrl import SecurityType


WPA_CTRL_DIR = "/run/openpilot-wpa"
WPA_CTRL_PATH = os.path.join(WPA_CTRL_DIR, "wlan0")
WPA_PID_FILE = os.path.join(WPA_CTRL_DIR, "wpa_supplicant.pid")
WPA_SUPPLICANT_CONF = "/tmp/wpa_supplicant.conf"
WPA_AP_CONF = "/tmp/wpa_supplicant_ap.conf"
WPA_CTRL_INTERFACE = f"ctrl_interface=DIR={WPA_CTRL_DIR} GROUP=netdev"


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


def prepare_runtime() -> None:
  subprocess.run(["sudo", "install", "-d", "-o", "root", "-g", "netdev", "-m", "775", WPA_CTRL_DIR], check=True)


def start(conf: str) -> bool:
  if is_running(conf):
    return True

  prepare_runtime()
  if _owned_pid() is not None:
    return False

  subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=True)
  result = subprocess.run([
    "sudo", "wpa_supplicant", "-B", "-i", "wlan0", "-c", conf, "-P", WPA_PID_FILE,
  ], capture_output=True)
  return result.returncode == 0 and is_running(conf)


def stop(conf: str, timeout: float = 2.0) -> bool:
  pid = _owned_pid(conf)
  if pid is None:
    return True

  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    return False

  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if _owned_pid(conf) != pid:
      subprocess.run(["sudo", "rm", "-f", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
      return True
    time.sleep(0.05)

  return False
