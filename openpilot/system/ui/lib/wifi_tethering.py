import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.wpa_ctrl import WpaCtrl, parse_status


TETHERING_ADDRESS = "192.168.43.1"
TETHERING_CIDR = f"{TETHERING_ADDRESS}/24"
TETHERING_SUBNET = "192.168.43.0/24"
DNSMASQ_PID_FILE = "/run/openpilot-wifi/dnsmasq.pid"
TETHERING_FORWARD_STATE_FILE = "/run/openpilot-wifi/tethering_ip_forward"
NAT_CHAIN = "OPENPILOT_TETHERING_NAT"
INPUT_CHAIN = "OPENPILOT_TETHERING_INPUT"
FORWARD_CHAIN = "OPENPILOT_TETHERING_FORWARD"
AP_READY_TIMEOUT_SECONDS = 5.0
AP_READY_RETRY_SECONDS = 0.05


def _iptables() -> str:
  return "iptables-legacy" if shutil.which("iptables-legacy") is not None else "iptables"


def _owned_dnsmasq_pid() -> int | None:
  try:
    pid = int(Path(DNSMASQ_PID_FILE).read_text().strip())
    args = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if arg]
  except (OSError, ValueError):
    return None

  if pid <= 1 or not args or os.path.basename(args[0]) != "dnsmasq":
    return None
  required = {
    "--interface=wlan0",
    f"--pid-file={DNSMASQ_PID_FILE}",
    f"--dhcp-option=3,{TETHERING_ADDRESS}",
  }
  return pid if required.issubset(args) else None


def dnsmasq_running() -> bool:
  return _owned_dnsmasq_pid() is not None


def start_dnsmasq() -> bool:
  if dnsmasq_running():
    return True
  subprocess.run(["sudo", "install", "-d", "-m", "755", os.path.dirname(DNSMASQ_PID_FILE)], check=True)
  subprocess.run(["sudo", "rm", "-f", DNSMASQ_PID_FILE], check=True)
  result = subprocess.run([
    "sudo", "dnsmasq",
    "--interface=wlan0",
    "--bind-interfaces",
    "--leasefile-ro",
    "--dhcp-range=192.168.43.2,192.168.43.254,255.255.255.0,1h",
    f"--dhcp-option=3,{TETHERING_ADDRESS}",
    f"--dhcp-option=6,{TETHERING_ADDRESS}",
    f"--pid-file={DNSMASQ_PID_FILE}",
  ], capture_output=True)
  return result.returncode == 0 and dnsmasq_running()


def stop_dnsmasq(timeout: float = 2.0) -> bool:
  pid = _owned_dnsmasq_pid()
  if pid is None:
    return True
  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    if _owned_dnsmasq_pid() is not None:
      return False
    subprocess.run(["sudo", "rm", "-f", DNSMASQ_PID_FILE], check=False)
    return True
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if _owned_dnsmasq_pid() != pid:
      subprocess.run(["sudo", "rm", "-f", DNSMASQ_PID_FILE], check=False)
      return True
    time.sleep(0.05)
  return False


def configure_interface() -> None:
  subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=True)
  subprocess.run(["sudo", "ip", "addr", "add", TETHERING_CIDR, "dev", "wlan0"], check=True)
  subprocess.run(["sudo", "ip", "link", "set", "wlan0", "up"], check=True)


def interface_cleared() -> bool:
  addresses = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", "wlan0"], capture_output=True, text=True, check=False)
  routes = subprocess.run(["ip", "-4", "route", "show", "dev", "wlan0"], capture_output=True, text=True, check=False)
  return addresses.returncode == 0 and routes.returncode == 0 and not addresses.stdout.strip() and not routes.stdout.strip()


def clear_interface() -> bool:
  addresses = subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], capture_output=True, check=False)
  routes = subprocess.run(["sudo", "ip", "route", "flush", "dev", "wlan0"], capture_output=True, check=False)
  return addresses.returncode == 0 and routes.returncode == 0 and interface_cleared()


def interface_configured() -> bool:
  result = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", "wlan0"], capture_output=True, text=True, check=False)
  return result.returncode == 0 and any(TETHERING_CIDR in line.split() for line in result.stdout.splitlines())


def ap_ready() -> bool:
  ctrl = WpaCtrl()
  try:
    ctrl.open()
    status = parse_status(ctrl.request("STATUS"))
  except (OSError, RuntimeError):
    return False
  finally:
    ctrl.close()
  return status.get("mode") == "AP" and status.get("wpa_state") == "COMPLETED"


def wait_for_ap_ready(timeout: float = AP_READY_TIMEOUT_SECONDS) -> bool:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if ap_ready():
      return True
    time.sleep(AP_READY_RETRY_SECONDS)
  return ap_ready()


def interface_ready() -> bool:
  try:
    flags = int(Path("/sys/class/net/wlan0/flags").read_text().strip(), 16)
  except (OSError, ValueError):
    return False
  return bool(flags & 1) and interface_configured() and ap_ready()  # IFF_UP


def get_ipv4_forward() -> bool:
  value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
  if value == "0":
    return False
  if value == "1":
    return True
  raise RuntimeError("invalid IPv4 forwarding state")


def set_ipv4_forward(enabled: bool) -> None:
  value = "1" if enabled else "0"
  if get_ipv4_forward() == enabled:
    return
  result = subprocess.run(["sudo", "sysctl", f"net.ipv4.ip_forward={value}"], capture_output=True, check=False)
  if result.returncode != 0:
    raise RuntimeError("failed to update IPv4 forwarding")


def _read_previous_ipv4_forward() -> bool | None:
  try:
    value = Path(TETHERING_FORWARD_STATE_FILE).read_text().strip()
  except FileNotFoundError:
    return None
  if value == "0":
    return False
  if value == "1":
    return True
  raise ValueError("invalid tethering IPv4 forwarding state")


def _write_previous_ipv4_forward(enabled: bool) -> None:
  value = "1\n" if enabled else "0\n"
  runtime_dir = os.path.dirname(TETHERING_FORWARD_STATE_FILE)
  subprocess.run(["sudo", "install", "-d", "-m", "755", runtime_dir], check=True)
  with tempfile.NamedTemporaryFile("w", delete=False) as f:
    f.write(value)
    path = f.name
  stage_path = f"{TETHERING_FORWARD_STATE_FILE}.{uuid.uuid4().hex}"
  try:
    subprocess.run(["sudo", "install", "-m", "644", path, stage_path], check=True)
    subprocess.run(["sudo", "mv", "-f", stage_path, TETHERING_FORWARD_STATE_FILE], check=True)
  finally:
    os.unlink(path)
    subprocess.run(["sudo", "rm", "-f", stage_path], check=False)


def _clear_previous_ipv4_forward() -> bool:
  return subprocess.run(["sudo", "rm", "-f", TETHERING_FORWARD_STATE_FILE], check=False).returncode == 0


def _replace_operation(command: list[str], operation: str) -> list[str]:
  result = command.copy()
  result[result.index("-A")] = operation
  return result


def _delete_jump(command: list[str]) -> None:
  delete = _replace_operation(command, "-D")
  while subprocess.run(delete, capture_output=True, check=False).returncode == 0:
    pass


def _commands():
  iptables = _iptables()
  nat = ["sudo", iptables, "-t", "nat"]
  filt = ["sudo", iptables]
  rules = (
    [*nat, "-A", NAT_CHAIN, "-s", TETHERING_SUBNET, "!", "-d", TETHERING_SUBNET, "-j", "MASQUERADE"],
    [*filt, "-A", INPUT_CHAIN, "-i", "wlan0", "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
    [*filt, "-A", INPUT_CHAIN, "-i", "wlan0", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
    [*filt, "-A", INPUT_CHAIN, "-i", "wlan0", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
    [*filt, "-A", FORWARD_CHAIN, "-i", "wlan0", "-s", TETHERING_SUBNET, "-j", "ACCEPT"],
    [*filt, "-A", FORWARD_CHAIN, "-o", "wlan0", "-d", TETHERING_SUBNET, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
  )
  jumps = (
    [*nat, "-A", "POSTROUTING", "-j", NAT_CHAIN],
    [*filt, "-A", "INPUT", "-j", INPUT_CHAIN],
    [*filt, "-A", "FORWARD", "-j", FORWARD_CHAIN],
  )
  return nat, filt, rules, jumps


def install_firewall() -> None:
  if not wait_for_ap_ready():
    raise RuntimeError("tethering AP failed to activate")
  nat, filt, rules, jumps = _commands()
  for command, chain in ((nat, NAT_CHAIN), (filt, INPUT_CHAIN), (filt, FORWARD_CHAIN)):
    subprocess.run([*command, "-N", chain], capture_output=True, check=False)
    subprocess.run([*command, "-F", chain], check=True)
  for rule in rules:
    subprocess.run(rule, check=True)
  for jump in jumps:
    _delete_jump(jump)
    subprocess.run(jump, check=True)


def remove_firewall() -> bool:
  nat, filt, _, jumps = _commands()
  for jump in jumps:
    _delete_jump(jump)
  for command, chain in ((nat, NAT_CHAIN), (filt, INPUT_CHAIN), (filt, FORWARD_CHAIN)):
    subprocess.run([*command, "-F", chain], capture_output=True, check=False)
    subprocess.run([*command, "-X", chain], capture_output=True, check=False)
  return not firewall_present()


def firewall_ready() -> bool:
  if not interface_ready():
    return False
  _, _, rules, jumps = _commands()
  checks = [_replace_operation(command, "-C") for command in (*rules, *jumps)]
  return all(subprocess.run(command, capture_output=True, check=False).returncode == 0 for command in checks)


def firewall_present() -> bool:
  nat, filt, _, _ = _commands()
  checks = (
    [*nat, "-S", NAT_CHAIN],
    [*filt, "-S", INPUT_CHAIN],
    [*filt, "-S", FORWARD_CHAIN],
  )
  return not all(subprocess.run(command, capture_output=True, check=False).returncode == 1 for command in checks)


class TetheringSession:
  def __init__(self):
    self._previous_ipv4_forward: bool | None = None

  def adopt(self) -> bool:
    if self._previous_ipv4_forward is not None:
      return dnsmasq_running() and firewall_ready()
    try:
      previous_ipv4_forward = _read_previous_ipv4_forward()
    except (OSError, ValueError):
      return False
    if previous_ipv4_forward is None or not dnsmasq_running() or not firewall_ready():
      return False
    self._previous_ipv4_forward = previous_ipv4_forward
    return True

  def start(self, ipv4_forward: bool) -> bool:
    if self._previous_ipv4_forward is not None:
      return dnsmasq_running() and firewall_ready()

    try:
      previous_ipv4_forward = get_ipv4_forward()
      _write_previous_ipv4_forward(previous_ipv4_forward)
    except (OSError, subprocess.SubprocessError, RuntimeError):
      return False
    self._previous_ipv4_forward = previous_ipv4_forward
    try:
      configure_interface()
      install_firewall()
      set_ipv4_forward(ipv4_forward)
      if not start_dnsmasq():
        raise RuntimeError("failed to start tethering dnsmasq")
      return True
    except (OSError, subprocess.SubprocessError, RuntimeError):
      self._rollback_start()
      return False

  def _rollback_start(self) -> None:
    if dnsmasq_running() and not stop_dnsmasq():
      return
    if not remove_firewall():
      return
    if not clear_interface():
      return
    if self._previous_ipv4_forward is not None:
      try:
        set_ipv4_forward(self._previous_ipv4_forward)
      except (OSError, subprocess.SubprocessError, RuntimeError):
        return
    if not _clear_previous_ipv4_forward():
      return
    self._previous_ipv4_forward = None

  def stop(self) -> bool:
    if not stop_dnsmasq():
      return False
    if not remove_firewall():
      return False
    if not clear_interface():
      return False
    previous_ipv4_forward = self._previous_ipv4_forward
    if previous_ipv4_forward is not None:
      try:
        set_ipv4_forward(previous_ipv4_forward)
      except (OSError, subprocess.SubprocessError, RuntimeError):
        cloudlog.exception("Failed to restore IPv4 forwarding after tethering")
        return False
    if not _clear_previous_ipv4_forward():
      return False
    self._previous_ipv4_forward = None
    return True

  @staticmethod
  def cleanup_stale() -> bool:
    try:
      previous_ipv4_forward = _read_previous_ipv4_forward()
    except (OSError, ValueError):
      return False
    if not dnsmasq_running() and not firewall_present() and not interface_configured() and previous_ipv4_forward is None:
      return True
    if not stop_dnsmasq():
      return False
    if not remove_firewall():
      return False
    if not clear_interface():
      return False
    try:
      set_ipv4_forward(False if previous_ipv4_forward is None else previous_ipv4_forward)
    except (OSError, subprocess.SubprocessError, RuntimeError):
      return False
    if not _clear_previous_ipv4_forward():
      return False
    return True
