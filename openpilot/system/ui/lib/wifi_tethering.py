import os
import shutil
import subprocess
import time
from pathlib import Path


TETHERING_ADDRESS = "192.168.43.1"
TETHERING_CIDR = f"{TETHERING_ADDRESS}/24"
TETHERING_SUBNET = "192.168.43.0/24"
DNSMASQ_PID_FILE = "/run/openpilot-wifi/dnsmasq.pid"
NAT_CHAIN = "OPENPILOT_TETHERING_NAT"
INPUT_CHAIN = "OPENPILOT_TETHERING_INPUT"
FORWARD_CHAIN = "OPENPILOT_TETHERING_FORWARD"


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
    return False
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


def clear_interface() -> None:
  subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], capture_output=True, check=False)
  subprocess.run(["sudo", "ip", "route", "flush", "dev", "wlan0"], capture_output=True, check=False)


def set_ipv4_forward(enabled: bool) -> None:
  value = "1" if enabled else "0"
  path = Path("/proc/sys/net/ipv4/ip_forward")
  try:
    if path.read_text().strip() == value:
      return
  except OSError:
    pass
  subprocess.run(["sudo", "sysctl", f"net.ipv4.ip_forward={value}"], check=True)


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
  nat, filt, rules, jumps = _commands()
  for command, chain in ((nat, NAT_CHAIN), (filt, INPUT_CHAIN), (filt, FORWARD_CHAIN)):
    subprocess.run([*command, "-N", chain], capture_output=True, check=False)
    subprocess.run([*command, "-F", chain], check=True)
  for rule in rules:
    subprocess.run(rule, check=True)
  for jump in jumps:
    _delete_jump(jump)
    subprocess.run(jump, check=True)


def remove_firewall() -> None:
  nat, filt, _, jumps = _commands()
  for jump in jumps:
    _delete_jump(jump)
  for command, chain in ((nat, NAT_CHAIN), (filt, INPUT_CHAIN), (filt, FORWARD_CHAIN)):
    subprocess.run([*command, "-F", chain], capture_output=True, check=False)
    subprocess.run([*command, "-X", chain], capture_output=True, check=False)


def firewall_ready() -> bool:
  _, _, rules, jumps = _commands()
  checks = [_replace_operation(command, "-C") for command in (*rules, *jumps)]
  return all(subprocess.run(command, capture_output=True, check=False).returncode == 0 for command in checks)
