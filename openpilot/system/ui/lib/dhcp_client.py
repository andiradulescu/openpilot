import os
import subprocess
import time
from pathlib import Path


DHCP_SCRIPT = os.path.join(os.path.dirname(__file__), "udhcpc.script")
DHCP_RUNTIME_DIR = "/run/openpilot-wifi"


class DhcpClient:
  def __init__(self, iface: str = "wlan0"):
    self._iface = iface
    self._pid_file = os.path.join(DHCP_RUNTIME_DIR, f"udhcpc-{iface}.pid")
    self._proc: subprocess.Popen | None = None

  def _owned_pid(self) -> int | None:
    try:
      pid = int(Path(self._pid_file).read_text().strip())
      args = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if arg]
    except (OSError, ValueError):
      return None

    def arg_after(flag: str) -> str | None:
      try:
        return args[args.index(flag) + 1]
      except (ValueError, IndexError):
        return None

    if pid <= 1 or not args or os.path.basename(args[0]) != "udhcpc":
      return None
    if arg_after("-i") != self._iface or arg_after("-p") != self._pid_file or arg_after("-s") != DHCP_SCRIPT:
      return None
    return pid

  @property
  def running(self) -> bool:
    if self._proc is not None and self._proc.poll() is None:
      return True
    return self._owned_pid() is not None

  def start(self) -> bool:
    if self.running:
      return True
    try:
      subprocess.run(["sudo", "install", "-d", "-o", "root", "-g", "root", "-m", "755", DHCP_RUNTIME_DIR], check=True)
      subprocess.run(["sudo", "rm", "-f", self._pid_file], check=False)
      self._proc = subprocess.Popen(
        ["sudo", "udhcpc", "-i", self._iface, "-f", "-t", "5", "-T", "3", "-p", self._pid_file, "-s", DHCP_SCRIPT],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
      )
    except (OSError, subprocess.SubprocessError):
      self._proc = None
      try:
        subprocess.run(["sudo", "rm", "-f", self._pid_file], check=False)
      except OSError:
        pass
      return False
    return True

  def stop(self, timeout: float = 3.0) -> bool:
    pid = self._owned_pid()
    if pid is not None:
      try:
        pgid = os.getpgid(pid)
      except OSError:
        pgid = None
      if pgid is not None and pgid > 1 and pgid != os.getpgrp():
        subprocess.run(["sudo", "kill", "-TERM", "--", f"-{pgid}"], check=False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self._owned_pid() == pid:
          time.sleep(0.05)
        if self._owned_pid() == pid:
          subprocess.run(["sudo", "kill", "-KILL", "--", f"-{pgid}"], check=False)
          deadline = time.monotonic() + timeout
          while time.monotonic() < deadline and self._owned_pid() == pid:
            time.sleep(0.05)
        if self._owned_pid() == pid:
          return False
    elif self._proc is not None and self._proc.poll() is None:
      self._proc.terminate()
      try:
        self._proc.wait(timeout=timeout)
      except subprocess.TimeoutExpired:
        self._proc.kill()
        self._proc.wait(timeout=timeout)

    self._proc = None
    subprocess.run(["sudo", "rm", "-f", self._pid_file], check=False)
    self.clear_ipv4()
    return True

  def clear_ipv4(self) -> None:
    subprocess.run(["sudo", "ip", "-4", "route", "flush", "dev", self._iface], capture_output=True, check=False)
    subprocess.run(["sudo", "ip", "-4", "addr", "flush", "dev", self._iface], capture_output=True, check=False)

  def clear_ipv6(self) -> None:
    subprocess.run(["sudo", "ip", "-6", "addr", "flush", "dev", self._iface, "scope", "global"], capture_output=True, check=False)
    subprocess.run(["sudo", "ip", "-6", "route", "flush", "dev", self._iface], capture_output=True, check=False)

  def ipv4_address(self) -> str:
    result = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", self._iface, "scope", "global"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
      return ""
    for line in result.stdout.splitlines():
      fields = line.split()
      if "inet" in fields:
        return fields[fields.index("inet") + 1].split("/", 1)[0]
    return ""

  def ready(self) -> bool:
    if not self.ipv4_address():
      return False
    result = subprocess.run(["ip", "-4", "route", "show", "default", "dev", self._iface], capture_output=True, text=True, check=False)
    return result.returncode == 0 and any("metric 600" in line for line in result.stdout.splitlines())
