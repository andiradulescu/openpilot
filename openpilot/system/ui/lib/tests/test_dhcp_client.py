import os
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import call, patch

from openpilot.system.ui.lib import dhcp_client
from openpilot.system.ui.lib.dhcp_client import DhcpClient


class TestDhcpClient(TestCase):
  def test_owned_pid_checks_command_line(self):
    client = DhcpClient()
    command = "\0".join((
      "/sbin/udhcpc", "-i", "wlan0", "-f", "-p", client._pid_file, "-s", dhcp_client.DHCP_SCRIPT, "",
    )).encode()
    with (
      patch.object(Path, "read_text", return_value="123"),
      patch.object(Path, "read_bytes", return_value=command),
    ):
      assert client._owned_pid() == 123

  def test_stop_does_not_forget_live_owned_process(self):
    client = DhcpClient()
    with (
      patch.object(client, "_owned_pid", return_value=123),
      patch.object(dhcp_client.os, "getpgid", return_value=456),
      patch.object(dhcp_client.os, "getpgrp", return_value=1),
      patch.object(dhcp_client.subprocess, "run") as run,
      patch.object(dhcp_client.time, "monotonic", side_effect=[0.0, 0.0, 4.0, 4.0, 8.0]),
      patch.object(dhcp_client.time, "sleep"),
    ):
      run.return_value.returncode = 0
      assert not client.stop(timeout=3.0)

    assert call(["sudo", "rm", "-f", client._pid_file], check=False) not in run.call_args_list

  def test_stop_flushes_lease_after_exit(self):
    client = DhcpClient()
    with (
      patch.object(client, "_owned_pid", side_effect=[123, None, None, None]),
      patch.object(dhcp_client.os, "getpgid", return_value=456),
      patch.object(dhcp_client.os, "getpgrp", return_value=1),
      patch.object(dhcp_client.subprocess, "run") as run,
      patch.object(dhcp_client.time, "monotonic", return_value=0.0),
    ):
      run.return_value.returncode = 0
      assert client.stop()

    assert run.call_args_list[-5:] == [
      call(["sudo", "rm", "-f", client._pid_file], check=False),
      call(["sudo", "ip", "-4", "route", "flush", "dev", "wlan0"], capture_output=True, check=False),
      call(["sudo", "ip", "-4", "addr", "flush", "dev", "wlan0"], capture_output=True, check=False),
      call(["sudo", "ip", "-6", "addr", "flush", "dev", "wlan0", "scope", "global"], capture_output=True, check=False),
      call(["sudo", "ip", "-6", "route", "flush", "dev", "wlan0"], capture_output=True, check=False),
    ]

  def test_clear_ipv6_accepts_empty_route_table(self):
    client = DhcpClient()
    addresses = subprocess.CompletedProcess([], 0, b"", b"")
    routes = subprocess.CompletedProcess([], 2, b"", b"Failed to send flush request: No such process\n")
    with patch.object(dhcp_client.subprocess, "run", side_effect=[addresses, routes]):
      assert client.clear_ipv6()

  def test_clear_ipv6_rejects_other_route_failure(self):
    client = DhcpClient()
    addresses = subprocess.CompletedProcess([], 0, b"", b"")
    routes = subprocess.CompletedProcess([], 2, b"", b"RTNETLINK answers: Operation not permitted\n")
    with patch.object(dhcp_client.subprocess, "run", side_effect=[addresses, routes]):
      assert not client.clear_ipv6()

  def test_ready_requires_address_and_metric_route(self):
    client = DhcpClient()
    address = subprocess.CompletedProcess([], 0, "1: wlan0 inet 10.0.0.2/24 scope global wlan0\n", "")
    route = subprocess.CompletedProcess([], 0, "default via 10.0.0.1 dev wlan0 metric 600\n", "")
    with patch.object(dhcp_client.subprocess, "run", side_effect=[address, route]):
      assert client.ready()

  def test_script_uses_installed_classless_default_gateway(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      default_script = root / "default.script"
      default_script.write_text("#!/bin/sh\nexit 0\n")
      default_script.chmod(0o755)

      log = root / "ip.log"
      ip = root / "ip"
      ip.write_text(f"""#!/bin/sh
if [ \"$*\" = \"-4 route show default dev wlan0\" ]; then
  echo 'default via 10.0.0.1 dev wlan0 metric 100'
  exit 0
fi
echo \"$*\" >> {log}
""")
      ip.chmod(0o755)

      env = os.environ.copy()
      env.update({
        "UDHCPC_DEFAULT_SCRIPT": str(default_script),
        "PATH": f"{root}:{env['PATH']}",
        "interface": "wlan0",
        "router": "",
      })
      subprocess.run([dhcp_client.DHCP_SCRIPT, "bound"], env=env, check=True)

      assert "-4 route replace default via 10.0.0.1 dev wlan0 metric 600" in log.read_text().splitlines()
