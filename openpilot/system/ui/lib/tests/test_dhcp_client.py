import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from openpilot.system.ui.lib import dhcp_client as dhcp_client_module
from openpilot.system.ui.lib.dhcp_client import DhcpClient


def stop_after_route_queries(client, check_output, query_count):
  def wait(_):
    if check_output.call_count >= query_count:
      client._metric_stop.set()
    return False
  return wait


class TestDhcpClient(TestCase):
  @staticmethod
  def route_commands(gateway):
    route = ["default", "via", gateway, "dev", "wlan0"]
    return [
      ["sudo", "ip", "-4", "route", "replace", *route, "metric", "600"],
      ["sudo", "ip", "-4", "route", "del", *route, "metric", "0"],
    ]

  def monitor_routes(self, outputs, run_results=None):
    client = DhcpClient()
    with (
      patch.object(dhcp_client_module.subprocess, "check_output", side_effect=outputs) as check_output,
      patch.object(dhcp_client_module.subprocess, "run", side_effect=run_results) as run,
      patch.object(client._metric_stop, "wait") as wait,
    ):
      wait.side_effect = stop_after_route_queries(client, check_output, len(outputs))
      client._fix_default_route_metric()
    return run, wait

  def test_adopt_existing_udhcpc_without_restarting_it(self):
    client = DhcpClient()
    with (
      patch.object(dhcp_client_module.subprocess, "run", return_value=MagicMock(returncode=0)) as run,
      patch.object(dhcp_client_module.subprocess, "Popen") as popen,
      patch.object(dhcp_client_module.threading, "Thread") as thread,
    ):
      assert client.adopt()

      run.assert_called_once_with(["pgrep", "-f", "^udhcpc -i wlan0( |$)"], capture_output=True, check=False)
      popen.assert_not_called()
      assert [item.kwargs["target"] for item in thread.call_args_list] == [
        client._monitor_client,
        client._fix_default_route_metric,
      ]
      assert thread.return_value.start.call_count == 2

  def test_start_detaches_udhcpc_from_ui_session(self):
    client = DhcpClient()
    with (
      patch.object(client, "stop") as stop,
      patch.object(dhcp_client_module.subprocess, "run") as run,
      patch.object(dhcp_client_module.subprocess, "Popen") as popen,
      patch.object(dhcp_client_module.threading, "Thread") as thread,
    ):
      client.start()

      stop.assert_called_once()
      assert [call.args[0] for call in run.call_args_list] == [
        ["sudo", "pkill", "-f", "udhcpc.*-i wlan0"],
        ["sudo", "ip", "-4", "route", "flush", "dev", "wlan0"],
        ["sudo", "ip", "-4", "addr", "flush", "dev", "wlan0"],
      ]
      popen.assert_called_once_with(
        ["sudo", "udhcpc", "-i", "wlan0", "-f", "-t", "5", "-T", "3"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
      )
      assert [item.kwargs["target"] for item in thread.call_args_list] == [
        client._monitor_client,
        client._fix_default_route_metric,
      ]
      assert thread.return_value.start.call_count == 2

  def test_failed_launch_starts_client_monitor(self):
    client = DhcpClient()
    with (
      patch.object(client, "stop"),
      patch.object(dhcp_client_module.subprocess, "run"),
      patch.object(dhcp_client_module.subprocess, "Popen", side_effect=OSError("exec failed")),
      patch.object(dhcp_client_module.threading, "Thread") as thread,
    ):
      client.start()

    targets = [item.kwargs["target"] for item in thread.call_args_list]
    assert client._monitor_client in targets

  def test_start_flushes_stale_lease_before_spawning_client(self):
    client = DhcpClient()
    events = []
    with (
      patch.object(client, "stop"),
      patch.object(dhcp_client_module.subprocess, "run"),
      patch.object(client, "_flush_address", side_effect=lambda: events.append("flush")),
      patch.object(client, "_spawn", side_effect=lambda: events.append("spawn") or True),
      patch.object(client, "_start_client_thread"),
      patch.object(client, "_start_metric_thread"),
    ):
      client.start()

    assert events == ["flush", "spawn"]

  def test_exited_client_is_restarted(self):
    client = DhcpClient()
    client._proc = MagicMock()
    client._proc.poll.return_value = 1

    with (
      patch.object(client._client_stop, "wait", side_effect=[False, True]),
      patch.object(
        dhcp_client_module.subprocess,
        "run",
        return_value=MagicMock(returncode=1),
      ),
      patch.object(client, "_flush_address") as flush_address,
      patch.object(client, "_spawn", return_value=True) as spawn,
      patch.object(client, "_start_metric_thread") as start_metric_thread,
    ):
      client._monitor_client()

    flush_address.assert_called_once()
    spawn.assert_called_once()
    start_metric_thread.assert_called_once()

  def test_metric_zero_route_is_replaced_with_wifi_metric(self):
    cases = (
      [
        "default via 192.168.1.1 dev wlan0 metric 0\n",
        "default via 192.168.1.1 dev wlan0 metric 600\n",
      ],
      [
        "default via 192.168.1.1 dev wlan0 metric 600\ndefault via 192.168.1.1 dev wlan0 metric 0\n",
        "default via 192.168.1.1 dev wlan0 metric 600\n",
      ],
    )
    for outputs in cases:
      with self.subTest(outputs=outputs):
        run, _ = self.monitor_routes(
          outputs,
          [
            MagicMock(returncode=0),
            MagicMock(returncode=0),
          ],
        )
        assert [item.args[0] for item in run.call_args_list] == self.route_commands("192.168.1.1")

  def test_failed_route_replacement_is_retried(self):
    metric_zero = "default via 192.168.1.1 dev wlan0 metric 0\n"
    run, _ = self.monitor_routes(
      [
        metric_zero,
        metric_zero,
        "default via 192.168.1.1 dev wlan0 metric 600\n",
      ],
      [
        MagicMock(returncode=1),
        MagicMock(returncode=0),
        MagicMock(returncode=0),
      ],
    )
    assert [item.args[0] for item in run.call_args_list] == [
      self.route_commands("192.168.1.1")[0],
      *self.route_commands("192.168.1.1"),
    ]

  def test_existing_wifi_metric_is_left_untouched(self):
    run, _ = self.monitor_routes(
      ["default via 192.168.1.1 dev wlan0 metric 600\n"],
    )
    run.assert_not_called()

  def test_metric_is_corrected_after_dhcp_renewal(self):
    run, wait = self.monitor_routes(
      [
        "default via 192.168.1.1 dev wlan0 metric 600\n",
        "default via 192.168.1.254 dev wlan0 metric 0\n",
        "default via 192.168.1.254 dev wlan0 metric 600\n",
      ],
      [
        MagicMock(returncode=0),
        MagicMock(returncode=0),
      ],
    )
    assert [item.args[0] for item in run.call_args_list] == self.route_commands("192.168.1.254")
    assert wait.call_args_list == [
      call(DhcpClient.ROUTE_MONITOR_INTERVAL_SECONDS),
      call(DhcpClient.ROUTE_RETRY_INTERVAL_SECONDS),
      call(DhcpClient.ROUTE_MONITOR_INTERVAL_SECONDS),
    ]

  def test_stop_cleans_only_wlan_dhcp_routes_and_address(self):
    client = DhcpClient()
    client._proc = MagicMock()
    with patch.object(dhcp_client_module.subprocess, "run") as run:
      client.stop()

      assert client._proc is None
      assert [call.args[0] for call in run.call_args_list] == [
        ["sudo", "pkill", "-f", "udhcpc.*-i wlan0"],
        ["sudo", "ip", "-4", "route", "flush", "dev", "wlan0"],
        ["sudo", "ip", "-4", "addr", "flush", "dev", "wlan0"],
      ]

  def test_clear_ipv6_state_cleans_global_addresses_and_routes(self):
    client = DhcpClient()
    with patch.object(dhcp_client_module.subprocess, "run", return_value=MagicMock(returncode=0)) as run:
      client.clear_ipv6_state()

    assert [item.args[0] for item in run.call_args_list] == [
      ["sudo", "ip", "-6", "addr", "flush", "dev", "wlan0", "scope", "global"],
      ["sudo", "ip", "-6", "route", "del", "default", "dev", "wlan0"],
      ["sudo", "ip", "-6", "route", "flush", "dev", "wlan0"],
    ]

  def test_clear_ipv6_state_ignores_absent_default_route(self):
    client = DhcpClient()
    results = (
      MagicMock(returncode=0, stderr=b""),
      MagicMock(returncode=2, stderr=b"RTNETLINK answers: No such process\n"),
      MagicMock(returncode=0, stderr=b""),
    )
    with (
      patch.object(dhcp_client_module.subprocess, "run", side_effect=results),
      patch.object(dhcp_client_module.cloudlog, "warning") as warning,
    ):
      client.clear_ipv6_state()

    warning.assert_not_called()
