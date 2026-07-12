import subprocess

from openpilot.system.ui.lib import dhcp_client as dhcp_client_module
from openpilot.system.ui.lib.dhcp_client import DhcpClient


class TestDhcpClient:
  def test_start_detaches_udhcpc_from_ui_session(self, mocker):
    client = DhcpClient()
    stop = mocker.patch.object(client, "stop")
    run = mocker.patch.object(dhcp_client_module.subprocess, "run")
    popen = mocker.patch.object(dhcp_client_module.subprocess, "Popen")
    thread = mocker.patch.object(dhcp_client_module.threading, "Thread")

    client.start()

    stop.assert_called_once()
    run.assert_called_once_with(["sudo", "pkill", "-f", "udhcpc.*-i wlan0"], check=False)
    popen.assert_called_once_with(
      ["sudo", "udhcpc", "-i", "wlan0", "-f", "-t", "5", "-T", "3"],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
      start_new_session=True,
    )
    thread.return_value.start.assert_called_once()

  def test_metric_zero_route_is_replaced_with_wifi_metric(self, mocker):
    client = DhcpClient()
    mocker.patch.object(
      dhcp_client_module.subprocess,
      "check_output",
      return_value="default via 192.168.1.1 dev wlan0 metric 0\n",
    )
    run = mocker.patch.object(dhcp_client_module.subprocess, "run")

    client._fix_default_route_metric()

    assert [call.args[0] for call in run.call_args_list] == [
      ["sudo", "ip", "-4", "route", "flush", "exact", "0.0.0.0/0", "dev", "wlan0"],
      ["sudo", "ip", "-4", "route", "add", "default", "via", "192.168.1.1", "dev", "wlan0", "metric", "600"],
    ]

  def test_existing_wifi_metric_is_left_untouched(self, mocker):
    client = DhcpClient()
    mocker.patch.object(
      dhcp_client_module.subprocess,
      "check_output",
      return_value="default via 192.168.1.1 dev wlan0 metric 600\n",
    )
    run = mocker.patch.object(dhcp_client_module.subprocess, "run")

    client._fix_default_route_metric()

    run.assert_not_called()

  def test_stop_cleans_only_wlan_dhcp_and_address(self, mocker):
    client = DhcpClient()
    client._proc = mocker.MagicMock()
    run = mocker.patch.object(dhcp_client_module.subprocess, "run")

    client.stop()

    assert client._proc is None
    assert [call.args[0] for call in run.call_args_list] == [
      ["sudo", "pkill", "-f", "udhcpc.*-i wlan0"],
      ["sudo", "ip", "addr", "flush", "dev", "wlan0"],
    ]
