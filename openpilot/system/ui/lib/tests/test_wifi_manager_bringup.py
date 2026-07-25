import subprocess
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, mock_open, patch

from openpilot.system.ui.lib import wifi_manager as wifi_manager_module
from openpilot.system.ui.lib.wifi_manager import (
  ConnectStatus,
  TETHERING_NAT_COMMENT,
  TETHERING_SUBNET,
  WifiManager,
  WifiState,
)


def build_tethering_manager() -> WifiManager:
  manager = WifiManager.__new__(WifiManager)
  manager._exit = True
  manager._ctrl = None
  manager._dhcp = MagicMock()
  manager._store = MagicMock()
  manager._monitor_epoch = 0
  manager._user_epoch = 0
  manager._last_connecting_at = 0.0
  manager._tethering_ssid = "weedle-test"
  manager._tethering_psk = "hotspot-psk-1234"
  manager._tethering_active = True
  manager._ipv4_forward = True
  manager._dnsmasq_proc = None
  manager._wifi_state = WifiState()
  manager._ipv4_address = ""
  manager._activated = []
  manager._disconnected = []
  manager._callback_queue = []
  manager._callback_lock = threading.Lock()
  return manager


@contextmanager
def tethering_side_effects(manager: WifiManager, mode: str = "AP"):
  ctrl = MagicMock()
  ctrl.request.return_value = f"wpa_state=COMPLETED\nmode={mode}\nssid={manager._tethering_ssid}\n"
  dnsmasq = MagicMock()
  dnsmasq.poll.return_value = None

  with (
    patch.object(wifi_manager_module.time, "sleep"),
    patch.object(wifi_manager_module.os, "open", return_value=3),
    patch.object(wifi_manager_module.os, "fdopen", mock_open()),
    patch.object(wifi_manager_module, "_pkill_wpa_supplicant"),
    patch.object(wifi_manager_module, "_wpa_supplicant_running", return_value=True),
    patch.object(wifi_manager_module, "stop_tethering_dnsmasq"),
    patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl),
    patch.object(wifi_manager_module.subprocess, "Popen", return_value=dnsmasq),
    patch.object(wifi_manager_module.subprocess, "run", return_value=MagicMock(returncode=1)) as run,
  ):
    yield run, ctrl


class TestTetheringFirewall:
  def test_uses_available_xtables_backend(self):
    with patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"):
      assert wifi_manager_module._tethering_nat_rule("-A")[1] == "iptables-legacy"

  def test_falls_back_to_default_backend(self):
    with patch.object(wifi_manager_module.shutil, "which", return_value=None):
      assert wifi_manager_module._tethering_nat_rule("-A")[1] == "iptables"

  def test_installs_uplink_independent_masquerade(self):
    manager = build_tethering_manager()
    with (
      patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"),
      tethering_side_effects(manager) as (run, ctrl),
    ):
      manager._start_tethering()

    commands = [item.args[0] for item in run.call_args_list]
    nat_add = next(command for command in commands if "-A" in command and "MASQUERADE" in command)
    assert nat_add[:2] == ["sudo", "iptables-legacy"]
    assert "-s" in nat_add and TETHERING_SUBNET in nat_add
    assert "!" in nat_add and "-d" in nat_add
    assert "-o" not in nat_add
    assert TETHERING_NAT_COMMENT in nat_add
    assert manager._ctrl is ctrl
    assert manager._wifi_state == WifiState("weedle-test", ConnectStatus.CONNECTED)

  def test_nat_failure_aborts_bringup(self):
    manager = build_tethering_manager()

    def fail_nat_add(command, **_):
      if "-A" in command and "MASQUERADE" in command:
        raise subprocess.CalledProcessError(1, command)
      return MagicMock(returncode=1)

    with (
      patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"),
      tethering_side_effects(manager) as (run, _),
    ):
      run.side_effect = fail_nat_add
      try:
        manager._start_tethering()
        raise AssertionError("tethering should fail when NAT cannot be installed")
      except subprocess.CalledProcessError:
        pass

    assert manager._ctrl is None
    assert manager._wifi_state.status != ConnectStatus.CONNECTED

  def test_non_ap_daemon_aborts_bringup(self):
    manager = build_tethering_manager()
    with tethering_side_effects(manager, mode="station") as (_, ctrl):
      try:
        manager._start_tethering()
        raise AssertionError("tethering should reject a station control socket")
      except RuntimeError as error:
        assert "did not take over wlan0" in str(error)

    ctrl.close.assert_called_once()
    assert manager._ctrl is None

  def test_stop_removes_nat_and_restores_station(self):
    manager = build_tethering_manager()
    manager._ctrl = MagicMock()
    manager._ensure_wpa_supplicant = MagicMock()

    with (
      patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"),
      patch.object(wifi_manager_module, "stop_tethering_dnsmasq"),
      patch.object(wifi_manager_module, "_pkill_wpa_supplicant"),
      patch.object(wifi_manager_module, "_generate_wpa_conf"),
      patch.object(wifi_manager_module.time, "sleep"),
      patch.object(wifi_manager_module.subprocess, "run", return_value=MagicMock(returncode=1)) as run,
    ):
      manager._stop_tethering()

    commands = [item.args[0] for item in run.call_args_list]
    assert ["sudo", "iptables-legacy", "-t", "nat", "-D", "POSTROUTING",
            "-s", TETHERING_SUBNET, "!", "-d", TETHERING_SUBNET,
            "-j", "MASQUERADE", "-m", "comment", "--comment", TETHERING_NAT_COMMENT] in commands
    manager._ensure_wpa_supplicant.assert_called_once()
    assert not manager._tethering_active
    assert manager._wifi_state == WifiState()
