import subprocess
import threading
from contextlib import contextmanager
from unittest import TestCase
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
  ap_file = mock_open()

  with (
    patch.object(wifi_manager_module.time, "sleep"),
    patch.object(wifi_manager_module.os, "open", return_value=3),
    patch.object(wifi_manager_module.os, "fdopen", ap_file),
    patch.object(wifi_manager_module, "_pkill_wpa_supplicant"),
    patch.object(wifi_manager_module, "_wpa_supplicant_running", return_value=True),
    patch.object(wifi_manager_module, "stop_tethering_dnsmasq"),
    patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl),
    patch.object(wifi_manager_module.subprocess, "Popen", return_value=dnsmasq),
    patch.object(wifi_manager_module.subprocess, "run", return_value=MagicMock(returncode=1)) as run,
  ):
    yield run, ctrl, ap_file


class TestTetheringFirewall(TestCase):
  def test_selects_xtables_backend(self):
    for discovered, expected in (("/usr/sbin/iptables-legacy", "iptables-legacy"), (None, "iptables")):
      with self.subTest(discovered=discovered), patch.object(wifi_manager_module.shutil, "which", return_value=discovered):
        assert wifi_manager_module._tethering_nat_rule("-A")[1] == expected

  def test_installs_uplink_independent_masquerade(self):
    manager = build_tethering_manager()
    with (
      patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"),
      tethering_side_effects(manager) as (run, ctrl, _),
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

  def test_start_preserves_untagged_masquerade_rules(self):
    manager = build_tethering_manager()
    with tethering_side_effects(manager) as (run, _, _):
      manager._start_tethering()

    commands = [item.args[0] for item in run.call_args_list]
    assert not any("-D" in command and "-o" in command and "MASQUERADE" in command for command in commands)

  def test_nat_failure_aborts_bringup(self):
    manager = build_tethering_manager()

    def fail_nat_add(command, **_):
      if "-A" in command and "MASQUERADE" in command:
        raise subprocess.CalledProcessError(1, command)
      return MagicMock(returncode=1)

    with (
      patch.object(wifi_manager_module.shutil, "which", return_value="/usr/sbin/iptables-legacy"),
      tethering_side_effects(manager) as (run, _, _),
    ):
      run.side_effect = fail_nat_add
      with self.assertRaises(subprocess.CalledProcessError):
        manager._start_tethering()

    assert manager._ctrl is None
    assert manager._wifi_state.status != ConnectStatus.CONNECTED

  def test_non_ap_daemon_aborts_bringup(self):
    manager = build_tethering_manager()
    with tethering_side_effects(manager, mode="station") as (_, ctrl, _):
      with self.assertRaisesRegex(RuntimeError, "did not take over wlan0"):
        manager._start_tethering()

    ctrl.close.assert_called_once()
    assert manager._ctrl is None

  def test_ap_config_uses_wpa2_with_ccmp(self):
    manager = build_tethering_manager()
    with tethering_side_effects(manager) as (_, _, ap_file):
      manager._start_tethering()

    config = ap_file().write.call_args.args[0]
    assert "  proto=RSN\n" in config
    assert "  pairwise=CCMP\n" in config
    assert "  group=CCMP\n" in config

  def test_stop_removes_nat_and_restores_station(self):
    manager = build_tethering_manager()
    manager._ctrl = MagicMock()

    with (
      patch.object(manager, "_ensure_wpa_supplicant") as ensure_wpa_supplicant,
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
    assert ["sudo", "sysctl", "net.ipv4.ip_forward=0"] in commands
    ensure_wpa_supplicant.assert_called_once()
    assert not manager._tethering_active
    assert manager._wifi_state == WifiState()
