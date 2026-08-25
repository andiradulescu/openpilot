from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from openpilot.system.ui.lib import wpa_supplicant
from openpilot.system.ui.lib.wpa_ctrl import SecurityType
from openpilot.system.ui.lib.wpa_supplicant import WpaNetwork


class TestWpaConfig(TestCase):
  def test_station_config(self):
    network = WpaNetwork(
      ssid="café",
      security=SecurityType.WPA,
      psk="password123",
      hidden=True,
      profile_uuid="11111111-1111-1111-1111-111111111111",
      priority=42,
      bssid="00:11:22:33:44:55",
    )

    with patch.object(wpa_supplicant, "atomic_write") as atomic_write:
      f = atomic_write.return_value.__enter__.return_value
      wpa_supplicant.write_station_config([network])

    config = f.write.call_args.args[0]
    assert f"ssid={'café'.encode().hex()}" in config
    assert 'psk="password123"' in config
    assert "scan_ssid=1" in config
    assert "bssid=00:11:22:33:44:55" in config
    assert 'id_str="11111111-1111-1111-1111-111111111111"' in config
    assert "priority=42" in config


class TestWpaProcess(TestCase):
  def test_stop_keeps_ownership_until_process_exits(self):
    run_results = []

    def run(command, **kwargs):
      result = type("Result", (), {"returncode": 0})()
      run_results.append((command, kwargs))
      return result

    with (
      patch.object(wpa_supplicant, "_owned_pid", return_value=123),
      patch.object(wpa_supplicant.subprocess, "run", side_effect=run),
      patch.object(wpa_supplicant.time, "monotonic", side_effect=[0.0, 0.0, 3.0]),
      patch.object(wpa_supplicant.time, "sleep"),
    ):
      assert not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF, timeout=2.0)

    assert run_results == [(["sudo", "kill", "123"], {"check": False})]

  def test_stop_removes_ownership_after_process_exits(self):
    with (
      patch.object(wpa_supplicant, "_owned_pid", side_effect=[123, 123, None]),
      patch.object(wpa_supplicant.subprocess, "run") as run,
      patch.object(wpa_supplicant.time, "monotonic", side_effect=[0.0, 0.0, 0.1]),
      patch.object(wpa_supplicant.time, "sleep"),
    ):
      run.return_value.returncode = 0
      assert wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF)

    assert run.call_args_list == [
      call(["sudo", "kill", "123"], check=False),
      call(["sudo", "rm", "-f", wpa_supplicant.WPA_PID_FILE, wpa_supplicant.WPA_CTRL_PATH], check=False),
    ]

  def test_start_refuses_owned_other_mode(self):
    with (
      patch.object(wpa_supplicant, "is_running", return_value=False),
      patch.object(wpa_supplicant, "_owned_pid", return_value=123),
      patch.object(wpa_supplicant, "prepare_runtime"),
      patch.object(wpa_supplicant.subprocess, "run") as run,
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF)

    run.assert_not_called()

  def test_start_restores_networkmanager_after_spawn_failure(self):
    with (
      patch.object(wpa_supplicant, "is_running", return_value=False),
      patch.object(wpa_supplicant, "_owned_pid", side_effect=[None, None]),
      patch.object(wpa_supplicant, "prepare_runtime"),
      patch.object(wpa_supplicant, "release_networkmanager", return_value=True),
      patch.object(wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
      patch.object(wpa_supplicant.subprocess, "run", side_effect=[MagicMock(returncode=0), MagicMock(returncode=1)]),
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF)

    restore_networkmanager.assert_called_once_with()

  def test_start_does_not_restore_networkmanager_with_owned_process(self):
    with (
      patch.object(wpa_supplicant, "is_running", return_value=False),
      patch.object(wpa_supplicant, "_owned_pid", side_effect=[None, 123]),
      patch.object(wpa_supplicant, "prepare_runtime"),
      patch.object(wpa_supplicant, "release_networkmanager", return_value=True),
      patch.object(wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
      patch.object(wpa_supplicant.subprocess, "run", side_effect=[MagicMock(returncode=0), MagicMock(returncode=1)]),
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF)

    restore_networkmanager.assert_not_called()

  def test_owned_pid_checks_command_line(self):
    command = "\0".join((
      "/usr/sbin/wpa_supplicant", "-B", "-i", "wlan0", "-c",
      wpa_supplicant.WPA_SUPPLICANT_CONF, "-P", wpa_supplicant.WPA_PID_FILE, "",
    )).encode()
    with (
      patch.object(Path, "read_text", return_value="123"),
      patch.object(Path, "read_bytes", return_value=command),
    ):
      assert wpa_supplicant._owned_pid() == 123
      assert wpa_supplicant._owned_pid(wpa_supplicant.WPA_SUPPLICANT_CONF) == 123
      assert wpa_supplicant._owned_pid(wpa_supplicant.WPA_AP_CONF) is None
