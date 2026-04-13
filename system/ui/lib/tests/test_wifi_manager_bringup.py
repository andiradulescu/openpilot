"""Tests for WifiManager._ensure_wpa_supplicant attach-first bringup.

Pins the contract: we never kill a wpa_supplicant daemon we didn't spawn,
and we never spawn a second daemon if one is already answering on the
ctrl socket. Designed to coexist with a future systemd/OpenRC-managed
wpa_supplicant on tici.
"""
from openpilot.system.ui.lib import wifi_manager as wifi_manager_module
from openpilot.system.ui.lib.wifi_manager import WPA_SUPPLICANT_CONF


def _patch_bringup_sideeffects(wm, mocker):
  """Mock the side-effect calls in the spawn fallback path."""
  mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
  mocker.patch.object(wifi_manager_module.os.path, "exists", return_value=True)
  mocker.patch.object(wifi_manager_module.glob, "glob", return_value=[])
  mocker.patch.object(wm, "_unmanage_wlan0")
  mocker.patch.object(wifi_manager_module.time, "sleep")
  wm._exit = False
  # Fixture lacks scan/state threads — ensure GC-triggered __del__ → stop()
  # doesn't crash when _exit flips to False for the duration of the test.
  wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
  wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
  wm._gsm = mocker.MagicMock()
  return mock_run


class TestAttachFirst:
  def test_attach_success_skips_all_subprocess_calls(self, wm, mocker):
    """Happy path: existing daemon answers on ctrl socket → no pkill, no spawn."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")

    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl
    ctrl.open.assert_called_once()
    mock_run.assert_not_called()

  def test_attach_success_calls_reconfigure_and_enable(self, wm, mocker):
    """On attach, RECONFIGURE picks up fresh config and networks are enabled."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mocker.patch.object(wifi_manager_module.subprocess, "run")

    wm._ensure_wpa_supplicant()

    requests = [call.args[0] for call in ctrl.request.call_args_list]
    assert "RECONFIGURE" in requests
    assert "ENABLE_NETWORK all" in requests

  def test_attach_success_swallows_request_errors(self, wm, mocker):
    """RECONFIGURE/ENABLE_NETWORK failures (e.g. permission-restricted
    system daemon) must not fail the attach."""
    ctrl = mocker.MagicMock()
    ctrl.request.side_effect = OSError("permission denied")
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mocker.patch.object(wifi_manager_module.subprocess, "run")

    # Should not raise
    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl


class TestSpawnFallback:
  def test_attach_failure_falls_through_to_spawn(self, wm, mocker):
    """When no daemon answers, we spawn wpa_supplicant with our config."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl",
                        side_effect=[OSError("no socket"), ctrl])
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl
    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    spawn_cmds = [cmd for cmd in commands if cmd[:2] == ("sudo", "wpa_supplicant")]
    assert spawn_cmds, f"no spawn call in {commands}"
    assert WPA_SUPPLICANT_CONF in spawn_cmds[0]

  def test_spawn_fallback_never_bare_killalls_wpa_supplicant(self, wm, mocker):
    """Critical: we must never `sudo killall wpa_supplicant` — that would
    stomp on a system-managed daemon we're supposed to coexist with."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl",
                        side_effect=[OSError("no socket"), ctrl])
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    for cmd in commands:
      if "killall" in cmd:
        assert "wpa_supplicant" not in cmd, \
          f"bare killall stomps on system daemons: {cmd}"

  def test_spawn_fallback_pkill_targets_our_config(self, wm, mocker):
    """The pkill fallback must target only processes running our config,
    so a baked system daemon on a different config survives."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl",
                        side_effect=[OSError("no socket"), ctrl])
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    pkill_cmds = [cmd for cmd in commands if cmd[:2] == ("sudo", "pkill")]
    assert pkill_cmds, f"no pkill fallback in {commands}"
    assert any(WPA_SUPPLICANT_CONF in arg for cmd in pkill_cmds for arg in cmd), \
      f"pkill doesn't narrow to our config: {pkill_cmds}"

  def test_spawn_then_reattach_loop(self, wm, mocker):
    """After spawn, the retry loop attaches successfully to the new daemon."""
    ctrl = mocker.MagicMock()
    # First attempt (pre-spawn) fails, second (post-spawn retry) succeeds
    mocker.patch.object(wifi_manager_module, "WpaCtrl",
                        side_effect=[OSError("no socket"), ctrl])
    _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl
    # ENABLE_NETWORK is called on the post-spawn attach
    requests = [call.args[0] for call in ctrl.request.call_args_list]
    assert "ENABLE_NETWORK all" in requests


class TestMultipleDaemonsPrevented:
  def test_attach_short_circuits_before_any_subprocess(self, wm, mocker):
    """Regression guard: verify the spawn block is never entered when attach
    succeeds. If this test fails, we risk spawning a second daemon."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
    mock_unmanage = mocker.patch.object(wm, "_unmanage_wlan0")

    wm._ensure_wpa_supplicant()

    mock_run.assert_not_called()
    mock_unmanage.assert_not_called()
