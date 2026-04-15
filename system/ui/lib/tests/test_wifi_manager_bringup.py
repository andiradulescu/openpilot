"""Tests for WifiManager._ensure_wpa_supplicant attach-first bringup.

Pins the contract: we never kill a wpa_supplicant daemon we didn't spawn,
and we never spawn a second daemon if one is already answering on the
ctrl socket. Designed to coexist with a future systemd/OpenRC-managed
wpa_supplicant on tici.
"""
import re

import pytest

from openpilot.system.ui.lib import wifi_manager as wifi_manager_module
from openpilot.system.ui.lib.wifi_manager import WPA_SUPPLICANT_CONF


def _patch_bringup_sideeffects(wm, mocker):
  """Mock the side-effect calls in the spawn fallback path.

  `_our_wpa_supplicant_running` is called twice by the spawn path: once at
  the top as the fast-path gate (must be False so we fall through to
  spawn) and again in the post-spawn retry loop as the "don't latch onto a
  foreign daemon" gate (must be True so the attach is allowed once our
  spawn completes). Use a side_effect that returns False first and True
  thereafter so both tests are satisfied.
  """
  mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
  mocker.patch.object(wifi_manager_module.os.path, "exists", return_value=True)
  mocker.patch.object(wifi_manager_module.glob, "glob", return_value=[])
  mocker.patch.object(wm, "_unmanage_wlan0")
  pgrep_calls = [0]
  def pgrep_side_effect():
    pgrep_calls[0] += 1
    return pgrep_calls[0] > 1  # False on first call, True after spawn
  mocker.patch.object(wm, "_our_wpa_supplicant_running", side_effect=pgrep_side_effect)
  mocker.patch.object(wifi_manager_module.time, "sleep")
  wm._exit = False
  # Fixture lacks scan/state threads — ensure GC-triggered __del__ → stop()
  # doesn't crash when _exit flips to False for the duration of the test.
  wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
  wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
  wm._gsm = mocker.MagicMock()
  return mock_run


class TestAttachFirst:
  # The wm fixture sets _exit=True, which short-circuits the wait-for-wlan0
  # loop at the top of _ensure_wpa_supplicant, so these tests don't need to
  # mock os.path.exists or time.sleep.

  def test_attach_success_skips_nmcli_pkill_and_spawn(self, wm, mocker):
    """Fast path: when our own daemon is already running, we attach
    directly. No nmcli, no pkill, no spawn — we do not disturb NM at all,
    because there's nothing to release."""
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=True)
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")

    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl
    ctrl.open.assert_called_once()
    mock_run.assert_not_called()

  def test_attach_success_enables_networks(self, wm, mocker):
    """On attach, all networks are re-enabled (no RECONFIGURE — that would
    be rude on a system-managed daemon)."""
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=True)
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mocker.patch.object(wifi_manager_module.subprocess, "run")

    wm._ensure_wpa_supplicant()

    requests = [call.args[0] for call in ctrl.request.call_args_list]
    assert "ENABLE_NETWORK all" in requests
    assert "RECONFIGURE" not in requests

  def test_attach_success_swallows_request_errors(self, wm, mocker):
    """ENABLE_NETWORK failures must not fail the attach."""
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=True)
    ctrl = mocker.MagicMock()
    ctrl.request.side_effect = OSError("permission denied")
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mocker.patch.object(wifi_manager_module.subprocess, "run")

    # Should not raise
    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl

  def test_our_daemon_missing_falls_through_to_spawn(self, wm, mocker):
    """Regression guard: when no daemon we own is alive, we must NOT
    attach — even if the socket file still exists — because that would
    latch onto NM's wpa_supplicant, which NM is about to tear down."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    # _our_wpa_supplicant_running is False (set by helper), so we never
    # call WpaCtrl before the spawn path runs.
    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    spawn_cmds = [cmd for cmd in commands if cmd[:2] == ("sudo", "wpa_supplicant")]
    assert spawn_cmds, f"no spawn in {commands}"


class TestSpawnFallback:
  def test_no_owned_daemon_falls_through_to_spawn(self, wm, mocker):
    """When no daemon we own is running, we spawn wpa_supplicant with our
    config."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
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
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    for cmd in commands:
      if "killall" in cmd:
        assert "wpa_supplicant" not in cmd, \
          f"bare killall stomps on system daemons: {cmd}"

  def test_spawn_fallback_pkill_targets_our_config(self, wm, mocker):
    """The pkill fallback must target only processes running our config,
    so a baked system daemon on a different config survives. The CONF path
    is regex-escaped to avoid over-match on metacharacters."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    pkill_cmds = [cmd for cmd in commands if cmd[:2] == ("sudo", "pkill")]
    assert pkill_cmds, f"no pkill fallback in {commands}"
    escaped = re.escape(WPA_SUPPLICANT_CONF)
    assert any(escaped in arg for cmd in pkill_cmds for arg in cmd), \
      f"pkill doesn't narrow to our escaped config: {pkill_cmds}"

  def test_spawn_waits_for_nm_teardown_before_spawning(self, wm, mocker):
    """After _unmanage_wlan0, we must poll until the ctrl socket is gone
    before cleaning up or spawning. Otherwise we race NM's asynchronous
    wpa_supplicant deinit and spawn into a still-occupied ctrl_iface.
    This test pins that the wait loop runs and gives up once the socket
    is gone."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = _patch_bringup_sideeffects(wm, mocker)

    # Simulate the socket disappearing after 3 polls by sequencing
    # os.path.exists return values. /sys/class/net/wlan0 check at the top
    # of _ensure_wpa_supplicant always returns True (fixture _exit=False
    # would loop forever otherwise, but the fixture sets _exit=True which
    # skips that loop). The ctrl-socket wait loop is the one we care about.
    exists_calls = iter([True, True, True, False] + [True] * 50)
    mocker.patch.object(wifi_manager_module.os.path, "exists",
                        side_effect=lambda _: next(exists_calls))

    wm._ensure_wpa_supplicant()

    commands = [tuple(call.args[0]) for call in mock_run.call_args_list]
    spawn_cmds = [cmd for cmd in commands if cmd[:2] == ("sudo", "wpa_supplicant")]
    assert spawn_cmds, f"no spawn after socket clear: {commands}"

  def test_spawn_then_reattach_loop(self, wm, mocker):
    """After spawn, the retry loop attaches successfully to the new daemon."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    _patch_bringup_sideeffects(wm, mocker)

    wm._ensure_wpa_supplicant()

    assert wm._ctrl is ctrl
    # ENABLE_NETWORK is called on the post-spawn attach
    requests = [call.args[0] for call in ctrl.request.call_args_list]
    assert "ENABLE_NETWORK all" in requests

  def test_post_spawn_refuses_foreign_daemon(self, wm, mocker):
    """Regression guard for codex P1: if NM never released the ctrl socket
    (wait loop timed out) and our spawn failed, the retry loop must NOT
    attach to the foreign daemon still occupying /var/run/wpa_supplicant/
    wlan0. _our_wpa_supplicant_running gates the attach; when it returns
    False the whole post-spawn window, we end with no ctrl bound."""
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    # Don't use the False-then-True helper — here pgrep must return False
    # for every call so neither the fast path nor the post-spawn retry
    # attach succeeds.
    mocker.patch.object(wifi_manager_module.subprocess, "run")
    mocker.patch.object(wifi_manager_module.os.path, "exists", return_value=True)
    mocker.patch.object(wifi_manager_module.glob, "glob", return_value=[])
    mocker.patch.object(wm, "_unmanage_wlan0")
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=False)
    mocker.patch.object(wifi_manager_module.time, "sleep")
    wm._exit = False
    wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._gsm = mocker.MagicMock()

    wm._ensure_wpa_supplicant()

    # We must not have latched onto the foreign daemon on the socket.
    assert wm._ctrl is not ctrl
    ctrl.open.assert_not_called()


class TestMultipleDaemonsPrevented:
  def test_attach_short_circuits_before_pkill_and_spawn(self, wm, mocker):
    """Regression guard: when our daemon is alive and attach succeeds, we
    must not run any subprocess at all — no nmcli, no pkill, no spawn."""
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=True)
    ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ctrl)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
    mock_unmanage = mocker.patch.object(wm, "_unmanage_wlan0")

    wm._ensure_wpa_supplicant()

    mock_run.assert_not_called()
    mock_unmanage.assert_not_called()


def _patch_tethering_sideeffects(wm, mocker):
  """Silence all the subprocess / filesystem plumbing _start_tethering
  executes so we can exercise just the ctrl-socket bringup check."""
  mocker.patch.object(wifi_manager_module.subprocess, "run")
  mocker.patch.object(wifi_manager_module.subprocess, "Popen")
  mocker.patch.object(wifi_manager_module.time, "sleep")
  mocker.patch.object(wifi_manager_module.os, "open", return_value=0)

  class _DummyFd:
    def __enter__(self):
      return self

    def __exit__(self, *a):
      return False

    def write(self, _data):
      return None

  mocker.patch.object(wifi_manager_module.os, "fdopen", return_value=_DummyFd())
  mocker.patch.object(wifi_manager_module, "_get_upstream_iface", return_value="wwan0")
  wm._tethering_ssid = "weedle-test"
  wm._tethering_psk = "hotspot-psk-1234"
  wm._ipv4_forward = False
  wm._monitor_epoch = 0


class TestTetheringBringupVerification:
  def test_start_tethering_raises_when_attached_daemon_is_not_ap(self, wm, mocker):
    """If a surviving STA daemon still owns wlan0, our AP spawn fails but
    attach still succeeds against the old daemon. STATUS reports mode=station,
    so bringup must raise (so set_tethering_active's rollback runs)."""
    _patch_tethering_sideeffects(wm, mocker)
    sta_ctrl = mocker.MagicMock()
    sta_ctrl.request.return_value = "wpa_state=COMPLETED\nmode=station\nssid=NotOurs\n"
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=sta_ctrl)

    with pytest.raises(RuntimeError, match="did not take over wlan0"):
      wm._start_tethering()

    sta_ctrl.close.assert_called_once()
    # We must NOT publish the stale ctrl as our own — otherwise callers
    # (monitor thread, connect path) would keep talking to the STA daemon
    # thinking it's our AP.
    assert wm._ctrl is None

  def test_start_tethering_accepts_ap_mode(self, wm, mocker):
    """Happy path: STATUS says mode=AP → attach is accepted and state flips
    to CONNECTED."""
    _patch_tethering_sideeffects(wm, mocker)
    ap_ctrl = mocker.MagicMock()
    ap_ctrl.request.return_value = f"wpa_state=COMPLETED\nmode=AP\nssid={wm._tethering_ssid}\n"
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=ap_ctrl)

    wm._start_tethering()

    assert wm._ctrl is ap_ctrl
    ap_ctrl.close.assert_not_called()
    from openpilot.system.ui.lib.wifi_manager import ConnectStatus
    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == wm._tethering_ssid

  def test_start_tethering_raises_when_status_request_fails(self, wm, mocker):
    """A daemon that answers the socket but errors on STATUS is also unsafe
    to keep — we raise and close the ctrl."""
    _patch_tethering_sideeffects(wm, mocker)
    broken_ctrl = mocker.MagicMock()
    broken_ctrl.request.side_effect = OSError("broken pipe")
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=broken_ctrl)

    with pytest.raises(RuntimeError, match="STATUS failed"):
      wm._start_tethering()

    broken_ctrl.close.assert_called_once()
    assert wm._ctrl is None


class TestStopTetheringRollback:
  """_stop_tethering must restore STA mode via _ensure_wpa_supplicant: attach
  to our own STA daemon if one is alive, otherwise unmanage + spawn. It must
  never attach to NM's wpa_supplicant (NM would tear it down under us)."""

  def _patch_common(self, wm, mocker):
    mocker.patch.object(wifi_manager_module.time, "sleep")
    mocker.patch.object(wifi_manager_module, "_generate_wpa_conf")
    mocker.patch.object(wm, "_unmanage_wlan0")
    mocker.patch.object(wifi_manager_module.os.path, "exists", return_value=True)
    mocker.patch.object(wifi_manager_module.glob, "glob", return_value=[])
    wm._dnsmasq_proc = None
    wm._tethering_upstream_iface = "wwan0"
    wm._monitor_epoch = 0
    wm._exit = False
    wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._gsm = mocker.MagicMock()

  def test_rollback_attaches_to_our_own_surviving_daemon(self, wm, mocker):
    """If our STA daemon survived _start_tethering (AP bringup failed before
    killing it), rollback must attach to it without spawning a second."""
    self._patch_common(wm, mocker)
    mocker.patch.object(wm, "_our_wpa_supplicant_running", return_value=True)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
    existing_ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=existing_ctrl)

    wm._stop_tethering()

    assert wm._ctrl is existing_ctrl
    existing_ctrl.request.assert_any_call("ENABLE_NETWORK all")
    spawn_cmds = [c for c in mock_run.call_args_list
                  if len(c.args[0]) >= 2 and c.args[0][0] == "sudo" and c.args[0][1] == "wpa_supplicant"]
    assert not spawn_cmds, f"must not spawn when our daemon is alive: {spawn_cmds}"

  def _mock_pgrep_false_then_true(self, wm, mocker):
    """Same False-then-True sequence as _patch_bringup_sideeffects: fast
    path sees no owned daemon, post-spawn retry sees the spawned one."""
    pgrep_calls = [0]
    def pgrep_side_effect():
      pgrep_calls[0] += 1
      return pgrep_calls[0] > 1
    mocker.patch.object(wm, "_our_wpa_supplicant_running", side_effect=pgrep_side_effect)

  def test_rollback_spawns_when_no_daemon_we_own(self, wm, mocker):
    """If no daemon we own is running (regardless of whether NM's or a
    system daemon is present), rollback must unmanage NM and spawn our own
    STA daemon. Attaching to a foreign daemon would be torn down when NM
    releases wlan0."""
    self._patch_common(wm, mocker)
    self._mock_pgrep_false_then_true(wm, mocker)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
    new_ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=new_ctrl)

    wm._stop_tethering()

    assert wm._ctrl is new_ctrl
    spawn_cmds = [c for c in mock_run.call_args_list
                  if len(c.args[0]) >= 2 and c.args[0][0] == "sudo" and c.args[0][1] == "wpa_supplicant"]
    assert spawn_cmds, "spawn must run when no owned daemon is alive"
    assert WPA_SUPPLICANT_CONF in spawn_cmds[0].args[0]

  def test_rollback_never_bare_killall_wpa_supplicant(self, wm, mocker):
    """Invariant: rollback must never `killall wpa_supplicant`. pkill is
    allowed because it's narrowed to our config path via regex."""
    self._patch_common(wm, mocker)
    self._mock_pgrep_false_then_true(wm, mocker)
    mock_run = mocker.patch.object(wifi_manager_module.subprocess, "run")
    new_ctrl = mocker.MagicMock()
    mocker.patch.object(wifi_manager_module, "WpaCtrl", return_value=new_ctrl)

    wm._stop_tethering()

    for call in mock_run.call_args_list:
      cmd = call.args[0]
      if "killall" in cmd:
        assert "wpa_supplicant" not in cmd, f"bare killall would stomp system daemon: {cmd}"
