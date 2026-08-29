#!/usr/bin/env python3
import os
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_HEAD = "b3129a9210aa48fad416d74316455d58341ab5e3"


def run(*args: str, env: dict[str, str] | None = None) -> None:
  subprocess.run(args, check=True, env=env)


def output(*args: str) -> str:
  return subprocess.check_output(args, text=True).strip()


def replace_once(text: str, old: str, new: str) -> str:
  count = text.count(old)
  if count != 1:
    raise RuntimeError(f"expected one match, found {count}: {old[:80]!r}")
  return text.replace(old, new, 1)


def commit(message: str, *paths: str) -> None:
  run(sys.executable, "-m", "py_compile", *[path for path in paths if path.endswith(".py")])
  run("git", "diff", "--check")
  run("git", "add", *paths)
  run("git", "commit", "-m", message)


if output("git", "rev-parse", "HEAD") != EXPECTED_HEAD:
  raise RuntimeError("target branch moved")
run("git", "config", "user.name", "Andrei Radulescu")
run("git", "config", "user.email", "andi.radulescu@gmail.com")

controller_path = Path("openpilot/system/ui/lib/wifi_controller.py")
controller_tests = Path("openpilot/system/ui/lib/tests/test_wifi_controller.py")
tethering_path = Path("openpilot/system/ui/lib/wifi_tethering.py")
tethering_tests = Path("openpilot/system/ui/lib/tests/test_wifi_tethering.py")

# Commit 1: don't switch network ownership while DHCP or tethering resources are still live.
text = controller_path.read_text()
text = replace_once(text, '''    wpa_supplicant.write_ap_config(self._tethering_ssid, self._tethering_password)
    self._clear_l3()
    self._close_ctrl()
''', '''    wpa_supplicant.write_ap_config(self._tethering_ssid, self._tethering_password)
    if not self._clear_l3():
      self._callbacks.put(("tethering_failed", None))
      return
    self._close_ctrl()
''')
text = replace_once(text, '''    if not self._tethering.start(self._ipv4_forward):
      wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF)
      self._restore_station_after_tethering_failure()
      self._callbacks.put(("tethering_failed", None))
      return
''', '''    if not self._tethering.start(self._ipv4_forward):
      if not self._tethering.stop():
        self._tethering_active = True
        self._state = WifiState()
        self._callbacks.put(("tethering_failed", None))
        return
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        self._tethering_active = True
        self._state = WifiState()
        self._callbacks.put(("tethering_failed", None))
        return
      self._restore_station_after_tethering_failure()
      self._callbacks.put(("tethering_failed", None))
      return
''')
text = replace_once(text, '''  def _begin_selection(self, ssid: str):
    self._assert_owner()
    self._clear_l3()
    self._requested_ssid = ssid
    self._connecting_since = time.monotonic()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)
''', '''  def _begin_selection(self, ssid: str) -> bool:
    self._assert_owner()
    if not self._clear_l3():
      self._callbacks.put(("settings_failed", ssid))
      return False
    self._requested_ssid = ssid
    self._connecting_since = time.monotonic()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)
    return True
''')
text = replace_once(text, '''  def _clear_l3(self):
    self._assert_owner()
    clear_active_profile()
    self._dhcp.stop()
    self._dhcp.clear_ipv6()
''', '''  def _clear_l3(self) -> bool:
    self._assert_owner()
    if not self._dhcp.stop():
      return False
    clear_active_profile()
    self._dhcp.clear_ipv6()
    return True
''')
pattern = re.compile(r'^(    )self\._begin_selection\(([^()\n]+)\)\n', re.MULTILINE)
if len(pattern.findall(text)) != 2:
  raise RuntimeError("unexpected _begin_selection call count")
text = pattern.sub(lambda match: f'{match.group(1)}if not self._begin_selection({match.group(2)}):\n{match.group(1)}  return\n', text)
pattern = re.compile(r'^(\s*)self\._clear_l3\(\)\n', re.MULTILINE)
text, count = pattern.subn(lambda match: f'{match.group(1)}if not self._clear_l3():\n{match.group(1)}  raise RuntimeError("failed to stop Wi-Fi DHCP")\n', text)
if count < 3:
  raise RuntimeError(f"unexpected remaining _clear_l3 call count: {count}")
controller_path.write_text(text)

text = controller_tests.read_text()
anchor = "  def test_stop_waits_for_controller_shutdown(self):\n"
addition = '''  def test_selection_aborts_when_dhcp_cannot_stop(self):
    controller, _, dhcp = make_controller()
    controller._state = controller.state.__class__(ssid="Old", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A, ipv4_address="10.0.0.2")
    dhcp.stop.return_value = False

    assert not controller._begin_selection("New")

    assert controller.state.ssid == "Old"
    assert controller.state.status == ConnectStatus.CONNECTED
    assert controller.get_callback() == ("settings_failed", "New")

'''
if anchor not in text:
  raise RuntimeError("selection test anchor missing")
text = text.replace(anchor, addition + anchor, 1)
anchor = "  def test_failed_ap_start_restores_station(self):\n"
addition = '''  def test_failed_tethering_cleanup_does_not_restore_station(self):
    controller, _, _ = make_controller()
    controller._close_ctrl = MagicMock()
    controller._clear_l3 = MagicMock(return_value=True)
    controller._restore_station_after_tethering_failure = MagicMock()
    controller._tethering.start = MagicMock(return_value=False)
    controller._tethering.stop = MagicMock(return_value=False)

    with (
      patch.object(wifi_controller.wpa_supplicant, "write_ap_config"),
      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=True),
      patch.object(wifi_controller.wpa_supplicant, "start", return_value=True),
    ):
      controller._enter_tethering()

    controller._restore_station_after_tethering_failure.assert_not_called()
    assert controller.tethering_active
    assert controller.get_callback() == ("tethering_failed", None)

'''
if anchor not in text:
  raise RuntimeError("tethering test anchor missing")
controller_tests.write_text(text.replace(anchor, addition + anchor, 1))
commit("wifi: abort transitions with live services", str(controller_path), str(controller_tests))

# Commit 2: contain persistence failures and the dnsmasq signal race.
text = controller_path.read_text()
text = replace_once(text, "import queue\n", "import queue\nimport subprocess\n")
text = replace_once(text, '''        profile_uuid = stored.uuid
      except OSError:
        return

    profile = self._store.get(profile_uuid)
''', '''        profile_uuid = stored.uuid
      except (OSError, subprocess.SubprocessError):
        self._cancel_selection()
        return

    profile = self._store.get(profile_uuid)
''')
controller_path.write_text(text)

text = tethering_path.read_text()
text = replace_once(text, '''  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    return False
  deadline = time.monotonic() + timeout
''', '''  if subprocess.run(["sudo", "kill", str(pid)], check=False).returncode != 0:
    if _owned_dnsmasq_pid() is not None:
      return False
    subprocess.run(["sudo", "rm", "-f", DNSMASQ_PID_FILE], check=False)
    return True
  deadline = time.monotonic() + timeout
''')
tethering_path.write_text(text)

text = controller_tests.read_text()
text = replace_once(text, "import threading\n", "import subprocess\nimport threading\n")
anchor = "  def test_connected_status_uses_exact_profile_metering(self):\n"
addition = '''  def test_profile_persistence_failure_cancels_selection(self):
    profile = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123")
    controller, store, dhcp = make_controller()
    controller._pending_profile = profile
    controller._temporary_network_id = "9"
    controller._runtime_profiles = {UUID_A: "9"}
    controller._request = MagicMock(return_value="OK\\n")
    store.write.side_effect = subprocess.CalledProcessError(1, ["sudo", "install"])

    controller._adopt_status({"wpa_state": "COMPLETED", "ssid": "Test", "id_str": UUID_A})

    assert controller._pending_profile is None
    dhcp.stop.assert_called_once_with()
    assert controller.get_callback() == ("disconnected", None)

'''
if anchor not in text:
  raise RuntimeError("persistence test anchor missing")
controller_tests.write_text(text.replace(anchor, addition + anchor, 1))

text = tethering_tests.read_text()
anchor = "  def test_forwarding_command_failure_is_reported(self):\n"
addition = '''  def test_stop_accepts_dnsmasq_exit_before_signal(self):
    with (
      patch.object(wifi_tethering, "_owned_dnsmasq_pid", side_effect=[123, None]),
      patch.object(wifi_tethering.subprocess, "run", side_effect=[MagicMock(returncode=1), MagicMock(returncode=0)]) as run,
    ):
      assert wifi_tethering.stop_dnsmasq()

    assert run.call_args_list == [
      call(["sudo", "kill", "123"], check=False),
      call(["sudo", "rm", "-f", wifi_tethering.DNSMASQ_PID_FILE], check=False),
    ]

'''
if anchor not in text:
  raise RuntimeError("dnsmasq test anchor missing")
tethering_tests.write_text(text.replace(anchor, addition + anchor, 1))
commit("wifi: handle network service failures", str(controller_path), str(tethering_path), str(controller_tests), str(tethering_tests))

# Commit 3: retry publishing metering identity until it succeeds.
text = controller_path.read_text()
text = replace_once(text, '''    self._ipv4_forward = False
    self._owner_ident: int | None = None
''', '''    self._ipv4_forward = False
    self._published_active_profile: tuple[str, int] | None = None
    self._owner_ident: int | None = None
''')
text = replace_once(text, '''    clear_active_profile()
    self._dhcp.clear_ipv6()
    return True
''', '''    clear_active_profile()
    self._published_active_profile = None
    self._dhcp.clear_ipv6()
    return True
''')
text = replace_once(text, '''  def _publish_active_profile(self, profile: NetworkProfile):
    self._assert_owner()
    try:
      write_active_profile(profile.uuid, int(profile.metered))
    except Exception:
      cloudlog.exception("Failed to publish active Wi-Fi profile")
''', '''  def _publish_active_profile(self, profile: NetworkProfile) -> bool:
    self._assert_owner()
    active_profile = (profile.uuid, int(profile.metered))
    if self._published_active_profile == active_profile:
      return True
    try:
      write_active_profile(*active_profile)
    except Exception:
      cloudlog.exception("Failed to publish active Wi-Fi profile")
      return False
    self._published_active_profile = active_profile
    return True
''')
text = replace_once(text, '''      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTING:
''', '''      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTED:
        profile = self._store.get(profile_uuid)
        if profile is not None:
          self._publish_active_profile(profile)

      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTING:
''')
controller_path.write_text(text)

text = controller_tests.read_text()
anchor = "  def test_station_request_failure_keeps_live_supplicant(self):\n"
addition = '''  def test_active_profile_publication_retries_after_failure(self):
    profile = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123", metered=MeteredType.YES)
    controller, _, dhcp = make_controller((profile,))
    controller._state = controller.state.__class__(ssid="Test", status=ConnectStatus.CONNECTING, profile_uuid=UUID_A, metered=MeteredType.YES)
    controller._request = MagicMock(return_value=f"wpa_state=COMPLETED\\nssid=Test\\nid_str={UUID_A}\\n")
    dhcp.running = True
    dhcp.ready.return_value = True
    dhcp.ipv4_address.return_value = "10.0.0.2"
    self.write_active.side_effect = [OSError("write failed"), None]

    controller._reconcile()
    controller._reconcile()
    controller._reconcile()

    assert controller.state.status == ConnectStatus.CONNECTED
    assert self.write_active.call_count == 2

'''
if anchor not in text:
  raise RuntimeError("publication test anchor missing")
controller_tests.write_text(text.replace(anchor, addition + anchor, 1))
commit("wifi: retry active profile publication", str(controller_path), str(controller_tests))

# Commit 4: a failed tethering start is cleanup-pending even if residual services look healthy.
text = controller_path.read_text()
text = replace_once(text, '''  def _reconcile_tethering(self):
    self._assert_owner()
    if (wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF)
        and wifi_tethering.dnsmasq_running()
        and wifi_tethering.firewall_ready()):
      return
    self._leave_tethering(failed=True)
''', '''  def _reconcile_tethering(self):
    self._assert_owner()
    if self._state.status != ConnectStatus.CONNECTED:
      self._leave_tethering(failed=True)
      return
    if (wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF)
        and wifi_tethering.dnsmasq_running()
        and wifi_tethering.firewall_ready()):
      return
    self._leave_tethering(failed=True)
''')
controller_path.write_text(text)

text = controller_tests.read_text()
anchor = "  def test_healthy_tethering_is_left_running(self):\n"
addition = '''  def test_failed_tethering_start_state_retries_cleanup(self):
    controller, _, _ = make_controller()
    controller._tethering_active = True
    controller._state = wifi_controller.WifiState()
    controller._leave_tethering = MagicMock()

    controller._reconcile_tethering()

    controller._leave_tethering.assert_called_once_with(failed=True)

'''
if anchor not in text:
  raise RuntimeError("tethering cleanup test anchor missing")
controller_tests.write_text(text.replace(anchor, addition + anchor, 1))
commit("wifi: retry failed tethering cleanup", str(controller_path), str(controller_tests))

# Focused tests without importing the full hardware/logging dependency graph.
run(sys.executable, "-m", "pip", "install", "-q", "pytest", "ruff")
stub_dir = Path("/tmp/openpilot-test-stubs")
stub_dir.mkdir(exist_ok=True)
(stub_dir / "sitecustomize.py").write_text('''import sys\nimport types\n\nclass _CloudLog:\n  def __getattr__(self, _):\n    return lambda *args, **kwargs: None\n\nmodule = types.ModuleType("openpilot.common.swaglog")\nmodule.cloudlog = _CloudLog()\nsys.modules["openpilot.common.swaglog"] = module\n''')
test_env = os.environ.copy()
test_env["PYTHONPATH"] = str(stub_dir) + (":" + test_env["PYTHONPATH"] if test_env.get("PYTHONPATH") else "")
run(sys.executable, "-m", "pytest", "-q", str(controller_tests), str(tethering_tests), env=test_env)
run("ruff", "check", str(controller_path), str(tethering_path), str(controller_tests), str(tethering_tests))
run("git", "diff", "--check", "HEAD~4..HEAD")
if output("git", "rev-list", "--count", f"{EXPECTED_HEAD}..HEAD") != "4":
  raise RuntimeError("unexpected commit count")
run("git", "push", "origin", "HEAD:wifi-no-networkmanager-refactor")
