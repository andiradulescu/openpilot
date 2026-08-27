from pathlib import Path
import subprocess

EXPECTED_HEAD = "32373531446918e2607a9d2b7b087f3740068ed9"


def replace_once(path: str, old: str, new: str) -> None:
  p = Path(path)
  text = p.read_text()
  count = text.count(old)
  if count != 1:
    raise RuntimeError(f"{path}: expected one match, got {count}")
  p.write_text(text.replace(old, new, 1))


def commit(message: str, paths: list[str]) -> None:
  subprocess.run(["git", "diff", "--check"], check=True)
  subprocess.run(["git", "add", *paths], check=True)
  subprocess.run(["git", "commit", "-m", message], check=True)


head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
if head != EXPECTED_HEAD:
  raise RuntimeError(f"target branch moved: expected {EXPECTED_HEAD}, got {head}")

# Tethering settings failures must remain retryable and always wake the UI.
replace_once(
  "openpilot/system/ui/lib/wifi_manager.py",
  """    self._disconnected: list[Callable[[], None]] = []
    self._ipv4_forward: bool | None = None
    self._last_snapshot = self._snapshot()
""",
  """    self._disconnected: list[Callable[[], None]] = []
    self._last_snapshot = self._snapshot()
""",
)
replace_once(
  "openpilot/system/ui/lib/wifi_manager.py",
  """  def set_ipv4_forward(self, enabled: bool):
    if enabled == self._ipv4_forward:
      return
    self._ipv4_forward = enabled
    self._controller.set_ipv4_forward(enabled)
""",
  """  def set_ipv4_forward(self, enabled: bool):
    self._controller.set_ipv4_forward(enabled)
""",
)
replace_once(
  "openpilot/system/ui/lib/tests/test_wifi_manager.py",
  """  def test_forwarding_is_edge_triggered(self):
    manager, controller = self.make_manager()

    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(False)

    assert [call.args[0] for call in controller.set_ipv4_forward.call_args_list] == [True, False]
""",
  """  def test_forwarding_retries_are_forwarded(self):
    manager, controller = self.make_manager()

    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(False)

    assert [call.args[0] for call in controller.set_ipv4_forward.call_args_list] == [True, True, False]
""",
)
replace_once(
  "openpilot/system/ui/lib/wifi_controller.py",
  """  def _set_tethering_password(self, password: str):
    self._assert_owner()
    if not self._valid_psk(password):
      return
""",
  """  def _set_tethering_password(self, password: str):
    self._assert_owner()
    if not self._valid_psk(password):
      self._callbacks.put((\"tethering_failed\", None))
      return
""",
)
replace_once(
  "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  """  def test_unchanged_tethering_password_emits_update(self):
    controller, _, _ = make_controller()

    controller._set_tethering_password(wifi_controller.DEFAULT_TETHERING_PASSWORD)

    controller._tethering_store.set_password.assert_not_called()
    assert controller.get_callback() == (\"networks_updated\", None)

""",
  """  def test_unchanged_tethering_password_emits_update(self):
    controller, _, _ = make_controller()

    controller._set_tethering_password(wifi_controller.DEFAULT_TETHERING_PASSWORD)

    controller._tethering_store.set_password.assert_not_called()
    assert controller.get_callback() == (\"networks_updated\", None)

  def test_invalid_tethering_password_emits_failure(self):
    controller, _, _ = make_controller()

    controller._set_tethering_password(\"x\" * 64)

    controller._tethering_store.set_password.assert_not_called()
    assert controller.get_callback() == (\"tethering_failed\", None)

""",
)
commit(
  "wifi: fix tethering settings retries",
  [
    "openpilot/system/ui/lib/wifi_manager.py",
    "openpilot/system/ui/lib/wifi_controller.py",
    "openpilot/system/ui/lib/tests/test_wifi_manager.py",
    "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  ],
)

# A failed process operation must not leave a half-owned interface behind.
replace_once(
  "openpilot/system/ui/lib/wpa_supplicant.py",
  """  if result.returncode == 0 and is_running(conf):
    return True
  if _owned_pid() is None:
    restore_networkmanager()
  return False
""",
  """  if result.returncode == 0 and is_running(conf):
    return True

  if is_running(conf) and not stop(conf):
    return False
  if _owned_pid() is None:
    restore_networkmanager()
  return False
""",
)
replace_once(
  "openpilot/system/ui/lib/wpa_supplicant.py",
  """  if subprocess.run([\"sudo\", \"kill\", str(pid)], check=False).returncode != 0:
    return False

  deadline = time.monotonic() + timeout
""",
  """  if subprocess.run([\"sudo\", \"kill\", str(pid)], check=False).returncode != 0:
    if _owned_pid(conf) is not None:
      return False
    subprocess.run([\"sudo\", \"rm\", \"-f\", WPA_PID_FILE, WPA_CTRL_PATH], check=False)
    return True

  deadline = time.monotonic() + timeout
""",
)
replace_once(
  "openpilot/system/ui/lib/tests/test_wpa_supplicant.py",
  """  def test_start_does_not_restore_networkmanager_with_owned_process(self):
    with (
      patch.object(wpa_supplicant, \"is_running\", return_value=False),
      patch.object(wpa_supplicant, \"_owned_pid\", side_effect=[None, 123]),
      patch.object(wpa_supplicant, \"prepare_runtime\"),
      patch.object(wpa_supplicant, \"release_networkmanager\", return_value=True),
      patch.object(wpa_supplicant, \"restore_networkmanager\") as restore_networkmanager,
      patch.object(wpa_supplicant.subprocess, \"run\", side_effect=[MagicMock(returncode=0), MagicMock(returncode=1)]),
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF)

    restore_networkmanager.assert_not_called()

""",
  """  def test_start_does_not_restore_networkmanager_with_owned_process(self):
    with (
      patch.object(wpa_supplicant, \"is_running\", return_value=False),
      patch.object(wpa_supplicant, \"_owned_pid\", side_effect=[None, 123]),
      patch.object(wpa_supplicant, \"prepare_runtime\"),
      patch.object(wpa_supplicant, \"release_networkmanager\", return_value=True),
      patch.object(wpa_supplicant, \"restore_networkmanager\") as restore_networkmanager,
      patch.object(wpa_supplicant.subprocess, \"run\", side_effect=[MagicMock(returncode=0), MagicMock(returncode=1)]),
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF)

    restore_networkmanager.assert_not_called()

  def test_failed_ap_start_stops_partial_owner(self):
    with (
      patch.object(wpa_supplicant, \"is_running\", side_effect=[False, True]),
      patch.object(wpa_supplicant, \"_owned_pid\", side_effect=[None, None]),
      patch.object(wpa_supplicant, \"prepare_runtime\"),
      patch.object(wpa_supplicant, \"release_networkmanager\", return_value=True),
      patch.object(wpa_supplicant, \"stop\", return_value=True) as stop,
      patch.object(wpa_supplicant, \"restore_networkmanager\") as restore_networkmanager,
      patch.object(wpa_supplicant.subprocess, \"run\", side_effect=[MagicMock(returncode=0), MagicMock(returncode=1)]),
    ):
      assert not wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF)

    stop.assert_called_once_with(wpa_supplicant.WPA_AP_CONF)
    restore_networkmanager.assert_called_once_with()

  def test_stop_accepts_process_exit_before_signal(self):
    with (
      patch.object(wpa_supplicant, \"_owned_pid\", side_effect=[123, None]),
      patch.object(wpa_supplicant.subprocess, \"run\", side_effect=[MagicMock(returncode=1), MagicMock(returncode=0)]) as run,
    ):
      assert wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF)

    assert run.call_args_list == [
      call([\"sudo\", \"kill\", \"123\"], check=False),
      call([\"sudo\", \"rm\", \"-f\", wpa_supplicant.WPA_PID_FILE, wpa_supplicant.WPA_CTRL_PATH], check=False),
    ]

""",
)
replace_once(
  "openpilot/system/ui/lib/wifi_controller.py",
  """  def _reconcile(self):
    self._assert_owner()
    try:
      status = parse_status(self._request(\"STATUS\"))
    except (OSError, RuntimeError):
      return
""",
  """  def _reconcile(self):
    self._assert_owner()
    try:
      status = parse_status(self._request(\"STATUS\"))
    except (OSError, RuntimeError):
      if wpa_supplicant.is_running(wpa_supplicant.WPA_SUPPLICANT_CONF):
        return
      self._close_ctrl()
      self._clear_l3()
      self._runtime_profiles = {}
      self._pending_profile = None
      self._temporary_network_id = None
      self._replacement_network_id = None
      self._requested_ssid = None
      self._connecting_since = 0.0
      self._state = WifiState()
      if not self._start_station():
        raise RuntimeError(\"failed to recover station wpa_supplicant\")
      return
""",
)
replace_once(
  "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  """  def test_connected_station_restarts_dhcp_when_l3_is_lost(self):
""",
  """  def test_station_request_failure_keeps_live_supplicant(self):
    controller, _, _ = make_controller()
    controller._request = MagicMock(side_effect=OSError)
    controller._start_station = MagicMock()

    with patch.object(wifi_controller.wpa_supplicant, \"is_running\", return_value=True):
      controller._reconcile()

    controller._start_station.assert_not_called()

  def test_dead_station_supplicant_is_restarted(self):
    profile = NetworkProfile(UUID_A, \"Test\", SecurityType.WPA, \"password123\")
    controller, _, dhcp = make_controller((profile,))
    controller._state = controller.state.__class__(ssid=\"Test\", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A, ipv4_address=\"10.0.0.2\")
    controller._request = MagicMock(side_effect=OSError)
    controller._close_ctrl = MagicMock()
    controller._start_station = MagicMock(return_value=True)
    controller._pending_profile = profile
    controller._temporary_network_id = \"9\"
    controller._replacement_network_id = \"3\"
    controller._requested_ssid = \"Test\"

    with patch.object(wifi_controller.wpa_supplicant, \"is_running\", return_value=False):
      controller._reconcile()

    controller._close_ctrl.assert_called_once_with()
    dhcp.stop.assert_called_once_with()
    controller._start_station.assert_called_once_with()
    assert controller.state == wifi_controller.WifiState()
    assert controller._pending_profile is None
    assert controller._temporary_network_id is None
    assert controller._replacement_network_id is None
    assert controller._requested_ssid is None

  def test_connected_station_restarts_dhcp_when_l3_is_lost(self):
""",
)
commit(
  "wifi: recover supplicant failures",
  [
    "openpilot/system/ui/lib/wpa_supplicant.py",
    "openpilot/system/ui/lib/wifi_controller.py",
    "openpilot/system/ui/lib/tests/test_wpa_supplicant.py",
    "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  ],
)

# A new profile identity cannot inherit the previous network's lease.
replace_once(
  "openpilot/system/ui/lib/wifi_controller.py",
  """    profile = self._store.get(profile_uuid)
    if profile is None:
      return

    self._requested_ssid = None
""",
  """    profile = self._store.get(profile_uuid)
    if profile is None:
      return

    if self._state.profile_uuid is not None and self._state.profile_uuid != profile_uuid:
      self._clear_l3()

    self._requested_ssid = None
""",
)
replace_once(
  "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  """  def test_auto_fallback_adopts_different_saved_ssid(self):
""",
  """  def test_adopting_different_profile_renews_dhcp(self):
    old = NetworkProfile(UUID_A, \"Old\", SecurityType.WPA, \"password123\")
    new = NetworkProfile(UUID_B, \"New\", SecurityType.WPA, \"password456\")
    controller, _, dhcp = make_controller((old, new))
    controller._state = controller.state.__class__(ssid=\"Old\", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A, ipv4_address=\"10.0.0.2\")
    controller._request = MagicMock(return_value=\"OK\\n\")
    dhcp.running = True

    def stop_dhcp():
      dhcp.running = False
      return True

    dhcp.stop.side_effect = stop_dhcp
    controller._adopt_status({\"wpa_state\": \"COMPLETED\", \"ssid\": \"New\", \"id_str\": UUID_B})

    dhcp.stop.assert_called_once_with()
    dhcp.start.assert_called_once_with()
    assert controller.state.ssid == \"New\"
    assert controller.state.profile_uuid == UUID_B
    assert controller.state.status == ConnectStatus.CONNECTING
    assert controller.state.ipv4_address == \"\"

  def test_crash_adoption_keeps_existing_dhcp(self):
    profile = NetworkProfile(UUID_A, \"Test\", SecurityType.WPA, \"password123\")
    controller, _, dhcp = make_controller((profile,))
    controller._request = MagicMock(return_value=\"OK\\n\")
    dhcp.running = True

    controller._adopt_status({\"wpa_state\": \"COMPLETED\", \"ssid\": \"Test\", \"id_str\": UUID_A})

    dhcp.stop.assert_not_called()
    dhcp.start.assert_not_called()
    assert controller.state.profile_uuid == UUID_A

  def test_auto_fallback_adopts_different_saved_ssid(self):
""",
)
commit(
  "wifi: renew DHCP after network changes",
  [
    "openpilot/system/ui/lib/wifi_controller.py",
    "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  ],
)

subprocess.run([
  "python3", "-m", "py_compile",
  "openpilot/system/ui/lib/wifi_manager.py",
  "openpilot/system/ui/lib/wifi_controller.py",
  "openpilot/system/ui/lib/wpa_supplicant.py",
  "openpilot/system/ui/lib/tests/test_wifi_manager.py",
  "openpilot/system/ui/lib/tests/test_wifi_controller.py",
  "openpilot/system/ui/lib/tests/test_wpa_supplicant.py",
], check=True)
subprocess.run(["git", "diff", "--check", EXPECTED_HEAD, "HEAD"], check=True)
subprocess.run(["git", "status", "--porcelain"], check=True)
subprocess.run(["git", "push", "origin", "HEAD:wifi-no-networkmanager-refactor"], check=True)
