import threading
from unittest import TestCase
from unittest.mock import MagicMock, patch

from openpilot.system.ui.lib import wifi_controller
from openpilot.system.ui.lib.wifi_controller import ConnectStatus, WifiController
from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkProfile
from openpilot.system.ui.lib.wifi_tethering_store import TetheringProfile
from openpilot.system.ui.lib.wpa_ctrl import SecurityType


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


def make_controller(profiles=()):
  store = MagicMock()
  store.profiles.return_value = list(profiles)
  store.profiles_for_ssid.side_effect = lambda ssid: [profile for profile in profiles if profile.ssid == ssid]
  store.get.side_effect = lambda profile_uuid: next((profile for profile in profiles if profile.uuid == profile_uuid), None)
  store.can_mutate.return_value = True
  dhcp = MagicMock()
  tethering_store = MagicMock()
  tethering_store.ensure.return_value = TetheringProfile(UUID_B, "weedle", wifi_controller.DEFAULT_TETHERING_PASSWORD)
  controller = WifiController(store=store, dhcp=dhcp, tethering_store=tethering_store, start=False)
  controller._owner_ident = threading.get_ident()
  controller._ctrl = MagicMock()
  controller._saved_ssids = frozenset(profile.ssid for profile in profiles)
  return controller, store, dhcp


class TestWifiController(TestCase):
  def setUp(self):
    self.clear_active = self.enterContext(patch.object(wifi_controller, "clear_active_profile"))
    self.write_active = self.enterContext(patch.object(wifi_controller, "write_active_profile"))

  def test_mutation_is_owner_only(self):
    controller, _, _ = make_controller()
    errors = []

    def worker():
      try:
        controller._begin_selection("Test")
      except AssertionError:
        errors.append(True)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert errors == [True]

  def test_public_saved_network_reads_do_not_touch_store(self):
    profile = NetworkProfile(UUID_A, "Saved", SecurityType.WPA, "password123")
    controller, store, _ = make_controller((profile,))
    controller._networks = (wifi_controller.Network("Saved", 50, SecurityType.WPA),)
    store.reset_mock()

    assert controller.is_connection_saved("Saved")
    assert controller.networks[0].ssid == "Saved"
    store.profiles.assert_not_called()
    store.profiles_for_ssid.assert_not_called()

  def test_owner_recovers_stores_before_initialization(self):
    controller, store, _ = make_controller()
    events = []
    controller._ctrl = None
    controller._monitor = None
    store.recover.side_effect = lambda: events.append("store")
    controller._tethering_store.recover.side_effect = lambda: events.append("tethering_store")
    controller._refresh_saved_ssids = MagicMock(side_effect=lambda: events.append("snapshot"))
    controller._initialize_tethering_profile = MagicMock(side_effect=lambda: events.append("tethering_profile"))
    controller._initialize_station = MagicMock(side_effect=lambda: events.append("station"))

    def drain():
      controller._exit = True

    controller._drain_commands = MagicMock(side_effect=drain)
    controller._close_ctrl = MagicMock()
    with (
      patch.object(wifi_controller.wpa_supplicant, "is_running", return_value=False),
      patch.object(wifi_controller.wifi_tethering.TetheringSession, "cleanup_stale", return_value=True),
    ):
      controller._run()

    assert events == ["store", "tethering_store", "snapshot", "tethering_profile", "station"]

  def test_activate_enables_all_profiles_for_same_ssid(self):
    profiles = (
      NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123", priority=10),
      NetworkProfile(UUID_B, "Test", SecurityType.WPA, "password456", priority=20),
    )
    controller, _, _ = make_controller(profiles)
    controller._runtime_profiles = {UUID_A: "3", UUID_B: "7"}
    controller._request = MagicMock(return_value="OK\n")

    controller._activate("Test")

    assert [call.args[0] for call in controller._request.call_args_list] == [
      "DISABLE_NETWORK all",
      "ENABLE_NETWORK 3",
      "ENABLE_NETWORK 7",
      "REASSOCIATE",
    ]
    assert controller.state.ssid == "Test"
    assert controller.state.status == ConnectStatus.CONNECTING

  def test_connected_status_uses_exact_profile_metering(self):
    profiles = (
      NetworkProfile(UUID_A, "Duplicate", SecurityType.WPA, "password123", metered=MeteredType.NO),
      NetworkProfile(UUID_B, "Duplicate", SecurityType.WPA, "password456", metered=MeteredType.YES),
    )
    controller, _, dhcp = make_controller(profiles)
    controller._request = MagicMock(return_value="OK\n")
    dhcp.running = False

    controller._adopt_status({"wpa_state": "COMPLETED", "ssid": "Duplicate", "id_str": UUID_B})

    assert controller.state.profile_uuid == UUID_B
    assert controller.state.metered == MeteredType.YES
    dhcp.start.assert_called_once()

  def test_stale_connected_status_does_not_replace_explicit_selection(self):
    profile = NetworkProfile(UUID_A, "Old", SecurityType.WPA, "password123")
    controller, _, dhcp = make_controller((profile,))
    controller._requested_ssid = "New"

    controller._adopt_status({"wpa_state": "COMPLETED", "ssid": "Old", "id_str": UUID_A})

    assert controller.state.status == ConnectStatus.DISCONNECTED
    dhcp.start.assert_not_called()

  def test_conflicting_security_scan_is_unsupported(self):
    controller, _, _ = make_controller()
    controller._request = MagicMock(side_effect=[
      "OK\n",
      "bssid / frequency / signal level / flags / ssid\n"
      "00:11:22:33:44:55\t2412\t-40\t[ESS]\tSame\n"
      "00:11:22:33:44:66\t2412\t-50\t[WPA2-PSK-CCMP][ESS]\tSame\n",
    ])

    controller._scan()

    assert len(controller.networks) == 1
    assert controller.networks[0].security_type == SecurityType.UNSUPPORTED

  def test_completed_association_waits_for_dhcp_before_activated(self):
    profile = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123", metered=MeteredType.YES)
    controller, _, dhcp = make_controller((profile,))
    controller._state = controller.state.__class__(ssid="Test", status=ConnectStatus.CONNECTING, profile_uuid=UUID_A, metered=MeteredType.YES)
    controller._request = MagicMock(return_value=f"wpa_state=COMPLETED\nssid=Test\nid_str={UUID_A}\n")
    dhcp.running = True
    dhcp.ready.return_value = True
    dhcp.ipv4_address.return_value = "10.0.0.2"

    controller._reconcile()

    assert controller.state.status == ConnectStatus.CONNECTED
    assert controller.state.ipv4_address == "10.0.0.2"
    assert controller.state.metered == MeteredType.YES
    self.write_active.assert_called_once_with(UUID_A, int(MeteredType.YES))
    assert controller.get_callback() == ("activated", None)

  def test_auto_fallback_adopts_different_saved_ssid(self):
    old = NetworkProfile(UUID_A, "Old", SecurityType.WPA, "password123")
    fallback = NetworkProfile(UUID_B, "Fallback", SecurityType.WPA, "password456")
    controller, _, dhcp = make_controller((old, fallback))
    controller._state = controller.state.__class__(ssid="Old", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A)
    controller._request = MagicMock(return_value="OK\n")
    dhcp.running = False

    controller._link_lost()
    controller._adopt_status({"wpa_state": "COMPLETED", "ssid": "Fallback", "id_str": UUID_B})

    assert controller.state.ssid == "Fallback"
    assert controller.state.profile_uuid == UUID_B
    assert controller.state.status == ConnectStatus.CONNECTING

  def test_credential_replacement_reuses_profile_uuid(self):
    old = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "old-password", priority=42, metered=MeteredType.YES)
    controller, _, _ = make_controller((old,))
    controller._runtime_profiles = {UUID_A: "3"}
    controller._request = MagicMock(side_effect=["9", "OK", "OK", "OK", "OK", "OK", "OK", "OK"])

    controller._connect(wifi_controller._Connect("Test", "new-password", False, SecurityType.WPA))

    assert controller._pending_profile is not None
    assert controller._pending_profile.uuid == UUID_A
    assert controller._pending_profile.priority == 42
    assert controller._pending_profile.metered == MeteredType.YES
    assert controller._replacement_network_id == "3"
    assert controller._runtime_profiles[UUID_A] == "9"

  def test_readonly_saved_profile_rejects_credential_replacement(self):
    old = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "old-password")
    controller, store, _ = make_controller((old,))
    store.can_mutate.return_value = False
    controller._request = MagicMock()

    controller._connect(wifi_controller._Connect("Test", "new-password", False, SecurityType.WPA))

    controller._request.assert_not_called()
    assert controller.get_callback() == ("profile_readonly", "Test")

  def test_failed_replacement_restores_old_runtime_mapping(self):
    old = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "old-password")
    controller, _, _ = make_controller((old,))
    controller._runtime_profiles = {UUID_A: "3"}
    controller._pending_profile = old
    controller._temporary_network_id = "9"
    controller._replacement_network_id = "3"
    controller._runtime_profiles[UUID_A] = "9"
    controller._request = MagicMock(return_value="OK")

    controller._cancel_selection()

    assert controller._runtime_profiles[UUID_A] == "3"
    assert controller._replacement_network_id is None

  def test_forget_disables_runtime_before_durable_remove(self):
    profile = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123")
    controller, store, _ = make_controller((profile,))
    controller._runtime_profiles = {UUID_A: "3"}
    events = []
    controller._request = MagicMock(side_effect=lambda command: events.append(command) or "OK")
    store.remove_ssid.side_effect = lambda ssid: events.append(f"remove:{ssid}") or True
    store.profiles.return_value = []

    with patch.object(wifi_controller.wpa_supplicant, "write_station_config"):
      controller._forget("Test")

    assert events[0:2] == ["DISABLE_NETWORK 3", "remove:Test"]
    assert not controller.is_connection_saved("Test")
    assert controller.get_callback() == ("forgotten", "Test")

  def test_set_metered_updates_exact_active_profile(self):
    old = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123", metered=MeteredType.NO)
    updated = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123", metered=MeteredType.YES)
    controller, store, _ = make_controller((old,))
    controller._state = controller.state.__class__(ssid="Test", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A, metered=MeteredType.NO)
    store.set_metered.return_value = updated

    controller._set_metered(MeteredType.YES)

    store.set_metered.assert_called_once_with(UUID_A, MeteredType.YES)
    self.write_active.assert_called_once_with(UUID_A, int(MeteredType.YES))
    assert controller.state.metered == MeteredType.YES

  def test_failed_metered_update_emits_settings_failure(self):
    profile = NetworkProfile(UUID_A, "Test", SecurityType.WPA, "password123")
    controller, store, _ = make_controller((profile,))
    controller._state = controller.state.__class__(ssid="Test", status=ConnectStatus.CONNECTED, profile_uuid=UUID_A)
    store.set_metered.return_value = None

    controller._set_metered(MeteredType.YES)

    assert controller.get_callback() == ("settings_failed", "Test")

  def test_enter_tethering_switches_from_station(self):
    controller, _, _ = make_controller()
    controller._close_ctrl = MagicMock()
    controller._clear_l3 = MagicMock()
    controller._tethering.start = MagicMock(return_value=True)

    with (
      patch.object(wifi_controller.wpa_supplicant, "write_ap_config") as write_ap_config,
      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=True) as stop_wpa,
      patch.object(wifi_controller.wpa_supplicant, "start", return_value=True) as start_wpa,
    ):
      controller._enter_tethering()

    write_ap_config.assert_called_once_with("weedle", wifi_controller.DEFAULT_TETHERING_PASSWORD)
    stop_wpa.assert_called_once_with(wifi_controller.wpa_supplicant.WPA_SUPPLICANT_CONF)
    start_wpa.assert_called_once_with(wifi_controller.wpa_supplicant.WPA_AP_CONF)
    controller._tethering.start.assert_called_once_with(False)
    assert controller.tethering_active
    assert controller.state.ssid == "weedle"
    assert controller.state.status == ConnectStatus.CONNECTED

  def test_failed_ap_start_restores_station(self):
    controller, _, _ = make_controller()
    controller._close_ctrl = MagicMock()
    controller._clear_l3 = MagicMock()
    controller._restore_station_after_tethering_failure = MagicMock()

    with (
      patch.object(wifi_controller.wpa_supplicant, "write_ap_config"),
      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=True),
      patch.object(wifi_controller.wpa_supplicant, "start", return_value=False),
    ):
      controller._enter_tethering()

    controller._restore_station_after_tethering_failure.assert_called_once()
    assert not controller.tethering_active
    assert controller.get_callback() == ("tethering_failed", None)

  def test_failed_ap_stop_keeps_tethering_resources(self):
    controller, _, _ = make_controller()
    controller._tethering_active = True
    controller._state = controller.state.__class__(ssid="weedle", status=ConnectStatus.CONNECTED)
    controller._tethering.stop = MagicMock(return_value=True)

    with patch.object(wifi_controller.wpa_supplicant, "stop", return_value=False):
      controller._leave_tethering()

    controller._tethering.stop.assert_not_called()
    assert controller.tethering_active
    assert controller.state.ssid == "weedle"
    assert controller.get_callback() == ("tethering_failed", None)

  def test_inactive_tethering_password_is_persisted_before_memory_update(self):
    controller, _, _ = make_controller()
    controller._tethering_store.set_password.return_value = TetheringProfile(UUID_B, "weedle", "new-password")

    controller._set_tethering_password("new-password")

    controller._tethering_store.set_password.assert_called_once_with("weedle", "new-password")
    assert controller.tethering_password == "new-password"

  def test_failed_tethering_password_persistence_keeps_old_password(self):
    controller, _, _ = make_controller()
    controller._tethering_store.set_password.return_value = None

    controller._set_tethering_password("new-password")

    assert controller.tethering_password == wifi_controller.DEFAULT_TETHERING_PASSWORD
    assert controller.get_callback() == ("tethering_failed", None)

  def test_active_tethering_forwarding_update_is_serialized(self):
    controller, _, _ = make_controller()
    controller._tethering_active = True

    with patch.object(wifi_controller.wifi_tethering, "set_ipv4_forward") as set_forward:
      controller._set_ipv4_forward(True)

    set_forward.assert_called_once_with(True)
    assert controller._ipv4_forward
