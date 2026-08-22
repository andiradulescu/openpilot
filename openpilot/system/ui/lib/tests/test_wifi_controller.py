import threading
from unittest import TestCase
from unittest.mock import MagicMock, patch

from openpilot.system.ui.lib.wifi_controller import ConnectStatus, WifiController
from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkProfile
from openpilot.system.ui.lib.wpa_ctrl import SecurityType


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


def make_controller(profiles=()):
  store = MagicMock()
  store.profiles.return_value = list(profiles)
  store.profiles_for_ssid.side_effect = lambda ssid: [profile for profile in profiles if profile.ssid == ssid]
  store.get.side_effect = lambda profile_uuid: next((profile for profile in profiles if profile.uuid == profile_uuid), None)
  dhcp = MagicMock()
  controller = WifiController(store=store, dhcp=dhcp, start=False)
  controller._owner_ident = threading.get_ident()
  controller._ctrl = MagicMock()
  return controller, store, dhcp


class TestWifiController(TestCase):
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
    assert controller.get_callback() == ("activated", None)
