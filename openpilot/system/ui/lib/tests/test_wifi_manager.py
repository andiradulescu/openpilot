from unittest import TestCase
from unittest.mock import MagicMock, patch

from openpilot.system.ui.lib import wifi_manager
from openpilot.system.ui.lib.wifi_controller import ConnectStatus as ControllerConnectStatus
from openpilot.system.ui.lib.wifi_controller import Network as ControllerNetwork
from openpilot.system.ui.lib.wifi_controller import WifiState as ControllerWifiState
from openpilot.system.ui.lib.wifi_network_store import MeteredType as StoreMeteredType
from openpilot.system.ui.lib.wpa_ctrl import SecurityType as ControllerSecurityType


class TestWifiManager(TestCase):
  def make_manager(self):
    controller = MagicMock()
    controller.state = ControllerWifiState()
    controller.networks = ()
    controller.tethering_active = False
    controller.tethering_password = "swagswagcomma"
    controller.get_callback.return_value = None
    with (
      patch.object(wifi_manager, "Params", None),
      patch.object(wifi_manager, "WifiController", return_value=controller),
      patch.object(wifi_manager.atexit, "register"),
    ):
      manager = wifi_manager.WifiManager()
    return manager, controller

  def test_connect_translates_open_and_wpa_security(self):
    manager, controller = self.make_manager()

    manager.connect_to_network("Open", "")
    manager.connect_to_network("Secure", "password123", hidden=True)

    assert controller.connect.call_args_list[0].args == ("Open", "", False, ControllerSecurityType.OPEN)
    assert controller.connect.call_args_list[1].args == ("Secure", "password123", True, ControllerSecurityType.WPA)

  def test_forwarding_is_edge_triggered(self):
    manager, controller = self.make_manager()

    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(True)
    manager.set_ipv4_forward(False)

    assert [call.args[0] for call in controller.set_ipv4_forward.call_args_list] == [True, False]

  def test_network_update_preserves_legacy_shape(self):
    manager, controller = self.make_manager()
    controller.networks = (ControllerNetwork("Test", 77, ControllerSecurityType.WPA),)
    controller.get_callback.side_effect = [("networks_updated", None), None]
    updates = []
    manager.add_callbacks(networks_updated=updates.append)

    manager.process_callbacks()

    assert updates == [[wifi_manager.Network("Test", 77, wifi_manager.SecurityType.WPA, False)]]

  def test_tethering_failure_refreshes_advanced_state(self):
    manager, controller = self.make_manager()
    controller.get_callback.side_effect = [("tethering_failed", None), None]
    updates = []
    manager.add_callbacks(networks_updated=updates.append)

    manager.process_callbacks()

    assert updates == [[]]

  def test_active_tethering_uses_legacy_network_entry(self):
    manager, controller = self.make_manager()
    controller.tethering_active = True
    controller.state = ControllerWifiState(ssid="weedle-1234", status=ControllerConnectStatus.CONNECTED, ipv4_address="192.168.43.1")

    assert manager.networks == [wifi_manager.Network("weedle-1234", 100, wifi_manager.SecurityType.WPA, True)]
    assert manager.connected_ssid == "weedle-1234"
    assert manager.ipv4_address == "192.168.43.1"

  def test_metered_value_translates_to_controller_enum(self):
    manager, controller = self.make_manager()

    manager.set_current_network_metered(wifi_manager.MeteredType.YES)

    controller.set_metered.assert_called_once_with(StoreMeteredType.YES)
