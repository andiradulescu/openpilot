from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from openpilot.system.ui.lib.tests import test_wifi_manager
from openpilot.system.ui.lib.wifi_manager import Network, SecurityType


class TestWifiForgetUI(TestCase):
  def test_tici_failure_clears_pending_state_and_allows_retry(self):
    from openpilot.system.ui.widgets import network

    manager, controller = test_wifi_manager.TestWifiManager().make_manager()
    widget = network.WifiManagerUI.__new__(network.WifiManagerUI)
    widget._wifi_manager = manager
    entry = Network("Test", 80, SecurityType.WPA, False)
    widget.forget_network(entry)
    manager.add_callbacks(forget_failed=widget._on_forget_failed)
    controller.get_callback.side_effect = [("forget_failed", "Test"), None]

    with patch.object(network, "alert_dialog") as alert, patch.object(network.gui_app, "push_widget") as push:
      manager.process_callbacks()
      alert.assert_called_once()
      push.assert_called_once_with(alert.return_value)

    assert widget.state == network.UIState.IDLE
    widget.forget_network(entry)
    assert widget.state == network.UIState.FORGETTING
    assert controller.forget.call_count == 2

  def test_tici_unrelated_failure_does_not_finish_pending_operation(self):
    from openpilot.system.ui.widgets import network

    widget = network.WifiManagerUI.__new__(network.WifiManagerUI)
    widget.state = network.UIState.FORGETTING
    widget._state_network = Network("Other", 80, SecurityType.WPA, False)

    with patch.object(network.gui_app, "push_widget") as push:
      widget._on_forget_failed("Test")

    assert widget.state == network.UIState.FORGETTING
    push.assert_not_called()

  def test_mici_failure_clears_only_matching_button_and_allows_retry(self):
    from openpilot.selfdrive.ui.mici.layouts.settings.network import wifi_ui

    manager, controller = test_wifi_manager.TestWifiManager().make_manager()
    buttons = []
    for ssid in ("Test", "Other"):
      button = wifi_ui.WifiButton.__new__(wifi_ui.WifiButton)
      button._wifi_manager = manager
      button._network = Network(ssid, 80, SecurityType.WPA, False)
      button._network_forgetting = False
      button._forget_network()
      buttons.append(button)
    widget = wifi_ui.WifiUIMici.__new__(wifi_ui.WifiUIMici)
    widget._scroller = SimpleNamespace(items=buttons)
    manager.add_callbacks(forget_failed=widget._on_forget_failed)
    controller.get_callback.side_effect = [("forget_failed", "Test"), None]

    with patch.object(wifi_ui, "BigDialog") as dialog, patch.object(wifi_ui.gui_app, "push_widget") as push:
      manager.process_callbacks()
      dialog.assert_called_once()
      push.assert_called_once_with(dialog.return_value)

    assert not buttons[0].network_forgetting
    assert buttons[1].network_forgetting
    buttons[0]._forget_network()
    assert buttons[0].network_forgetting
    assert controller.forget.call_count == 3
