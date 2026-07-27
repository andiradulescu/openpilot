from importlib import import_module
import os
from unittest import SkipTest, skipUnless, TestCase
from unittest.mock import MagicMock, patch

previous_scale = os.environ.get("SCALE")
os.environ["SCALE"] = "1"
try:
  try:
    import_module("pyray")
  except ImportError:
    pyray_available = False
  else:
    pyray_available = True
    from openpilot.system.ui.tici_setup import Setup, SetupState
    from openpilot.system.ui.tici_updater import Screen, Updater
    from openpilot.system.ui.widgets.network import UIState, WifiManagerUI
finally:
  if previous_scale is None:
    del os.environ["SCALE"]
  else:
    os.environ["SCALE"] = previous_scale


@skipUnless(pyray_available, "pyray is unavailable")
class TestStandaloneWifi(TestCase):
  def test_setup_activates_scanning_only_on_network_screen(self):
    setup = Setup.__new__(Setup)
    setup.state = SetupState.SOFTWARE_SELECTION
    setup.wifi_manager = MagicMock()

    setup.set_state(SetupState.NETWORK_SETUP)
    setup.wifi_manager.set_active.assert_called_once_with(True)

    setup.set_state(SetupState.SOFTWARE_SELECTION)
    setup.wifi_manager.set_active.assert_called_with(False)

  def test_updater_activates_scanning_only_on_wifi_screen(self):
    updater = Updater.__new__(Updater)
    updater.current_screen = Screen.PROMPT
    updater.wifi_manager = MagicMock()

    updater.set_current_screen(Screen.WIFI)
    updater.wifi_manager.set_active.assert_called_once_with(True)

    updater.set_current_screen(Screen.PROMPT)
    updater.wifi_manager.set_active.assert_called_with(False)

  def test_forget_failure_releases_wifi_controls(self):
    wifi_ui = WifiManagerUI.__new__(WifiManagerUI)
    wifi_ui.state = UIState.FORGETTING

    wifi_ui._on_forget_failed("SavedNet")

    assert wifi_ui.state == UIState.IDLE

  def test_mici_network_layout_deactivates_scanning_when_hidden(self):
    try:
      from openpilot.selfdrive.ui.mici.layouts.settings.network import network_layout as network_layout_module
      from openpilot.selfdrive.ui.mici.layouts.settings.network.network_layout import NetworkLayoutMici
    except ImportError as e:
      raise SkipTest("mici UI dependencies are unavailable") from e

    layout = NetworkLayoutMici.__new__(NetworkLayoutMici)
    layout._wifi_manager = MagicMock()

    with (
      patch.object(network_layout_module.NavScroller, "hide_event"),
      patch.object(network_layout_module.gui_app, "remove_nav_stack_tick"),
    ):
      layout.hide_event()

    layout._wifi_manager.set_active.assert_called_once_with(False)
