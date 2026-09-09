from unittest import TestCase
from unittest.mock import MagicMock, patch

from openpilot.system.ui.lib import wifi_controller
from openpilot.system.ui.lib.wifi_controller import WifiController


class TestWifiControllerFailure(TestCase):
  def test_initialize_station_failure_retries_without_teardown(self):
    controller = WifiController(store=MagicMock(), dhcp=MagicMock(), tethering_store=MagicMock(), start=False)
    controller._initialize_station = MagicMock(side_effect=[RuntimeError, None])
    controller._shutdown = MagicMock()
    controller._close_ctrl = MagicMock()
    controller._drain_commands = MagicMock(side_effect=lambda: setattr(controller, "_exit", True))

    with (
      patch.object(wifi_controller, "clear_active_profile"),
      patch.object(wifi_controller.wpa_supplicant, "is_running", return_value=False),
      patch.object(wifi_controller.wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
      patch.object(wifi_controller.wifi_tethering.TetheringSession, "cleanup_stale", return_value=True),
      patch.object(wifi_controller.time, "sleep"),
    ):
      controller._run()

    assert controller._initialize_station.call_count == 2
    controller._shutdown.assert_not_called()
    restore_networkmanager.assert_not_called()
