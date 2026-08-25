from unittest import TestCase
from unittest.mock import MagicMock, patch

from openpilot.system.ui.lib import wifi_controller
from openpilot.system.ui.lib.wifi_controller import WifiController


class TestWifiControllerFailure(TestCase):
  def test_active_tethering_cleanup_does_not_require_ap_process(self):
    controller = WifiController(store=MagicMock(), dhcp=MagicMock(), tethering_store=MagicMock(), start=False)
    controller._tethering_active = True
    controller._initialize_station = MagicMock(side_effect=RuntimeError)
    controller._shutdown = MagicMock()
    controller._close_ctrl = MagicMock()

    with (
      patch.object(wifi_controller, "clear_active_profile"),
      patch.object(wifi_controller.wpa_supplicant, "is_running", return_value=False),
      patch.object(wifi_controller.wifi_tethering.TetheringSession, "cleanup_stale", return_value=True),
    ):
      controller._run()

    controller._shutdown.assert_called_once_with()
