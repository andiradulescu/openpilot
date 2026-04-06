import threading
from unittest.mock import MagicMock

from openpilot.system.ui.lib.wifi_manager import ConnectStatus, WifiState
from openpilot.system.ui.lib.wifi_manager_service import WifiManagerClient


def _make_client():
  client = WifiManagerClient.__new__(WifiManagerClient)
  client._callback_queue = []
  client._callback_lock = threading.Lock()
  client._need_auth = []
  client._activated = []
  client._forgotten = []
  client._networks_updated = []
  client._disconnected = []
  client._networks = []
  client._saved_ssids = set()
  client._wifi_state = WifiState()
  client._ipv4_address = ""
  client._current_network_metered = 0
  client._tethering_active = False
  client._tethering_password = ""
  return client


def test_connecting_to_disconnected_fires_callback():
  client = _make_client()
  client._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  disconnected = MagicMock()
  client._disconnected.append(disconnected)

  client._apply_snapshot({
    "networks": [],
    "saved_ssids": [],
    "wifi_state": {"ssid": None, "status": int(ConnectStatus.DISCONNECTED)},
    "ipv4_address": "",
    "current_network_metered": 0,
    "tethering_active": False,
    "tethering_password": "",
  })
  client.process_callbacks()

  disconnected.assert_called_once()
