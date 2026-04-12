"""Shared pytest fixtures for wifi_manager / wifi_manager_service tests."""
import threading
import time

import pytest

from openpilot.system.ui.lib.wifi_manager import (
  WifiManager,
  WifiState,
  CONNECTING_STALE_TIMEOUT_SECONDS,
  MeteredType,
)
from openpilot.system.ui.lib.wifi_manager_service import WifiManagerClient


@pytest.fixture
def wm(mocker):
  """WifiManager stub with mocked dependencies for state-machine tests."""
  mocker.patch.object(WifiManager, "_initialize")
  wm = WifiManager.__new__(WifiManager)
  wm._exit = True
  wm._ctrl = mocker.MagicMock()
  wm._dhcp = mocker.MagicMock()
  wm._store = mocker.MagicMock()
  wm._store.get_metered.return_value = 0
  wm._tethering_active = False
  wm._wifi_state = WifiState()
  wm._user_epoch = 0
  wm._callback_queue = []
  wm._callback_lock = threading.Lock()
  wm._need_auth = []
  wm._activated = []
  wm._disconnected = []
  wm._networks_updated = []
  wm._forgotten = []
  wm._networks = []
  wm._ipv4_address = ""
  wm._current_network_metered = 0
  wm._pending_connection = None
  wm._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  wm._update_active_connection_info = mocker.MagicMock()
  wm._poll_for_ip = mocker.MagicMock()
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=TestNet\n"
  return wm


@pytest.fixture
def client():
  """WifiManagerClient stub with mocked state for snapshot/event tests."""
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
  client._current_network_metered = MeteredType.UNKNOWN
  client._tethering_active = False
  client._tethering_password = ""
  client._last_seq = 0
  return client
