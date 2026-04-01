import time
from unittest.mock import MagicMock

from openpilot.system.ui.lib.wifi_manager import WifiManager, WifiState, ConnectStatus, CONNECTING_STALE_TIMEOUT_SECONDS, Network, SecurityType


def _make_wm():
  wm = WifiManager.__new__(WifiManager)
  wm._exit = True
  wm._ctrl = MagicMock()
  wm._dhcp = MagicMock()
  wm._store = MagicMock()
  wm._tethering_active = False
  wm._wifi_state = WifiState()
  wm._callback_queue = []
  wm._need_auth = []
  wm._disconnected = []
  wm._activated = []
  wm._networks = []
  wm._ipv4_address = ""
  wm._current_network_metered = 0
  wm._pending_connection = None
  wm._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  wm._user_epoch = 0
  wm._poll_for_ip = MagicMock()
  return wm


def test_reconcile_stale_connecting_to_disconnected():
  wm = _make_wm()
  disconnected = MagicMock()
  wm._disconnected.append(disconnected)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  assert wm._wifi_state.ssid is None
  disconnected.assert_called_once()


def test_reconcile_stale_connecting_to_connected():
  wm = _make_wm()
  activated = MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTED
  assert wm._wifi_state.ssid == "systeam"
  wm._dhcp.start.assert_called_once()
  activated.assert_called_once()


def test_reconcile_stale_connecting_adopts_actual_connected_ssid():
  wm = _make_wm()
  activated = MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam5\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTED
  assert wm._wifi_state.ssid == "systeam5"
  wm._dhcp.start.assert_called_once()
  activated.assert_called_once()


def test_reconcile_stale_secure_network_prompts_auth():
  wm = _make_wm()
  need_auth = MagicMock()
  wm._need_auth.append(need_auth)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._networks = [Network(ssid="systeam", strength=90, security_type=SecurityType.WPA, is_tethering=False)]
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  need_auth.assert_called_once_with("systeam")
