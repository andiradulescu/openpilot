import threading
import time

from pytest_mock import MockerFixture

from openpilot.system.ui.lib.wifi_manager import WifiManager, WifiState, ConnectStatus, CONNECTING_STALE_TIMEOUT_SECONDS, Network, SecurityType


def _make_wm(mocker: MockerFixture):
  wm = WifiManager.__new__(WifiManager)
  wm._exit = True
  wm._ctrl = mocker.MagicMock()
  wm._dhcp = mocker.MagicMock()
  wm._store = mocker.MagicMock()
  wm._tethering_active = False
  wm._wifi_state = WifiState()
  wm._callback_queue = []
  wm._callback_lock = threading.Lock()
  wm._need_auth = []
  wm._disconnected = []
  wm._activated = []
  wm._networks = []
  wm._ipv4_address = ""
  wm._current_network_metered = 0
  wm._pending_connection = None
  wm._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  wm._user_epoch = 0
  wm._poll_for_ip = mocker.MagicMock()
  return wm


def test_reconcile_stale_connecting_to_disconnected(mocker):
  wm = _make_wm(mocker)
  disconnected = mocker.MagicMock()
  wm._disconnected.append(disconnected)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  assert wm._wifi_state.ssid is None
  disconnected.assert_called_once()


def test_reconcile_stale_connecting_to_connected(mocker):
  wm = _make_wm(mocker)
  activated = mocker.MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTED
  assert wm._wifi_state.ssid == "systeam"
  wm._dhcp.start.assert_called_once()
  activated.assert_called_once()


def test_reconcile_stale_connecting_adopts_actual_connected_ssid(mocker):
  wm = _make_wm(mocker)
  activated = mocker.MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam5\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTED
  assert wm._wifi_state.ssid == "systeam5"
  wm._dhcp.start.assert_called_once()
  activated.assert_called_once()


def test_reconcile_stale_secure_network_prompts_auth(mocker):
  wm = _make_wm(mocker)
  need_auth = mocker.MagicMock()
  wm._need_auth.append(need_auth)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._networks = [Network(ssid="systeam", strength=90, security_type=SecurityType.WPA, is_tethering=False)]
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  need_auth.assert_called_once_with("systeam")


def test_reconcile_disconnected_detects_missed_connected(mocker):
  """After tethering stops, monitor may miss CONNECTED event."""
  wm = _make_wm(mocker)
  activated = mocker.MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam5\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTED
  assert wm._wifi_state.ssid == "systeam5"
  wm._dhcp.start.assert_called_once()
  activated.assert_called_once()


def test_reconcile_disconnected_stays_disconnected(mocker):
  """Don't falsely connect when wpa_supplicant is also disconnected."""
  wm = _make_wm(mocker)
  activated = mocker.MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  wm._dhcp.start.assert_not_called()
  activated.assert_not_called()


def test_reconcile_disconnected_skipped_during_tethering(mocker):
  """Don't reconcile while tethering is active."""
  wm = _make_wm(mocker)
  wm._tethering_active = True
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam\n"

  wm._reconcile_connecting_state()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  wm._ctrl.request.assert_not_called()
