import time

from openpilot.system.ui.lib.wifi_manager import (
  CONNECTING_STALE_TIMEOUT_SECONDS,
  ConnectStatus,
  Network,
  PendingConnection,
  SecurityType,
  WifiState,
)


def test_reconcile_stale_connecting_to_disconnected(wm, mocker):
  disconnected = mocker.MagicMock()
  wm._disconnected.append(disconnected)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  assert wm._wifi_state.ssid is None
  disconnected.assert_called_once()


def test_reconcile_stale_connecting_to_connected(wm, mocker):
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


def test_reconcile_stale_connecting_adopts_actual_connected_ssid(wm, mocker):
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


def test_reconcile_stale_secure_network_prompts_auth(wm, mocker):
  need_auth = mocker.MagicMock()
  wm._need_auth.append(need_auth)
  wm._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
  wm._networks = [Network(ssid="systeam", strength=90, security_type=SecurityType.WPA, is_tethering=False)]
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  need_auth.assert_called_once_with("systeam")


def test_reconcile_disconnected_detects_missed_connected(wm, mocker):
  """After tethering stops, monitor may miss CONNECTED event."""
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


def test_reconcile_disconnected_stays_disconnected(wm, mocker):
  """Don't falsely connect when wpa_supplicant is also disconnected."""
  activated = mocker.MagicMock()
  wm._activated.append(activated)
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"

  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  wm._dhcp.start.assert_not_called()
  activated.assert_not_called()


def test_reconcile_disconnected_skipped_during_tethering(wm):
  """Don't reconcile while tethering is active."""
  wm._tethering_active = True
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=systeam\n"

  wm._reconcile_connecting_state()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  wm._ctrl.request.assert_not_called()


def test_reconcile_scanning_keeps_connecting(wm, mocker):
  """wpa_supplicant can remain in SCANNING past the stale window for
  legitimate reasons (hidden SSIDs, slow directed-probe responses). We
  must not synthesize a wrong-password failure — that would clear the
  pending credentials and drop back to disconnected, preventing the
  eventual successful connect from being persisted."""
  need_auth = mocker.MagicMock()
  disconnected = mocker.MagicMock()
  wm._need_auth.append(need_auth)
  wm._disconnected.append(disconnected)
  wm._wifi_state = WifiState(ssid="HiddenAP", status=ConnectStatus.CONNECTING)
  wm._networks = [Network(ssid="HiddenAP", strength=90, security_type=SecurityType.WPA, is_tethering=False)]
  wm._pending_connection = PendingConnection(ssid="HiddenAP", password="secret", hidden=True, epoch=1)
  wm._ctrl.request.return_value = "wpa_state=SCANNING\n"

  before = time.monotonic()
  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.CONNECTING
  assert wm._wifi_state.ssid == "HiddenAP"
  assert wm._pending_connection is not None, "pending credentials must survive SCANNING"
  need_auth.assert_not_called()
  disconnected.assert_not_called()
  # Timestamp refreshed so we wait another full window before re-checking.
  assert wm._last_connecting_at >= before


def test_reconcile_scanning_then_disconnected_fires_need_auth(wm, mocker):
  """Once SCANNING transitions to DISCONNECTED/INACTIVE, the terminal
  failure path still runs — we just don't run it prematurely on SCANNING."""
  need_auth = mocker.MagicMock()
  wm._need_auth.append(need_auth)
  wm._wifi_state = WifiState(ssid="HiddenAP", status=ConnectStatus.CONNECTING)
  wm._networks = [Network(ssid="HiddenAP", strength=90, security_type=SecurityType.WPA, is_tethering=False)]
  wm._pending_connection = PendingConnection(ssid="HiddenAP", password="secret", hidden=True, epoch=1)

  # First pass: SCANNING → keep waiting, refresh window.
  wm._ctrl.request.return_value = "wpa_state=SCANNING\n"
  wm._reconcile_connecting_state()
  wm.process_callbacks()
  need_auth.assert_not_called()
  assert wm._wifi_state.status == ConnectStatus.CONNECTING

  # Expire the fresh window and let DISCONNECTED resolve it.
  wm._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  wm._ctrl.request.return_value = "wpa_state=DISCONNECTED\n"
  wm._reconcile_connecting_state()
  wm.process_callbacks()

  assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
  need_auth.assert_called_once_with("HiddenAP")
