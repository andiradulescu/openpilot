from openpilot.system.ui.lib.wifi_manager import WifiState, ConnectStatus, Network, SecurityType


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
