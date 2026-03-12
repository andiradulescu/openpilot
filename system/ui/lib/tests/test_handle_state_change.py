"""Tests for WifiManager wpa_supplicant event-based state machine.

Tests the state machine in isolation by constructing a WifiManager with mocked
wpa_supplicant, then calling _handle_event directly with wpa_supplicant events.
"""
from pytest_mock import MockerFixture

from openpilot.system.ui.lib.wifi_manager import WifiManager, WifiState, ConnectStatus


def _make_wm(mocker: MockerFixture, saved_networks=None):
  """Create a WifiManager with only the fields _handle_event touches."""
  mocker.patch.object(WifiManager, '_initialize')
  wm = WifiManager.__new__(WifiManager)
  wm._exit = True
  wm._ctrl = mocker.MagicMock()
  wm._dhcp = mocker.MagicMock()
  wm._tethering_active = False
  wm._wifi_state = WifiState()
  wm._user_epoch = 0
  wm._callback_queue = []
  wm._need_auth = []
  wm._activated = []
  wm._disconnected = []
  wm._networks_updated = []
  wm._forgotten = []
  wm._ipv4_address = ""
  wm._current_network_metered = 0
  wm._update_active_connection_info = mocker.MagicMock()

  # Mock store
  wm._store = mocker.MagicMock()
  wm._store.contains.side_effect = lambda ssid: ssid in (saved_networks or {})
  wm._store.get_metered.return_value = 0

  # Default STATUS response
  wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=TestNet\n"
  return wm


def fire(wm: WifiManager, event: str) -> None:
  """Feed a wpa_supplicant event into the handler."""
  wm._handle_event(event)


# ---------------------------------------------------------------------------
# Basic transitions
# ---------------------------------------------------------------------------

class TestConnected:
  def test_connected_sets_state(self, mocker):
    wm = _make_wm(mocker)
    wm._set_connecting("MyNet")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=MyNet\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]")

    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "MyNet"
    wm._dhcp.start.assert_called_once()

  def test_connected_fires_activated_callback(self, mocker):
    wm = _make_wm(mocker)
    cb = mocker.MagicMock()
    wm.add_callbacks(activated=cb)
    wm._set_connecting("Net")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Net\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    wm.process_callbacks()
    cb.assert_called_once()


class TestDisconnected:
  def test_disconnected_clears_state(self, mocker):
    wm = _make_wm(mocker)
    wm._wifi_state = WifiState(ssid="Net", status=ConnectStatus.CONNECTED)

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid is None
    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm._dhcp.stop.assert_called_once()

  def test_disconnected_preserves_connecting(self, mocker):
    """If user just initiated a connect, don't clear the connecting state."""
    wm = _make_wm(mocker)
    wm._set_connecting("NewNet")

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid == "NewNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_disconnected_during_tethering_ignored(self, mocker):
    wm = _make_wm(mocker)
    wm._wifi_state = WifiState(ssid="tether", status=ConnectStatus.CONNECTED)
    wm._tethering_active = True

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid == "tether"
    assert wm._wifi_state.status == ConnectStatus.CONNECTED

  def test_disconnected_fires_callback(self, mocker):
    wm = _make_wm(mocker)
    cb = mocker.MagicMock()
    wm.add_callbacks(disconnected=cb)
    wm._wifi_state = WifiState(ssid="Net", status=ConnectStatus.CONNECTED)

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    wm.process_callbacks()
    cb.assert_called_once()


class TestWrongPassword:
  def test_wrong_key_fires_need_auth(self, mocker):
    wm = _make_wm(mocker)
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)
    wm._set_connecting("SecNet")

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"SecNet\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm.process_callbacks()
    cb.assert_called_once_with("SecNet")

  def test_wrong_key_no_ssid_no_callback(self, mocker):
    wm = _make_wm(mocker)
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Net\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert len(wm._callback_queue) == 0


class TestAutoConnect:
  def test_trying_to_associate_sets_connecting(self, mocker):
    """Auto-connect: wpa_supplicant connects on its own."""
    wm = _make_wm(mocker)
    wm._ctrl.request.return_value = "wpa_state=ASSOCIATING\nssid=AutoNet\n"

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='AutoNet' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "AutoNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_auto_connect_doesnt_overwrite_user_connecting(self, mocker):
    """If user initiated connect, auto-connect event is ignored."""
    wm = _make_wm(mocker)
    wm._set_connecting("UserNet")

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='OtherNet' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "UserNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING


class TestScanResults:
  def test_scan_results_triggers_update(self, mocker):
    wm = _make_wm(mocker)
    wm._active = True
    wm._scan_lock = mocker.MagicMock()
    wm._tethering_ssid = "weedle"
    wm._networks = []
    # Mock scan results
    wm._ctrl.request.return_value = "bssid / frequency / signal level / flags / ssid\naa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tTestNet\n"
    wm._update_networks = mocker.MagicMock()

    fire(wm, "CTRL-EVENT-SCAN-RESULTS")

    wm._update_networks.assert_called_once()


# ---------------------------------------------------------------------------
# Thread races: _set_connecting vs _handle_event
# ---------------------------------------------------------------------------

class TestThreadRaces:
  def test_connected_race_user_tap_during_status(self, mocker):
    """User taps B right as A finishes connecting (STATUS call in flight)."""
    wm = _make_wm(mocker)
    wm._set_connecting("A")

    def user_taps_b_during_status(cmd):
      if cmd == "STATUS":
        wm._set_connecting("B")
        return "wpa_state=COMPLETED\nssid=A\n"
      return ""

    wm._ctrl.request.side_effect = user_taps_b_during_status

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    assert wm._wifi_state.ssid == "B"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_auto_connect_race_user_tap_during_status(self, mocker):
    """User taps B while auto-connect STATUS lookup is in flight."""
    wm = _make_wm(mocker)

    def user_taps_b_during_status(cmd):
      if cmd == "STATUS":
        wm._set_connecting("B")
        return "wpa_state=ASSOCIATING\nssid=A\n"
      return ""

    wm._ctrl.request.side_effect = user_taps_b_during_status

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='A' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "B"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING


# ---------------------------------------------------------------------------
# Full sequences
# ---------------------------------------------------------------------------

class TestFullSequences:
  def test_normal_connect(self, mocker):
    """User connects → CONNECTED event → gets IP."""
    wm = _make_wm(mocker)
    wm._set_connecting("Home")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Home\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "Home"
    wm._dhcp.start.assert_called_once()

  def test_wrong_password_then_retry(self, mocker):
    """Wrong password → need_auth callback → user retries."""
    wm = _make_wm(mocker)
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)

    wm._set_connecting("Sec")
    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Sec\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm.process_callbacks()
    cb.assert_called_once_with("Sec")

    # Retry
    wm._set_connecting("Sec")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Sec\n"
    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "Sec"

  def test_connect_then_disconnect(self, mocker):
    """Connect, then network drops."""
    wm = _make_wm(mocker)
    wm._set_connecting("Net")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Net\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")
    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    assert wm._wifi_state.ssid is None

  def test_auto_connect_full_sequence(self, mocker):
    """wpa_supplicant auto-connects to saved network."""
    wm = _make_wm(mocker)
    wm._ctrl.request.return_value = "wpa_state=ASSOCIATING\nssid=AutoNet\n"

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='AutoNet' freq=2437 MHz)")
    assert wm._wifi_state.ssid == "AutoNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=AutoNet\n"
    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "AutoNet"

  def test_switch_networks(self, mocker):
    """User switches from A to B."""
    wm = _make_wm(mocker)
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=A\n"
    wm._set_connecting("A")
    fire(wm, "CTRL-EVENT-CONNECTED - Connection to 11:22:33:44:55:66 completed [id=0]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "A"

    # User taps B
    wm._set_connecting("B")

    # Disconnect from A (preserved because CONNECTING)
    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=11:22:33:44:55:66 reason=3")
    assert wm._wifi_state.ssid == "B"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

    # Connect to B
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=B\n"
    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=1]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "B"
