"""Tests for WifiManager wpa_supplicant event-based state machine.

Tests the state machine in isolation by constructing a WifiManager with mocked
wpa_supplicant, then calling _handle_event directly with wpa_supplicant events.
"""

from openpilot.system.ui.lib import wifi_manager as wifi_manager_module
from openpilot.system.ui.lib.wifi_manager import (
  ConnectStatus,
  Network,
  PendingConnection,
  SecurityType,
  WifiManager,
  WifiState,
)


def fire(wm: WifiManager, event: str) -> None:
  """Feed a wpa_supplicant event into the handler."""
  wm._handle_event(event)


# ---------------------------------------------------------------------------
# Basic transitions
# ---------------------------------------------------------------------------

class TestConnected:
  def test_connected_sets_state(self, wm):
    wm._set_connecting("MyNet")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=MyNet\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]")

    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "MyNet"
    wm._dhcp.start.assert_called_once()

  def test_connected_fires_activated_callback(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(activated=cb)
    wm._set_connecting("Net")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Net\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    wm.process_callbacks()
    cb.assert_called_once()

  def test_connected_persists_pending_connection(self, wm, mocker):
    wm._set_connecting("MyNet")
    wm._set_pending_connection("MyNet", "pass1234", False)
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=MyNet\n"
    mocker.patch.object(wifi_manager_module, "_generate_wpa_conf")

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]")

    wm._store.save_network.assert_called_once_with("MyNet", psk="pass1234", hidden=False)
    assert wm._pending_connection is None

  def test_handle_connected_is_idempotent(self, wm, mocker):
    """The scanner's reconcile loop and the monitor thread can both call
    _handle_connected for the same transition. The second call must not
    restart DHCP or fire another activated callback."""
    cb = mocker.MagicMock()
    wm.add_callbacks(activated=cb)

    wm._handle_connected("MyNet")
    # Simulate the second caller arriving after state is already CONNECTED.
    wm._handle_connected("MyNet")

    wm.process_callbacks()
    wm._dhcp.start.assert_called_once()
    cb.assert_called_once()

  def test_handle_connected_re_fires_on_ssid_change(self, wm, mocker):
    """Switching networks — second _handle_connected with a different ssid
    must still transition (not treated as a dup)."""
    cb = mocker.MagicMock()
    wm.add_callbacks(activated=cb)

    wm._handle_connected("First")
    wm._handle_connected("Second")

    wm.process_callbacks()
    assert wm._wifi_state.ssid == "Second"
    assert wm._dhcp.start.call_count == 2
    assert cb.call_count == 2


class TestDisconnected:
  def test_disconnected_clears_state(self, wm):
    wm._wifi_state = WifiState(ssid="Net", status=ConnectStatus.CONNECTED)

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid is None
    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm._dhcp.stop.assert_called_once()

  def test_disconnected_preserves_connecting(self, wm):
    """If user just initiated a connect, don't clear the connecting state."""
    wm._set_connecting("NewNet")

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid == "NewNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_disconnected_during_tethering_ignored(self, wm):
    wm._wifi_state = WifiState(ssid="tether", status=ConnectStatus.CONNECTED)
    wm._tethering_active = True

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid == "tether"
    assert wm._wifi_state.status == ConnectStatus.CONNECTED

  def test_disconnected_fires_callback(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(disconnected=cb)
    wm._wifi_state = WifiState(ssid="Net", status=ConnectStatus.CONNECTED)

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    wm.process_callbacks()
    cb.assert_called_once()


class TestWrongPassword:
  def test_wrong_key_fires_need_auth(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)
    wm._set_connecting("SecNet")

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"SecNet\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm.process_callbacks()
    cb.assert_called_once_with("SecNet")

  def test_wrong_key_no_ssid_no_callback(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Net\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert len(wm._callback_queue) == 0

  def test_wrong_key_clears_pending_without_saving(self, wm):
    wm._set_connecting("SecNet")
    wm._set_pending_connection("SecNet", "wrongpass", False)

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"SecNet\" auth_failures=1 duration=10 reason=WRONG_KEY")

    wm._store.save_network.assert_not_called()
    assert wm._pending_connection is None

  def test_wrong_key_ignores_stale_event_for_previous_ssid(self, wm, mocker):
    """A delayed TEMP-DISABLED for a previously-attempted SSID must not
    tear down the user's current connection attempt."""
    cb = mocker.MagicMock()
    wm.add_callbacks(need_auth=cb)
    wm._set_connecting("CurrentNet")

    fire(wm, "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"OldNet\" auth_failures=1 duration=10 reason=WRONG_KEY")

    assert wm._wifi_state.ssid == "CurrentNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING
    wm.process_callbacks()
    cb.assert_not_called()


class TestAutoConnect:
  def test_trying_to_associate_sets_connecting(self, wm):
    """Auto-connect: wpa_supplicant connects on its own."""
    wm._ctrl.request.return_value = "wpa_state=ASSOCIATING\nssid=AutoNet\n"

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='AutoNet' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "AutoNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_auto_connect_doesnt_overwrite_user_connecting(self, wm):
    """If user initiated connect, auto-connect event is ignored."""
    wm._set_connecting("UserNet")

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='OtherNet' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "UserNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING


class TestScanResults:
  def test_scan_results_triggers_update(self, wm, mocker):
    wm._active = True
    wm._scan_lock = mocker.MagicMock()
    wm._tethering_ssid = "weedle"
    # Mock scan results
    wm._ctrl.request.return_value = "bssid / frequency / signal level / flags / ssid\naa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tTestNet\n"
    wm._update_networks = mocker.MagicMock()

    fire(wm, "CTRL-EVENT-SCAN-RESULTS")

    wm._update_networks.assert_called_once()


# ---------------------------------------------------------------------------
# Thread races: _set_connecting vs _handle_event
# ---------------------------------------------------------------------------

class TestThreadRaces:
  def test_connected_race_user_tap_during_status(self, wm):
    """User taps B right as A finishes connecting (STATUS call in flight)."""
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

  def test_auto_connect_race_user_tap_during_status(self, wm):
    """User taps B while auto-connect STATUS lookup is in flight."""
    def user_taps_b_during_status(cmd):
      if cmd == "STATUS":
        wm._set_connecting("B")
        return "wpa_state=ASSOCIATING\nssid=A\n"
      return ""

    wm._ctrl.request.side_effect = user_taps_b_during_status

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='A' freq=2437 MHz)")

    assert wm._wifi_state.ssid == "B"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_disconnected_does_not_stomp_connecting(self, wm):
    """_set_connecting() between CONNECTING check and state write is preserved."""
    wm._wifi_state = WifiState(ssid="A", status=ConnectStatus.CONNECTED)

    original_handle = wm._handle_event.__func__

    def intercept(event):
      # Simulate: just after the CONNECTING check passes, user taps connect
      if "CTRL-EVENT-DISCONNECTED" in event:
        wm._set_connecting("B")
      original_handle(wm, event)

    wm._handle_event = intercept
    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")

    assert wm._wifi_state.ssid == "B"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

  def test_connected_with_none_ssid_is_ignored(self, wm):
    """CONNECTED event with no SSID (STATUS parse fails) should not transition."""
    wm._wifi_state = WifiState()  # DISCONNECTED, ssid=None
    wm._ctrl.request.side_effect = Exception("wpa_supplicant gone")

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    wm._dhcp.start.assert_not_called()


# ---------------------------------------------------------------------------
# Full sequences
# ---------------------------------------------------------------------------

class TestFullSequences:
  def test_normal_connect(self, wm):
    """User connects → CONNECTED event → gets IP."""
    wm._set_connecting("Home")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Home\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")

    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "Home"
    wm._dhcp.start.assert_called_once()

  def test_wrong_password_then_retry(self, wm, mocker):
    """Wrong password → need_auth callback → user retries."""
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

  def test_connect_then_disconnect(self, wm):
    """Connect, then network drops."""
    wm._set_connecting("Net")
    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=Net\n"

    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED

    fire(wm, "CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3")
    assert wm._wifi_state.status == ConnectStatus.DISCONNECTED
    assert wm._wifi_state.ssid is None

  def test_auto_connect_full_sequence(self, wm):
    """wpa_supplicant auto-connects to saved network."""
    wm._ctrl.request.return_value = "wpa_state=ASSOCIATING\nssid=AutoNet\n"

    fire(wm, "Trying to associate with aa:bb:cc:dd:ee:ff (SSID='AutoNet' freq=2437 MHz)")
    assert wm._wifi_state.ssid == "AutoNet"
    assert wm._wifi_state.status == ConnectStatus.CONNECTING

    wm._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=AutoNet\n"
    fire(wm, "CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0]")
    assert wm._wifi_state.status == ConnectStatus.CONNECTED
    assert wm._wifi_state.ssid == "AutoNet"

  def test_switch_networks(self, wm):
    """User switches from A to B."""
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


class TestConnectPersistence:
  def test_connect_to_network_does_not_save_before_auth(self, wm, mocker):
    wm._remove_wpa_network = mocker.MagicMock()
    wm._add_and_select_network = mocker.MagicMock()

    class ImmediateThread:
      def __init__(self, target=None, daemon=None):
        self._target = target

      def start(self):
        if self._target is not None:
          self._target()

    mocker.patch.object(wifi_manager_module.threading, "Thread", ImmediateThread)
    mocker.patch.object(wifi_manager_module, "_generate_wpa_conf")
    wm.connect_to_network("SecNet", "secretpass", hidden=True)

    wm._store.save_network.assert_not_called()
    assert wm._pending_connection == PendingConnection(ssid="SecNet", password="secretpass", hidden=True, epoch=1)
    wm._remove_wpa_network.assert_called_once_with("SecNet")
    wm._add_and_select_network.assert_called_once_with("SecNet", "secretpass", True)


class TestNetworksUpdatedCoalescing:
  def test_mark_networks_updated_is_idempotent(self, wm):
    wm._mark_networks_updated()
    wm._mark_networks_updated()
    wm._mark_networks_updated()
    # Only the single dirty flag is buffered — no queue growth.
    assert wm._networks_updated_pending is True
    assert wm._callback_queue == []

  def test_many_scan_ticks_while_panel_hidden_collapse_to_one_call(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(networks_updated=cb)

    for _ in range(50):
      wm._mark_networks_updated()

    assert wm._callback_queue == []
    wm.process_callbacks()

    cb.assert_called_once_with(wm.networks)
    assert wm._networks_updated_pending is False

  def test_process_callbacks_uses_latest_networks_snapshot(self, wm, mocker):
    seen = []
    wm.add_callbacks(networks_updated=lambda nets: seen.append(list(nets)))
    wm._store.saved_ssids.return_value = set()

    stale = Network(ssid="Stale", strength=50, security_type=SecurityType.OPEN, is_tethering=False)
    fresh = Network(ssid="Fresh", strength=80, security_type=SecurityType.OPEN, is_tethering=False)

    wm._networks = [stale]
    wm._mark_networks_updated()

    # Simulate newer scan landing before the drain.
    wm._networks = [fresh]

    wm.process_callbacks()

    assert len(seen) == 1
    assert [n.ssid for n in seen[0]] == ["Fresh"]

  def test_process_callbacks_without_flag_does_not_fire(self, wm, mocker):
    cb = mocker.MagicMock()
    wm.add_callbacks(networks_updated=cb)

    wm.process_callbacks()

    cb.assert_not_called()


class TestStop:
  def test_stop_calls_stop_tethering_when_active(self, wm, mocker):
    wm._tethering_active = True
    wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._gsm = mocker.MagicMock()
    wm._stop_tethering = mocker.MagicMock()
    wm._exit = False

    wm.stop()

    wm._stop_tethering.assert_called_once()

  def test_stop_skips_tethering_when_not_active(self, wm, mocker):
    wm._tethering_active = False
    wm._scan_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._state_thread = mocker.MagicMock(is_alive=mocker.MagicMock(return_value=False))
    wm._gsm = mocker.MagicMock()
    wm._stop_tethering = mocker.MagicMock()
    wm._exit = False

    wm.stop()

    wm._stop_tethering.assert_not_called()
