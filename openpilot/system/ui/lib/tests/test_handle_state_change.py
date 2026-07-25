import threading
import time
from unittest.mock import MagicMock, call, patch

from openpilot.system.ui.lib import wifi_manager as wifi_manager_module
from openpilot.system.ui.lib.wifi_manager import (
  CONNECTING_STALE_TIMEOUT_SECONDS,
  ConnectStatus,
  MeteredType,
  WifiManager,
  WifiState,
)


def build_wifi_manager() -> WifiManager:
  manager = WifiManager.__new__(WifiManager)
  manager._exit = True
  manager._ctrl = MagicMock()
  manager._dhcp = MagicMock()
  manager._store = MagicMock()
  manager._store.get_metered.return_value = 0
  manager._tethering_active = False
  manager._wifi_state = WifiState()
  manager._user_epoch = 0
  manager._callback_queue = []
  manager._callback_lock = threading.Lock()
  manager._connect_lock = threading.Lock()
  manager._networks_updated_pending = False
  manager._need_auth = []
  manager._activated = []
  manager._disconnected = []
  manager._networks_updated = []
  manager._forgotten = []
  manager._networks = []
  manager._ipv4_address = ""
  manager._current_network_metered = MeteredType.UNKNOWN
  manager._pending_connection = None
  manager._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  manager._last_connected_recheck = 0.0
  manager._last_wrong_key_dispatch = {}
  manager._monitor_epoch = 0
  manager._update_active_connection_info = MagicMock()
  manager._poll_for_ip = MagicMock()
  manager._scan_thread = MagicMock()
  manager._state_thread = MagicMock()
  manager._scan_thread.is_alive.return_value = False
  manager._state_thread.is_alive.return_value = False
  manager._ctrl.request.return_value = "wpa_state=COMPLETED\nssid=TestNet\n"
  return manager


class TestConnectionState:
  def setup_method(self):
    self.manager = build_wifi_manager()

  def test_connected_persists_after_auth_and_is_idempotent(self):
    activated = MagicMock()
    self.manager.add_callbacks(activated=activated)
    self.manager._set_connecting("TestNet")
    self.manager._set_pending_connection("TestNet", "password123", False)

    with patch.object(wifi_manager_module, "_generate_wpa_conf"):
      self.manager._handle_connected("TestNet")
      self.manager._handle_connected("TestNet")

    self.manager.process_callbacks()
    assert self.manager.wifi_state == WifiState("TestNet", ConnectStatus.CONNECTED)
    self.manager._store.save_network.assert_called_once_with("TestNet", psk="password123", hidden=False)
    self.manager._dhcp.start.assert_called_once()
    activated.assert_called_once()
    assert call("ENABLE_NETWORK all") in self.manager._ctrl.request.call_args_list

  def test_persist_failure_is_retried_without_restarting_dhcp(self):
    self.manager._set_connecting("TestNet")
    self.manager._set_pending_connection("TestNet", "password123", False)
    self.manager._store.save_network.side_effect = [OSError("read-only"), None]

    with patch.object(wifi_manager_module, "_generate_wpa_conf"):
      self.manager._handle_connected("TestNet")
      self.manager._handle_connected("TestNet")

    assert self.manager._store.save_network.call_count == 2
    assert self.manager._pending_connection is None
    self.manager._dhcp.start.assert_called_once()

  def test_disconnected_event_cleans_station_state(self):
    self.manager._wifi_state = WifiState("TestNet", ConnectStatus.CONNECTED)
    self.manager._ipv4_address = "192.168.1.20"
    self.manager._current_network_metered = MeteredType.YES

    self.manager._handle_event("CTRL-EVENT-DISCONNECTED reason=3")

    assert self.manager.wifi_state == WifiState()
    assert self.manager.ipv4_address == ""
    assert self.manager.current_network_metered == MeteredType.UNKNOWN
    self.manager._dhcp.stop.assert_called_once()

  def test_disconnected_event_does_not_override_user_connection(self):
    self.manager._set_connecting("NextNet")

    self.manager._handle_event("CTRL-EVENT-DISCONNECTED reason=3")

    assert self.manager.wifi_state == WifiState("NextNet", ConnectStatus.CONNECTING)
    self.manager._dhcp.stop.assert_not_called()

  def test_wrong_key_removes_runtime_credentials_and_stops_dhcp(self):
    need_auth = MagicMock()
    self.manager.add_callbacks(need_auth=need_auth)
    self.manager._set_connecting("TestNet")
    self.manager._set_pending_connection("TestNet", "wrongpass", False)
    self.manager._remove_wpa_network = MagicMock()

    with patch.object(wifi_manager_module.time, "monotonic", return_value=100):
      self.manager._handle_event('CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="TestNet" reason=WRONG_KEY')

    self.manager.process_callbacks()
    assert self.manager._pending_connection is None
    assert self.manager.wifi_state == WifiState()
    self.manager._remove_wpa_network.assert_called_once_with("TestNet")
    self.manager._dhcp.stop.assert_called_once()
    need_auth.assert_called_once_with("TestNet")

  def test_request_error_invalidates_control_socket(self):
    self.manager._ctrl.request.side_effect = OSError("socket closed")
    epoch = self.manager._monitor_epoch

    try:
      self.manager._request("SCAN")
    except OSError:
      pass

    assert self.manager._ctrl is None
    assert self.manager._monitor_epoch == epoch + 1


class TestStartupAdoption:
  def setup_method(self):
    self.manager = build_wifi_manager()

  def test_station_adopts_existing_dhcp_client(self):
    self.manager._ctrl.request.return_value = "wpa_state=COMPLETED\nmode=station\nssid=TestNet\n"
    self.manager._dhcp.adopt.return_value = True

    self.manager._init_wifi_state()

    assert self.manager.wifi_state == WifiState("TestNet", ConnectStatus.CONNECTED)
    self.manager._dhcp.adopt.assert_called_once()
    self.manager._dhcp.start.assert_not_called()

  def test_station_starts_dhcp_when_no_client_survived(self):
    self.manager._ctrl.request.return_value = "wpa_state=COMPLETED\nmode=station\nssid=TestNet\n"
    self.manager._dhcp.adopt.return_value = False

    self.manager._init_wifi_state()

    self.manager._dhcp.start.assert_called_once()

  def test_hotspot_adopts_only_with_dnsmasq(self):
    self.manager._ctrl.request.return_value = "wpa_state=COMPLETED\nmode=AP\nssid=Hotspot\n"

    with patch.object(wifi_manager_module, "_our_dnsmasq_running", return_value=True):
      self.manager._init_wifi_state()

    assert self.manager.is_tethering_active()
    assert self.manager.wifi_state == WifiState("Hotspot", ConnectStatus.CONNECTED)
    assert self.manager.ipv4_address == "192.168.43.1"
    self.manager._dhcp.start.assert_not_called()

  def test_incomplete_hotspot_is_removed(self):
    self.manager._ctrl.request.return_value = "wpa_state=COMPLETED\nmode=AP\nssid=Hotspot\n"

    with (
      patch.object(wifi_manager_module, "_our_dnsmasq_running", return_value=False),
      patch.object(wifi_manager_module, "_pkill_wpa_supplicant") as kill_supplicant,
    ):
      self.manager._init_wifi_state()

    assert self.manager.wifi_state == WifiState()
    assert not self.manager.is_tethering_active()
    kill_supplicant.assert_called_once_with(wifi_manager_module.WPA_AP_CONF)

  def test_reconcile_adopts_missed_connection(self):
    self.manager._ctrl.request.return_value = "wpa_state=COMPLETED\nmode=station\nssid=TestNet\n"

    self.manager._reconcile_connecting_state()

    assert self.manager.wifi_state == WifiState("TestNet", ConnectStatus.CONNECTED)
    self.manager._dhcp.start.assert_called_once()


class TestLifecycle:
  def test_stop_leaves_network_data_plane_running(self):
    manager = build_wifi_manager()
    manager._exit = False
    manager._tethering_active = True
    manager._stop_tethering = MagicMock()

    manager.stop()

    assert manager._exit
    manager._ctrl.close.assert_called_once()
    manager._dhcp.stop.assert_not_called()
    manager._stop_tethering.assert_not_called()

  def test_callbacks_coalesce_network_updates(self):
    manager = build_wifi_manager()
    updated = MagicMock()
    manager.add_callbacks(networks_updated=updated)

    for _ in range(100):
      manager._mark_networks_updated()
    manager.process_callbacks()

    updated.assert_called_once_with(manager.networks)
