"""Tests for WifiManagerClient snapshot and event handling."""
import threading
from unittest.mock import MagicMock

from openpilot.system.ui.lib.wifi_manager import ConnectStatus, MeteredType, Network, SecurityType, WifiState
from openpilot.system.ui.lib.wifi_manager_service import WifiManagerClient, _EventBroker


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
  client._current_network_metered = MeteredType.UNKNOWN
  client._tethering_active = False
  client._tethering_pending = False
  client._tethering_password = ""
  client._last_seq = 0
  return client


def _snapshot(**overrides):
  base = {
    "networks": [],
    "saved_ssids": [],
    "wifi_state": {"ssid": None, "status": int(ConnectStatus.DISCONNECTED)},
    "ipv4_address": "",
    "current_network_metered": 0,
    "tethering_active": False,
    "tethering_password": "",
  }
  base.update(overrides)
  return base


# ---------------------------------------------------------------------------
# _apply_snapshot
# ---------------------------------------------------------------------------

class TestApplySnapshot:
  def test_connecting_to_disconnected_fires_callback(self):
    client = _make_client()
    client._wifi_state = WifiState(ssid="systeam", status=ConnectStatus.CONNECTING)
    disconnected = MagicMock()
    client._disconnected.append(disconnected)

    client._apply_snapshot(_snapshot())
    client.process_callbacks()

    disconnected.assert_called_once()

  def test_connected_to_disconnected_fires_callback(self):
    client = _make_client()
    client._wifi_state = WifiState(ssid="MyNet", status=ConnectStatus.CONNECTED)
    disconnected = MagicMock()
    client._disconnected.append(disconnected)

    client._apply_snapshot(_snapshot())
    client.process_callbacks()

    disconnected.assert_called_once()

  def test_disconnected_to_connected_fires_activated(self):
    client = _make_client()
    activated = MagicMock()
    client._activated.append(activated)

    client._apply_snapshot(_snapshot(wifi_state={"ssid": "MyNet", "status": int(ConnectStatus.CONNECTED)}))
    client.process_callbacks()

    activated.assert_called_once()

  def test_connected_to_connected_does_not_fire_activated(self):
    client = _make_client()
    client._wifi_state = WifiState(ssid="MyNet", status=ConnectStatus.CONNECTED)
    activated = MagicMock()
    client._activated.append(activated)

    client._apply_snapshot(_snapshot(wifi_state={"ssid": "OtherNet", "status": int(ConnectStatus.CONNECTED)}))
    client.process_callbacks()

    activated.assert_not_called()

  def test_disconnected_to_disconnected_does_not_fire(self):
    client = _make_client()
    client._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
    disconnected = MagicMock()
    client._disconnected.append(disconnected)

    client._apply_snapshot(_snapshot())
    client.process_callbacks()

    disconnected.assert_not_called()

  def test_identical_snapshot_fires_no_callbacks(self):
    client = _make_client()
    disconnected = MagicMock()
    networks_updated = MagicMock()
    client._disconnected.append(disconnected)
    client._networks_updated.append(networks_updated)

    client._apply_snapshot(_snapshot())
    client.process_callbacks()

    disconnected.assert_not_called()
    networks_updated.assert_not_called()

  def test_network_list_change_fires_networks_updated(self):
    client = _make_client()
    networks_updated = MagicMock()
    client._networks_updated.append(networks_updated)

    client._apply_snapshot(_snapshot(networks=[
      {"ssid": "NewNet", "strength": 80, "security_type": int(SecurityType.WPA), "is_tethering": False},
    ]))
    client.process_callbacks()

    networks_updated.assert_called_once()

  def test_saved_ssids_change_fires_networks_updated(self):
    client = _make_client()
    networks_updated = MagicMock()
    client._networks_updated.append(networks_updated)

    client._apply_snapshot(_snapshot(saved_ssids=["MyNet"]))
    client.process_callbacks()

    networks_updated.assert_called_once()

  def test_tethering_state_applied(self):
    client = _make_client()
    client._apply_snapshot(_snapshot(tethering_active=True, tethering_password="secret123"))
    assert client._tethering_active is True
    assert client._tethering_password == "secret123"

  def test_ipv4_address_applied(self):
    client = _make_client()
    client._apply_snapshot(_snapshot(ipv4_address="10.0.0.5"))
    assert client._ipv4_address == "10.0.0.5"


# ---------------------------------------------------------------------------
# _apply_events
# ---------------------------------------------------------------------------

class TestApplyEvents:
  def test_need_auth_event(self):
    client = _make_client()
    need_auth = MagicMock()
    client._need_auth.append(need_auth)

    client._apply_events([{"seq": 1, "type": "need_auth", "payload": {"ssid": "LockedNet"}}])
    client.process_callbacks()

    need_auth.assert_called_once_with("LockedNet")

  def test_activated_event(self):
    client = _make_client()
    activated = MagicMock()
    client._activated.append(activated)

    client._apply_events([{"seq": 1, "type": "activated", "payload": {}}])
    client.process_callbacks()

    activated.assert_called_once()

  def test_forgotten_event(self):
    client = _make_client()
    forgotten = MagicMock()
    client._forgotten.append(forgotten)

    client._apply_events([{"seq": 1, "type": "forgotten", "payload": {"ssid": "OldNet"}}])
    client.process_callbacks()

    forgotten.assert_called_once_with("OldNet")

  def test_disconnected_event(self):
    client = _make_client()
    disconnected = MagicMock()
    client._disconnected.append(disconnected)

    client._apply_events([{"seq": 1, "type": "disconnected", "payload": {}}])
    client.process_callbacks()

    disconnected.assert_called_once()

  def test_networks_updated_event(self):
    client = _make_client()
    networks_updated = MagicMock()
    client._networks_updated.append(networks_updated)

    client._apply_events([{"seq": 1, "type": "networks_updated", "payload": {}}])
    client.process_callbacks()

    networks_updated.assert_called_once()

  def test_updates_last_seq(self):
    client = _make_client()
    client._apply_events([
      {"seq": 5, "type": "activated", "payload": {}},
      {"seq": 3, "type": "disconnected", "payload": {}},
    ])
    assert client._last_seq == 5

  def test_need_auth_without_ssid_ignored(self):
    client = _make_client()
    need_auth = MagicMock()
    client._need_auth.append(need_auth)

    client._apply_events([{"seq": 1, "type": "need_auth", "payload": {}}])
    client.process_callbacks()

    need_auth.assert_not_called()

  def test_unknown_event_type_ignored(self):
    client = _make_client()
    client._apply_events([{"seq": 1, "type": "unknown_type", "payload": {}}])
    client.process_callbacks()
    # No exception, no callbacks


# ---------------------------------------------------------------------------
# _EventBroker
# ---------------------------------------------------------------------------

class TestEventBroker:
  def test_push_and_since(self):
    broker = _EventBroker()
    broker.push("activated")
    broker.push("disconnected")

    events = broker.since(0)
    assert len(events) == 2
    assert events[0]["type"] == "activated"
    assert events[1]["type"] == "disconnected"

  def test_since_filters_by_seq(self):
    broker = _EventBroker()
    broker.push("activated")
    broker.push("disconnected")
    broker.push("need_auth", ssid="TestNet")

    events = broker.since(2)
    assert len(events) == 1
    assert events[0]["type"] == "need_auth"
    assert events[0]["payload"]["ssid"] == "TestNet"

  def test_since_empty(self):
    broker = _EventBroker()
    assert broker.since(0) == []

  def test_returns_copies(self):
    broker = _EventBroker()
    broker.push("activated")
    events1 = broker.since(0)
    events2 = broker.since(0)
    assert events1[0] is not events2[0]
