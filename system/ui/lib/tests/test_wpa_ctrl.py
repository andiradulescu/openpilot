"""Tests for wpa_ctrl.py parsing helpers and NetworkStore."""
import json
import tempfile
import pytest

from openpilot.system.ui.lib.wpa_ctrl import (
  SecurityType, parse_scan_results, flags_to_security_type,
  parse_status, dbm_to_percent,
)
from openpilot.system.ui.lib.wifi_manager import NetworkStore, MeteredType


# ---------------------------------------------------------------------------
# parse_scan_results
# ---------------------------------------------------------------------------

class TestParseScanResults:
  def test_basic(self):
    raw = (
      "bssid / frequency / signal level / flags / ssid\n"
      "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tMyNetwork\n"
      "11:22:33:44:55:66\t5180\t-70\t[WPA-PSK-TKIP][ESS]\tOtherNet\n"
    )
    results = parse_scan_results(raw)
    assert len(results) == 2
    assert results[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert results[0].freq == 2437
    assert results[0].signal == -50
    assert results[0].flags == "[WPA2-PSK-CCMP][ESS]"
    assert results[0].ssid == "MyNetwork"

  def test_empty(self):
    assert parse_scan_results("") == []
    assert parse_scan_results("bssid / frequency / signal level / flags / ssid\n") == []

  def test_malformed_line_skipped(self):
    raw = (
      "bssid / frequency / signal level / flags / ssid\n"
      "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tGood\n"
      "bad line\n"
      "11:22:33:44:55:66\t5180\t-70\t[ESS]\tAlsoGood\n"
    )
    results = parse_scan_results(raw)
    assert len(results) == 2

  def test_hidden_network_empty_ssid(self):
    raw = (
      "bssid / frequency / signal level / flags / ssid\n"
      "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\t\n"
    )
    results = parse_scan_results(raw)
    # The fifth field is empty string
    assert len(results) == 1
    assert results[0].ssid == ""


# ---------------------------------------------------------------------------
# flags_to_security_type
# ---------------------------------------------------------------------------

class TestFlagsToSecurityType:
  @pytest.mark.parametrize("flags, expected", [
    ("[WPA2-PSK-CCMP][ESS]", SecurityType.WPA),
    ("[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS]", SecurityType.WPA),
    ("[WPA-PSK-CCMP+TKIP][ESS]", SecurityType.WPA),
    ("[RSN-PSK-CCMP][ESS]", SecurityType.WPA),
    ("[SAE][ESS]", SecurityType.WPA),
    ("[ESS]", SecurityType.OPEN),
    ("", SecurityType.OPEN),
    ("[WPA2-EAP-CCMP][ESS]", SecurityType.UNSUPPORTED),
    ("[WPA2-EAP+FT/EAP-CCMP][802.1X][ESS]", SecurityType.UNSUPPORTED),
  ])
  def test_flags(self, flags, expected):
    assert flags_to_security_type(flags) == expected


# ---------------------------------------------------------------------------
# parse_status
# ---------------------------------------------------------------------------

class TestParseStatus:
  def test_basic(self):
    raw = "bssid=aa:bb:cc:dd:ee:ff\nfreq=2437\nssid=MyNet\nwpa_state=COMPLETED\nkey_mgmt=WPA2-PSK\n"
    result = parse_status(raw)
    assert result["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert result["ssid"] == "MyNet"
    assert result["wpa_state"] == "COMPLETED"

  def test_empty(self):
    assert parse_status("") == {}

  def test_value_with_equals(self):
    raw = "key=val=ue\n"
    result = parse_status(raw)
    assert result["key"] == "val=ue"


# ---------------------------------------------------------------------------
# dbm_to_percent
# ---------------------------------------------------------------------------

class TestDbmToPercent:
  @pytest.mark.parametrize("dbm, expected", [
    (-100, 0),
    (-50, 100),
    (-30, 100),  # clamped
    (-110, 0),   # clamped
    (-75, 50),
    (-90, 20),
  ])
  def test_conversion(self, dbm, expected):
    assert dbm_to_percent(dbm) == expected


# ---------------------------------------------------------------------------
# NetworkStore
# ---------------------------------------------------------------------------

class TestNetworkStore:
  def test_save_load(self, tmp_path):
    path = str(tmp_path / "networks.json")
    store = NetworkStore(path)
    store.save_network("MyNet", psk="pass123", metered=0, hidden=False)

    # Reload from disk
    store2 = NetworkStore(path)
    entry = store2.get("MyNet")
    assert entry is not None
    assert entry["psk"] == "pass123"

  def test_remove(self, tmp_path):
    path = str(tmp_path / "networks.json")
    store = NetworkStore(path)
    store.save_network("A", psk="p1")
    store.save_network("B", psk="p2")

    assert store.remove("A")
    assert not store.contains("A")
    assert store.contains("B")
    assert not store.remove("nonexistent")

  def test_metered(self, tmp_path):
    path = str(tmp_path / "networks.json")
    store = NetworkStore(path)
    store.save_network("Net", psk="p")
    assert store.get_metered("Net") == MeteredType.UNKNOWN

    store.set_metered("Net", MeteredType.YES)
    assert store.get_metered("Net") == MeteredType.YES

  def test_get_psk(self, tmp_path):
    path = str(tmp_path / "networks.json")
    store = NetworkStore(path)
    store.save_network("Net", psk="secret")
    assert store.get_psk("Net") == "secret"
    assert store.get_psk("nonexistent") == ""

  def test_missing_file(self, tmp_path):
    path = str(tmp_path / "nonexistent.json")
    store = NetworkStore(path)
    assert store.get_all() == {}
