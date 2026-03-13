"""Tests for wpa_ctrl.py parsing helpers and NetworkStore."""
import configparser
import os
import stat

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
  HEADER = "bssid / frequency / signal level / flags / ssid\n"

  def test_basic(self):
    raw = self.HEADER + "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tMyNetwork\n" + \
                        "11:22:33:44:55:66\t5180\t-70\t[WPA-PSK-TKIP][ESS]\tOtherNet\n"
    results = parse_scan_results(raw)
    assert len(results) == 2
    assert results[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert results[0].freq == 2437
    assert results[0].signal == -50
    assert results[0].flags == "[WPA2-PSK-CCMP][ESS]"
    assert results[0].ssid == "MyNetwork"

  def test_empty(self):
    assert parse_scan_results("") == []
    assert parse_scan_results(self.HEADER) == []

  def test_malformed_line_skipped(self):
    raw = self.HEADER + "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tGood\n" + \
                        "bad line\n" + \
                        "11:22:33:44:55:66\t5180\t-70\t[ESS]\tAlsoGood\n"
    results = parse_scan_results(raw)
    assert len(results) == 2

  def test_hidden_network_empty_ssid(self):
    raw = self.HEADER + "aa:bb:cc:dd:ee:ff\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\t\n"
    results = parse_scan_results(raw)
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
# NetworkStore (.nmconnection directory-based)
# ---------------------------------------------------------------------------

class TestNetworkStore:
  def test_save_creates_nmconnection_file(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("MyNet", psk="pass123", metered=0, hidden=False)

    fpath = tmp_path / "MyNet.nmconnection"
    assert fpath.exists()

    cp = configparser.ConfigParser(interpolation=None)
    cp.read(str(fpath))
    assert cp.get("wifi", "ssid") == "MyNet"
    assert cp.get("wifi", "mode") == "infrastructure"
    assert cp.get("wifi-security", "psk") == "pass123"
    assert cp.get("wifi-security", "key-mgmt") == "wpa-psk"
    assert cp.getint("connection", "metered") == 0
    assert cp.get("connection", "id") == "MyNet"

  def test_save_load_roundtrip(self, tmp_path):
    d = str(tmp_path)
    store = NetworkStore(d)
    store.save_network("MyNet", psk="pass123", metered=1, hidden=True)

    # Reload from disk
    store2 = NetworkStore(d)
    entry = store2.get("MyNet")
    assert entry is not None
    assert entry["psk"] == "pass123"
    assert entry["metered"] == 1
    assert entry["hidden"] is True

  def test_remove(self, tmp_path):
    d = str(tmp_path)
    store = NetworkStore(d)
    store.save_network("A", psk="p1")
    store.save_network("B", psk="p2")

    assert store.remove("A")
    assert not store.contains("A")
    assert store.contains("B")
    assert not store.remove("nonexistent")

    # File should be deleted
    assert not (tmp_path / "A.nmconnection").exists()
    assert (tmp_path / "B.nmconnection").exists()

  def test_metered(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("Net", psk="p")
    assert store.get_metered("Net") == MeteredType.UNKNOWN

    store.set_metered("Net", MeteredType.YES)
    assert store.get_metered("Net") == MeteredType.YES

  def test_get_psk(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("Net", psk="secret")
    assert store.get_psk("Net") == "secret"
    assert store.get_psk("nonexistent") == ""

  def test_empty_directory(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    assert store.get_all() == {}

  def test_file_permissions(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("Net", psk="secret")
    fpath = tmp_path / "Net.nmconnection"
    mode = stat.S_IMODE(os.stat(str(fpath)).st_mode)
    assert mode == 0o600

  def test_special_characters_in_ssid(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("My/Net", psk="pass")
    # Slash replaced with underscore in filename
    assert (tmp_path / "My_Net.nmconnection").exists()
    assert store.get_psk("My/Net") == "pass"

    # Roundtrip
    store2 = NetworkStore(str(tmp_path))
    assert store2.contains("My/Net")
    assert store2.get_psk("My/Net") == "pass"

  def test_open_network_no_security_section(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("OpenNet")

    cp = configparser.ConfigParser(interpolation=None)
    cp.read(str(tmp_path / "OpenNet.nmconnection"))
    assert not cp.has_section("wifi-security")

  def test_load_preexisting_nm_file(self, tmp_path):
    """Simulate a .nmconnection file written by NetworkManager."""
    content = """\
[connection]
id=CoffeeShop
uuid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
type=wifi
metered=2

[wifi]
ssid=CoffeeShop
mode=infrastructure
hidden=false

[wifi-security]
key-mgmt=wpa-psk
psk=latte123

[ipv4]
method=auto

[ipv6]
method=auto
"""
    (tmp_path / "CoffeeShop.nmconnection").write_text(content)

    store = NetworkStore(str(tmp_path))
    assert store.contains("CoffeeShop")
    assert store.get_psk("CoffeeShop") == "latte123"
    assert store.get_metered("CoffeeShop") == MeteredType.NO
    # UUID should be preserved from the file
    entry = store.get("CoffeeShop")
    assert entry["uuid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

  def test_skips_ap_mode(self, tmp_path):
    """AP mode .nmconnection files should be ignored."""
    content = """\
[connection]
id=Hotspot
uuid=11111111-2222-3333-4444-555555555555
type=wifi

[wifi]
ssid=Hotspot
mode=ap
"""
    (tmp_path / "Hotspot.nmconnection").write_text(content)

    store = NetworkStore(str(tmp_path))
    assert not store.contains("Hotspot")

  def test_uuid_preserved_on_update(self, tmp_path):
    store = NetworkStore(str(tmp_path))
    store.save_network("Net", psk="old")
    uuid1 = store.get("Net")["uuid"]

    store.save_network("Net", psk="new")
    uuid2 = store.get("Net")["uuid"]
    assert uuid1 == uuid2
