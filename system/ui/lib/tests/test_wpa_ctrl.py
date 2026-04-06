"""Tests for wpa_ctrl parsing helpers and constants."""
import pytest

from openpilot.system.ui.lib.wpa_ctrl import (
  RECV_BUF_SIZE,
  SecurityType,
  parse_scan_results,
  parse_status,
  flags_to_security_type,
  dbm_to_percent,
)


class TestParseStatus:
  def test_basic(self):
    raw = "wpa_state=COMPLETED\nssid=MyNet\nip_address=10.0.0.5\n"
    d = parse_status(raw)
    assert d["wpa_state"] == "COMPLETED"
    assert d["ssid"] == "MyNet"
    assert d["ip_address"] == "10.0.0.5"

  def test_value_with_equals(self):
    raw = "ssid=My=Network\n"
    d = parse_status(raw)
    assert d["ssid"] == "My=Network"

  def test_empty(self):
    assert parse_status("") == {}


class TestFlagsToSecurityType:
  @pytest.mark.parametrize("flags,expected", [
    ("[WPA2-PSK-CCMP][ESS]", SecurityType.WPA),
    ("[RSN-PSK-CCMP]", SecurityType.WPA),
    ("[WPA-PSK-TKIP]", SecurityType.WPA),
    ("[SAE]", SecurityType.WPA),
    ("[ESS]", SecurityType.OPEN),
    ("", SecurityType.OPEN),
    ("[WPA2-EAP-CCMP]", SecurityType.UNSUPPORTED),
    ("[802.1X]", SecurityType.UNSUPPORTED),
  ])
  def test_security_types(self, flags, expected):
    assert flags_to_security_type(flags) == expected


class TestDbmToPercent:
  def test_boundaries(self):
    assert dbm_to_percent(-100) == 0
    assert dbm_to_percent(-50) == 100

  def test_clamps(self):
    assert dbm_to_percent(-120) == 0
    assert dbm_to_percent(-30) == 100

  def test_mid(self):
    assert dbm_to_percent(-75) == 50


class TestParseScanResults:
  HEADER = "bssid / frequency / signal level / flags / ssid\n"

  def test_basic(self):
    raw = self.HEADER + "00:11:22:33:44:55\t2437\t-65\t[WPA2-PSK-CCMP][ESS]\tMyNetwork\n"
    results = parse_scan_results(raw)
    assert len(results) == 1
    r = results[0]
    assert r.bssid == "00:11:22:33:44:55"
    assert r.freq == 2437
    assert r.signal == -65
    assert r.ssid == "MyNetwork"

  def test_hidden_ssid(self):
    raw = self.HEADER + "00:11:22:33:44:55\t2437\t-65\t[ESS]\t\n"
    results = parse_scan_results(raw)
    assert len(results) == 1
    assert results[0].ssid == ""

  def test_missing_ssid_field(self):
    raw = self.HEADER + "00:11:22:33:44:55\t2437\t-65\t[ESS]\n"
    results = parse_scan_results(raw)
    assert len(results) == 1
    assert results[0].ssid == ""

  def test_malformed_lines_skipped(self):
    raw = self.HEADER + "garbage\n" + "00:11:22:33:44:55\t2437\t-65\t[ESS]\tGood\n"
    results = parse_scan_results(raw)
    assert len(results) == 1
    assert results[0].ssid == "Good"

  def test_large_scan_fits_in_recv_buffer(self):
    """A dense AP environment can return many results. Verify they parse
    correctly and that RECV_BUF_SIZE is large enough for a realistic worst case."""
    lines = [self.HEADER.strip()]
    for i in range(200):
      bssid = f"00:11:22:33:{i // 256:02x}:{i % 256:02x}"
      ssid = f"Network_{i:03d}_with_a_longer_name_padding"
      lines.append(f"{bssid}\t2437\t{-30 - (i % 70)}\t[WPA2-PSK-CCMP][ESS]\t{ssid}")
    raw = "\n".join(lines) + "\n"

    # Ensure the payload fits in our buffer
    assert len(raw.encode()) < RECV_BUF_SIZE, (
      f"200-AP scan result ({len(raw.encode())} bytes) exceeds RECV_BUF_SIZE ({RECV_BUF_SIZE})"
    )

    results = parse_scan_results(raw)
    assert len(results) == 200
    assert results[0].ssid == "Network_000_with_a_longer_name_padding"
    assert results[199].ssid == "Network_199_with_a_longer_name_padding"

  def test_old_buffer_would_truncate(self):
    """Demonstrate that 4096 bytes is insufficient for dense scan results."""
    lines = ["header"]
    for i in range(200):
      bssid = f"00:11:22:33:{i // 256:02x}:{i % 256:02x}"
      ssid = f"Network_{i:03d}_with_a_longer_name_padding"
      lines.append(f"{bssid}\t2437\t{-30 - (i % 70)}\t[WPA2-PSK-CCMP][ESS]\t{ssid}")
    raw = "\n".join(lines) + "\n"
    assert len(raw.encode()) > 4096, "Test assumes 200 APs exceed 4096 bytes"
