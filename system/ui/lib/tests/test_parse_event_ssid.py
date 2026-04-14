"""Tests for parse_event_ssid (wpa_supplicant CTRL-EVENT ssid= extraction)."""
from openpilot.system.ui.lib.wifi_manager import parse_event_ssid


class TestParseEventSsid:
  def test_plain(self):
    event = 'CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="MyNet" auth_failures=1 duration=10 reason=WRONG_KEY'
    assert parse_event_ssid(event) == "MyNet"

  def test_missing_ssid_returns_none(self):
    assert parse_event_ssid("CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3") is None

  def test_escaped_quote(self):
    # wpa_supplicant escapes embedded quotes as \"
    event = 'CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="My \\"Home\\" Net" reason=WRONG_KEY'
    assert parse_event_ssid(event) == 'My "Home" Net'

  def test_hex_escape(self):
    # Non-ASCII SSIDs (e.g. UTF-8 "é" = 0xc3 0xa9) come through printf_encoded.
    # Must round-trip to the same 5 UTF-8 bytes the AP broadcasts, or
    # SET_NETWORK on auth-retry will fail to match.
    event = 'CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="caf\\xc3\\xa9" reason=WRONG_KEY'
    ssid = parse_event_ssid(event)
    assert ssid == "café"
    assert ssid.encode("utf-8") == b"caf\xc3\xa9"

  def test_backslash_in_ssid(self):
    # A real backslash in the SSID is emitted as `\\`.
    event = 'CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="a\\\\b" reason=WRONG_KEY'
    assert parse_event_ssid(event) == "a\\b"
