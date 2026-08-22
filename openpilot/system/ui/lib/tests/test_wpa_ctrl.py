import socket
import threading
import time
from typing import cast
from unittest import TestCase

from openpilot.system.ui.lib.wpa_ctrl import (
  SecurityType,
  WpaCtrl,
  dbm_to_percent,
  decode_ssid,
  flags_to_security_type,
  normalize_ssid,
  parse_scan_results,
  parse_status,
)


class TestWpaCtrlParsing(TestCase):
  def test_status(self):
    assert parse_status("wpa_state=COMPLETED\nssid=caf\\xc3\\xa9\nip_address=10.0.0.5\n") == {
      "wpa_state": "COMPLETED",
      "ssid": "café",
      "ip_address": "10.0.0.5",
    }

  def test_scan_results_preserve_ssid_spaces(self):
    raw = "bssid / frequency / signal level / flags / ssid\n00:11:22:33:44:55\t2437\t-65\t[ESS]\tMyNet \n"
    assert parse_scan_results(raw)[0].ssid == "MyNet "

  def test_security_types(self):
    cases = (
      ("[WPA2-PSK-CCMP][ESS]", SecurityType.WPA),
      ("[WPA2-PSK+SAE-CCMP][ESS]", SecurityType.WPA),
      ("[WPA2-PSK+EAP-CCMP][ESS]", SecurityType.WPA),
      ("[WPA2-PSK-SHA256+SAE-CCMP][ESS]", SecurityType.UNSUPPORTED),
      ("[SAE-CCMP]", SecurityType.UNSUPPORTED),
      ("[OWE-CCMP][ESS]", SecurityType.UNSUPPORTED),
      ("[WPA2-EAP-CCMP]", SecurityType.UNSUPPORTED),
      ("[ESS]", SecurityType.OPEN),
    )
    for flags, expected in cases:
      with self.subTest(flags=flags):
        assert flags_to_security_type(flags) == expected

  def test_dbm_to_percent(self):
    cases = ((-120, 0), (-100, 0), (-70, 50), (-40, 100), (-30, 100))
    for dbm, expected in cases:
      with self.subTest(dbm=dbm):
        assert dbm_to_percent(dbm) == expected


class TestDecodeSsid(TestCase):
  def test_values(self):
    cases = (
      ("MyNetwork", "MyNetwork"),
      ("\\x41\\x42", "AB"),
      ("caf\\xc3\\xa9", "café"),
      ("\\101", "A"),
      ("\\\\", "\\"),
      ('\\"', '"'),
      ("\\n", "\n"),
      ("\\x00" * 32, ""),
      ("A\\x00B", "A\x00B"),
    )
    for encoded, expected in cases:
      with self.subTest(encoded=encoded):
        assert decode_ssid(encoded) == expected

  def test_invalid_utf8_preserves_identity(self):
    decoded = decode_ssid("\\xff")
    assert decoded.encode("utf-8", errors="surrogateescape") == b"\xff"
    assert normalize_ssid(decoded) == "�"


class _RacySock:
  def __init__(self):
    self._lock = threading.Lock()
    self._last_sent = b""

  def send(self, data: bytes):
    with self._lock:
      self._last_sent = data

  def recv(self, _bufsize: int) -> bytes:
    time.sleep(0.005)
    with self._lock:
      return b"REPLY:" + self._last_sent


class TestWpaCtrl(TestCase):
  def test_requests_are_serialized(self):
    ctrl = WpaCtrl()
    ctrl._sock = cast(socket.socket, _RacySock())
    results = {}

    def worker(command: str):
      results[command] = ctrl.request(command)

    threads = [threading.Thread(target=worker, args=(command,)) for command in ("STATUS", "SCAN_RESULTS", "PING")]
    for thread in threads:
      thread.start()
    for thread in threads:
      thread.join(timeout=5)

    assert results == {command: f"REPLY:{command}" for command in ("STATUS", "SCAN_RESULTS", "PING")}
    ctrl._sock = None
