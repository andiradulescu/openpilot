"""Tests for NetworkStore (saved WiFi network persistence)."""
import os
import tempfile

from pytest_mock import MockerFixture

from openpilot.system.ui.lib.wifi_manager import _generate_wpa_conf, _format_psk_value, _is_raw_psk
from openpilot.system.ui.lib.wifi_network_store import NetworkStore


class TestNetworkStore:
  def setup_method(self):
    self.tmpdir = tempfile.mkdtemp()

  def _make_store(self, mocker: MockerFixture):
    mocker.patch("subprocess.run")
    return NetworkStore(directory=self.tmpdir)

  def test_empty_store(self, mocker: MockerFixture):
    store = self._make_store(mocker)
    assert store.get_all() == {}

  def test_remove_nonexistent_returns_false(self, mocker: MockerFixture):
    store = self._make_store(mocker)
    assert store.remove("DoesNotExist") is False

  def test_remove_existing_returns_true(self, mocker: MockerFixture):
    store = self._make_store(mocker)
    store._networks["TestNet"] = {"psk": "pass123", "metered": 0, "hidden": False, "uuid": "abc"}
    mock_run = mocker.patch("subprocess.run")
    result = store.remove("TestNet")
    assert result is True
    assert "TestNet" not in store._networks
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[:3] == ["sudo", "rm", "-f"]

  def test_remove_uses_check_false(self, mocker: MockerFixture):
    """Verify remove uses check=False, not check=True (rm -f handles missing files)."""
    store = self._make_store(mocker)
    store._networks["TestNet"] = {"psk": "x", "metered": 0, "hidden": False, "uuid": "abc"}
    mock_run = mocker.patch("subprocess.run")
    store.remove("TestNet")
    kwargs = mock_run.call_args[1]
    assert kwargs.get("check") is False, "remove() should use check=False since rm -f handles missing files"

  def test_get_returns_copy(self, mocker: MockerFixture):
    store = self._make_store(mocker)
    store._networks["TestNet"] = {"psk": "pass123", "metered": 0, "hidden": False, "uuid": "abc"}
    entry = store.get("TestNet")
    assert entry is not None
    entry["psk"] = "CHANGED"
    assert store.get("TestNet")["psk"] == "pass123"

  def test_get_nonexistent_returns_none(self, mocker: MockerFixture):
    store = self._make_store(mocker)
    assert store.get("DoesNotExist") is None

  def test_load_reads_nmconnection_files(self, mocker: MockerFixture):
    """Write a real .nmconnection file and verify it loads."""
    content = """\
[connection]
id=MyWifi
uuid=test-uuid-123
type=wifi
metered=0

[wifi]
ssid=MyWifi
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk=secret123

[ipv4]
method=auto
"""
    fpath = os.path.join(self.tmpdir, "MyWifi.nmconnection")
    with open(fpath, "w") as f:
      f.write(content)

    mocker.patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", return_value=content)
    store = NetworkStore(directory=self.tmpdir)

    entry = store.get("MyWifi")
    assert entry is not None
    assert entry["psk"] == "secret123"
    assert entry["uuid"] == "test-uuid-123"
    assert entry["metered"] == 0

  def test_load_skips_ap_mode(self, mocker: MockerFixture):
    content = """\
[connection]
id=Hotspot
uuid=ap-uuid
type=wifi

[wifi]
ssid=Hotspot
mode=ap
"""
    fpath = os.path.join(self.tmpdir, "Hotspot.nmconnection")
    with open(fpath, "w") as f:
      f.write(content)

    mocker.patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", return_value=content)
    store = NetworkStore(directory=self.tmpdir)

    assert store.get("Hotspot") is None


class TestPskFormatting:
  """wpa_supplicant requires 64-hex PSKs unquoted and 8-63 char passphrases
  quoted (hostap config.c:620-694). A quoted 64-char value always FAILs."""

  def test_is_raw_psk_64_hex(self):
    assert _is_raw_psk("0123456789abcdef" * 4) is True

  def test_is_raw_psk_uppercase(self):
    assert _is_raw_psk("0123456789ABCDEF" * 4) is True

  def test_is_raw_psk_63_chars_false(self):
    assert _is_raw_psk("0" * 63) is False

  def test_is_raw_psk_65_chars_false(self):
    assert _is_raw_psk("0" * 65) is False

  def test_is_raw_psk_non_hex_false(self):
    # 64 chars but contains a non-hex char.
    assert _is_raw_psk("z" + "0" * 63) is False

  def test_format_passphrase_quoted(self):
    assert _format_psk_value("hello123") == '"hello123"'

  def test_format_raw_psk_unquoted(self):
    raw = "deadbeef" * 8
    assert _format_psk_value(raw) == raw

  def test_format_quotes_escaped_in_passphrase(self):
    assert _format_psk_value('pa"ss') == '"pa\\"ss"'


class _FakeStore:
  def __init__(self, networks):
    self._networks = networks

  def get_all(self):
    return self._networks


class TestGenerateWpaConf:
  def setup_method(self):
    self.tmpdir = tempfile.mkdtemp()
    self.path = os.path.join(self.tmpdir, "wpa.conf")

  def test_raw_hex_psk_written_unquoted(self):
    raw = "deadbeef" * 8
    store = _FakeStore({"RawNet": {"psk": raw}})
    _generate_wpa_conf(store, path=self.path)
    with open(self.path) as f:
      content = f.read()
    assert f"  psk={raw}" in content
    assert f'  psk="{raw}"' not in content
    assert "key_mgmt=WPA-PSK" in content

  def test_passphrase_written_quoted(self):
    store = _FakeStore({"SecNet": {"psk": "myp@ssw0rd"}})
    _generate_wpa_conf(store, path=self.path)
    with open(self.path) as f:
      content = f.read()
    assert '  psk="myp@ssw0rd"' in content

  def test_open_network_no_psk(self):
    store = _FakeStore({"OpenNet": {"psk": ""}})
    _generate_wpa_conf(store, path=self.path)
    with open(self.path) as f:
      content = f.read()
    assert "key_mgmt=NONE" in content
    assert "psk=" not in content
