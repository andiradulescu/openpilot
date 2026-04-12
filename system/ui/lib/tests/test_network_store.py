"""Tests for NetworkStore (saved WiFi network persistence)."""
import os
import tempfile

from pytest_mock import MockerFixture

from openpilot.system.ui.lib.wifi_manager import NetworkStore


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

    mocker.patch("openpilot.system.ui.lib.wifi_manager.sudo_read", return_value=content)
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

    mocker.patch("openpilot.system.ui.lib.wifi_manager.sudo_read", return_value=content)
    store = NetworkStore(directory=self.tmpdir)

    assert store.get("Hotspot") is None
