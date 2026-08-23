import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkStore, parse_profile, render_profile
from openpilot.system.ui.lib.wpa_ctrl import SecurityType


PROFILE_UUID = "11111111-1111-4111-8111-111111111111"


def profile_text(profile_uuid: str = PROFILE_UUID, ssid: str = "TestNet", metered: int = 0) -> str:
  return f"""[connection]
uuid={profile_uuid}
type=wifi
metered={metered}
[wifi]
ssid={ssid}
[ipv4]
method=auto
[ipv6]
method=auto
"""


class TestNetworkProfile(TestCase):
  def test_parses_profile_written_by_master(self):
    raw = f"""\
[connection]
id=openpilot connection TestNet
uuid={PROFILE_UUID}
type=802-11-wireless
autoconnect-retries=0
metered=1

[802-11-wireless]
ssid=TestNet
hidden=false
mode=infrastructure

[802-11-wireless-security]
key-mgmt=wpa-psk
psk=password123

[ipv4]
method=auto
dns-priority=600

[ipv6]
method=ignore
"""
    profile = parse_profile(raw)
    assert profile is not None
    assert profile.uuid == PROFILE_UUID
    assert profile.ssid == "TestNet"
    assert profile.security == SecurityType.WPA
    assert profile.psk == "password123"
    assert profile.metered == MeteredType.YES
    assert not profile.ipv6_enabled

  def test_decodes_keyfile_escapes_once(self):
    raw = f"""\
[connection]
uuid={PROFILE_UUID}
type=wifi

[wifi]
ssid=foo\\\\;bar
mode=infrastructure

[ipv4]
method=auto

[ipv6]
method=auto
"""
    profile = parse_profile(raw)
    assert profile is not None
    assert profile.ssid == "foo\\;bar"

  def test_rejects_priority_wpa_cannot_represent(self):
    raw = f"""\
[connection]
uuid={PROFILE_UUID}
type=wifi
autoconnect-priority=999

[wifi]
ssid=TestNet

[ipv4]
method=auto

[ipv6]
method=auto
"""
    assert parse_profile(raw) is None

  def test_rejects_control_characters_in_psk(self):
    raw = f"""\
[connection]
uuid={PROFILE_UUID}
type=wifi

[wifi]
ssid=TestNet

[wifi-security]
key-mgmt=wpa-psk
psk=password\\n123

[ipv4]
method=auto

[ipv6]
method=auto
"""
    assert parse_profile(raw) is None

  def test_round_trip_keeps_networkmanager_semantics(self):
    raw = f"""\
[connection]
uuid={PROFILE_UUID}
type=wifi
autoconnect-retries=0
autoconnect-priority=42
metered=2

[wifi]
ssid=32;71;117;101;115;116;32;
hidden=true
bssid=00:11:22:33:44:55

[wifi-security]
key-mgmt=wpa-psk
psk=password123

[ipv4]
method=auto
dns-priority=600

[ipv6]
method=ignore
"""
    profile = parse_profile(raw)
    assert profile is not None
    reparsed = parse_profile(render_profile(profile))
    assert reparsed is not None
    assert reparsed == profile


class TestNetworkStore(TestCase):
  def test_persistent_profile_wins_same_uuid_runtime_copy(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      persistent_path = Path(persistent) / "persistent.nmconnection"
      runtime_path = Path(runtime) / "runtime.nmconnection"
      persistent_path.write_text(profile_text(metered=1))
      runtime_path.write_text(profile_text(metered=2))

      with patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = NetworkStore(persistent, runtime)

      assert store.metered(PROFILE_UUID) == MeteredType.YES
      assert store.get(PROFILE_UUID).persistent
      assert not store.can_mutate(PROFILE_UUID)
      assert store.set_metered(PROFILE_UUID, MeteredType.NO) is None
      assert not store.remove_ssid("TestNet")
      assert persistent_path.exists()
      assert runtime_path.exists()

  def test_persistent_profile_without_runtime_shadow_can_be_mutated(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      persistent_path = Path(persistent) / "persistent.nmconnection"
      persistent_path.write_text(profile_text())

      with patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = NetworkStore(persistent, runtime)

      assert store.can_mutate(PROFILE_UUID)

  def test_runtime_only_profile_cannot_be_mutated(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      runtime_path = Path(runtime) / "runtime.nmconnection"
      runtime_path.write_text(profile_text())
      with patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = NetworkStore(persistent, runtime)

      assert store.set_metered(PROFILE_UUID, MeteredType.YES) is None
      assert not store.remove_ssid("TestNet")
      assert runtime_path.exists()

  def test_update_keeps_existing_noncanonical_path(self):
    with tempfile.TemporaryDirectory() as persistent:
      existing_path = Path(persistent) / "saved.nmconnection"
      existing_path.write_text(profile_text(metered=0))
      commands = []

      def run(command, **kwargs):
        commands.append(command)
        if command[:2] == ["sudo", "install"] and "-d" not in command:
          Path(command[-1]).write_bytes(Path(command[-2]).read_bytes())
        elif command[:3] == ["sudo", "mv", "-f"]:
          os.replace(command[3], command[4])
        elif command[:3] == ["sudo", "rm", "-f"]:
          Path(command[3]).unlink(missing_ok=True)
        return type("Result", (), {"returncode": 0})()

      with (
        patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", side_effect=lambda path: Path(path).read_text()),
        patch("openpilot.system.ui.lib.wifi_network_store.subprocess.run", side_effect=run),
      ):
        store = NetworkStore(persistent, None)
        updated = store.set_metered(PROFILE_UUID, MeteredType.YES)

      assert updated is not None
      assert updated.path == str(existing_path)
      assert existing_path.exists()
      assert len(list(Path(persistent).glob("*.nmconnection"))) == 1
      assert parse_profile(existing_path.read_text()).metered == MeteredType.YES
      install_idx = next(i for i, command in enumerate(commands) if command[:2] == ["sudo", "install"] and "-d" not in command)
      move_idx = next(i for i, command in enumerate(commands) if command[:3] == ["sudo", "mv", "-f"])
      assert install_idx < move_idx
      assert commands[install_idx][-1] != str(existing_path)
      assert commands[move_idx][-1] == str(existing_path)

  def test_constructor_does_not_recover(self):
    with tempfile.TemporaryDirectory() as persistent:
      staged = Path(persistent) / f"test.nmconnection.openpilot-forget-{'a' * 32}"
      staged.write_text(profile_text())

      with patch("openpilot.system.ui.lib.wifi_network_store.subprocess.run") as run:
        store = NetworkStore(persistent, None)

      run.assert_not_called()
      assert store.profiles() == []
      assert staged.exists()

  def test_uncommitted_forget_is_restored(self):
    with tempfile.TemporaryDirectory() as persistent:
      original = Path(persistent) / "test.nmconnection"
      staged = Path(f"{original}.openpilot-forget-{'a' * 32}")
      staged.write_text(profile_text())

      def run(command, **kwargs):
        if command[:3] == ["sudo", "mv", "-f"]:
          os.replace(command[3], command[4])
        return type("Result", (), {"returncode": 0})()

      with (
        patch("openpilot.system.ui.lib.wifi_network_store.subprocess.run", side_effect=run),
        patch("openpilot.system.ui.lib.wifi_network_store.sudo_read", side_effect=lambda path: Path(path).read_text()),
      ):
        store = NetworkStore(persistent, None)
        store.recover()

      assert original.exists()
      assert not staged.exists()
      assert store.get(PROFILE_UUID) is not None

  def test_committed_forget_is_not_restored_when_cleanup_fails(self):
    with tempfile.TemporaryDirectory() as persistent:
      token = "b" * 32
      original = Path(persistent) / "test.nmconnection"
      staged = Path(f"{original}.openpilot-forget-{token}")
      marker = Path(persistent) / f".openpilot-forget-committed-{token}"
      staged.write_text(profile_text())
      marker.touch()

      def run(command, **kwargs):
        returncode = 1 if command[:3] == ["sudo", "rm", "-f"] and command[3] == str(staged) else 0
        return type("Result", (), {"returncode": returncode})()

      with patch("openpilot.system.ui.lib.wifi_network_store.subprocess.run", side_effect=run):
        store = NetworkStore(persistent, None)
        store.recover()

      assert store.profiles() == []
      assert not original.exists()
      assert staged.exists()
      assert marker.exists()
