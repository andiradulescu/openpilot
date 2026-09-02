import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from openpilot.system.ui.lib.wifi_tethering_store import TetheringProfile, TetheringStore, parse_tethering_profile, render_tethering_profile


PROFILE_UUID = "11111111-1111-4111-8111-111111111111"


def master_profile(password: str = "swagswagcomma") -> str:
  return f"""[connection]
id=Hotspot
uuid={PROFILE_UUID}
type=802-11-wireless
interface-name=wlan0
autoconnect=false
autoconnect-retries=0

[802-11-wireless]
band=bg
mode=ap
ssid=weedle

[802-11-wireless-security]
group=ccmp;
key-mgmt=wpa-psk
pairwise=ccmp;
proto=rsn;
psk={password}

[ipv4]
method=shared
address1=192.168.43.1/24,192.168.43.1
never-default=true

[ipv6]
method=ignore
"""


class TestTetheringProfile(TestCase):
  def test_parses_master_tethering_profile(self):
    profile = parse_tethering_profile(master_profile())
    assert profile is not None
    assert profile.uuid == PROFILE_UUID
    assert profile.ssid == "weedle"
    assert profile.password == "swagswagcomma"

  def test_round_trip_profile(self):
    profile = TetheringProfile(PROFILE_UUID, "weedle-1234", "password123")
    parsed = parse_tethering_profile(render_tethering_profile(profile))
    assert parsed is not None
    assert parsed.uuid == profile.uuid
    assert parsed.ssid == profile.ssid
    assert parsed.password == profile.password

  def test_round_trip_preserves_password_boundary_spaces(self):
    password = "  password  "
    raw = render_tethering_profile(TetheringProfile(PROFILE_UUID, "weedle", password))

    assert "psk=\\s\\spassword\\s\\s" in raw
    profile = parse_tethering_profile(raw)
    assert profile is not None
    assert profile.password == password

  def test_rejects_control_characters_in_password(self):
    assert parse_tethering_profile(master_profile("password\\n123")) is None


def run_sudo(command, **kwargs):
  if command[:2] == ["sudo", "install"]:
    if "-d" in command:
      Path(command[-1]).mkdir(parents=True, exist_ok=True)
    else:
      Path(command[-1]).parent.mkdir(parents=True, exist_ok=True)
      Path(command[-1]).write_bytes(Path(command[-2]).read_bytes())
  elif command[:3] == ["sudo", "mv", "-f"]:
    os.replace(command[3], command[4])
  elif command[:3] == ["sudo", "rm", "-f"]:
    Path(command[3]).unlink(missing_ok=True)
  return type("Result", (), {"returncode": 0})()


class TestTetheringStore(TestCase):
  def test_runtime_shadow_does_not_block_password_update(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      persistent_path = Path(persistent) / "Hotspot.nmconnection"
      runtime_path = Path(runtime) / "Hotspot.nmconnection"
      persistent_path.write_text(master_profile())
      runtime_path.write_text(master_profile())

      with (
        patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()),
        patch("openpilot.system.ui.lib.wifi_tethering_store.subprocess.run", side_effect=run_sudo),
      ):
        store = TetheringStore(persistent, runtime)
        profile = store.get("weedle")
        assert profile is not None
        assert profile.persistent
        assert store.can_mutate(profile)
        updated = store.set_password("weedle", "new-password")

      assert updated is not None
      assert updated.password == "new-password"
      assert parse_tethering_profile(persistent_path.read_text()).password == "new-password"
      assert not runtime_path.exists()

  def test_runtime_only_profile_is_promoted_on_ensure(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      runtime_path = Path(runtime) / "Hotspot.nmconnection"
      runtime_path.write_text(master_profile())

      with (
        patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()),
        patch("openpilot.system.ui.lib.wifi_tethering_store.subprocess.run", side_effect=run_sudo),
      ):
        store = TetheringStore(persistent, runtime)
        profile = store.ensure("weedle", "different-password")
        updated = store.set_password("weedle", "newer-password")

      assert profile is not None
      assert profile.persistent
      assert profile.password == "swagswagcomma"
      persistent_files = list(Path(persistent).glob("*.nmconnection"))
      assert len(persistent_files) == 1
      assert parse_tethering_profile(persistent_files[0].read_text()).password == "newer-password"
      assert not runtime_path.exists()
      assert updated is not None
      assert updated.password == "newer-password"

  def test_runtime_only_profile_applies_explicit_password_update(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      runtime_path = Path(runtime) / "Hotspot.nmconnection"
      runtime_path.write_text(master_profile())

      with (
        patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()),
        patch("openpilot.system.ui.lib.wifi_tethering_store.subprocess.run", side_effect=run_sudo),
      ):
        store = TetheringStore(persistent, runtime)
        updated = store.set_password("weedle", "new-password")

      assert updated is not None
      assert updated.persistent
      assert updated.password == "new-password"
      persistent_files = list(Path(persistent).glob("*.nmconnection"))
      assert len(persistent_files) == 1
      assert parse_tethering_profile(persistent_files[0].read_text()).password == "new-password"
      assert not runtime_path.exists()

  def test_ensure_stops_live_ap_with_different_identity(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      with (
        patch("openpilot.system.ui.lib.wifi_tethering_store.subprocess.run", side_effect=run_sudo),
        patch("openpilot.system.ui.lib.wifi_tethering_store.wpa_supplicant.is_running", return_value=True),
        patch("openpilot.system.ui.lib.wifi_tethering_store._live_ap_password", return_value=None),
        patch("openpilot.system.ui.lib.wifi_tethering_store.wpa_supplicant.stop", return_value=True) as stop,
      ):
        store = TetheringStore(persistent, runtime)
        profile = store.ensure("weedle-1234", "password123")

      stop.assert_called_once()
      assert profile is not None
      assert profile.ssid == "weedle-1234"

  def test_ensure_retries_when_mismatched_live_ap_cannot_stop(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      with (
        patch("openpilot.system.ui.lib.wifi_tethering_store.wpa_supplicant.is_running", return_value=True),
        patch("openpilot.system.ui.lib.wifi_tethering_store._live_ap_password", return_value=None),
        patch("openpilot.system.ui.lib.wifi_tethering_store.wpa_supplicant.stop", return_value=False),
      ):
        store = TetheringStore(persistent, runtime)
        with self.assertRaises(RuntimeError):
          store.ensure("weedle-1234", "password123")

  def test_get_prefers_persistent_when_ssid_has_runtime_copy(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      other_uuid = "22222222-2222-4222-8222-222222222222"
      persistent_path = Path(persistent) / "Hotspot.nmconnection"
      runtime_path = Path(runtime) / "runtime.nmconnection"
      persistent_path.write_text(master_profile())
      runtime_path.write_text(master_profile().replace(PROFILE_UUID, other_uuid))

      with patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = TetheringStore(persistent, runtime)

      profile = store.get("weedle")
      assert profile is not None
      assert profile.persistent
      assert profile.uuid == PROFILE_UUID

  def test_ensure_creates_rollback_profile_when_missing(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
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

      with patch("openpilot.system.ui.lib.wifi_tethering_store.subprocess.run", side_effect=run):
        store = TetheringStore(persistent, runtime)
        profile = store.ensure("weedle", "password123")

      assert profile is not None
      assert profile.persistent
      path = Path(profile.path)
      assert path.exists()
      assert parse_tethering_profile(path.read_text()) is not None
      install = next(command for command in commands if command[:2] == ["sudo", "install"] and "-d" not in command)
      move = next(command for command in commands if command[:3] == ["sudo", "mv", "-f"])
      assert install[-1] != str(path)
      assert move[-1] == str(path)
