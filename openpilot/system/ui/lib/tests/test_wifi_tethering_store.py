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


class TestTetheringStore(TestCase):
  def test_runtime_shadow_makes_persistent_profile_read_only(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      persistent_path = Path(persistent) / "Hotspot.nmconnection"
      runtime_path = Path(runtime) / "Hotspot.nmconnection"
      persistent_path.write_text(master_profile())
      runtime_path.write_text(master_profile())

      with patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = TetheringStore(persistent, runtime)

      profile = store.get("weedle")
      assert profile is not None
      assert profile.persistent
      assert not store.can_mutate(profile)
      assert store.set_password("weedle", "new-password") is None
      assert persistent_path.read_text() == master_profile()

  def test_runtime_only_profile_is_reused_without_duplicate(self):
    with tempfile.TemporaryDirectory() as persistent, tempfile.TemporaryDirectory() as runtime:
      runtime_path = Path(runtime) / "Hotspot.nmconnection"
      runtime_path.write_text(master_profile())

      with patch("openpilot.system.ui.lib.wifi_tethering_store.sudo_read", side_effect=lambda path: Path(path).read_text()):
        store = TetheringStore(persistent, runtime)
        profile = store.ensure("weedle", "different-password")

      assert profile is not None
      assert not profile.persistent
      assert profile.password == "swagswagcomma"
      assert list(Path(persistent).glob("*.nmconnection")) == []

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
