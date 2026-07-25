import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from openpilot.system.ui.lib import wifi_network_store as store_module
from openpilot.system.ui.lib.wifi_network_store import NetworkStore


def write_profile(directory: str, filename: str, ssid: str, *,
                  file_uuid: str | None = None, psk: str | None = "password123",
                  key_mgmt: str = "wpa-psk", mode: str = "infrastructure",
                  autoconnect: bool = True, extra_security: str = "") -> str:
  security = ""
  if psk is not None or extra_security:
    security = f"""
[wifi-security]
key-mgmt={key_mgmt}
{f"psk={psk}" if psk is not None else ""}
{extra_security}
"""
  content = f"""\
[connection]
id={ssid}
uuid={file_uuid or ssid.lower() + "-uuid"}
type=wifi
autoconnect={str(autoconnect).lower()}

[wifi]
ssid={ssid}
mode={mode}
{security}
"""
  path = os.path.join(directory, filename)
  Path(path).write_text(content)
  return path


def require_entry(store: NetworkStore, ssid: str) -> dict:
  entry = store.get(ssid)
  assert entry is not None
  return entry


class TestNetworkStore:
  def setup_method(self):
    self.root = tempfile.mkdtemp()
    self.persistent = os.path.join(self.root, "persistent")
    self.runtime = os.path.join(self.root, "runtime")
    self.netplan = os.path.join(self.root, "netplan")
    for directory in (self.persistent, self.runtime, self.netplan):
      os.mkdir(directory)

  def teardown_method(self):
    shutil.rmtree(self.root)

  def patch_reads(self, mocker):
    mocker.patch.object(store_module, "sudo_read", side_effect=lambda path: Path(path).read_text())

  def make_store(self) -> NetworkStore:
    return NetworkStore(self.persistent, self.runtime, self.netplan)

  def test_loads_persistent_and_open_profiles(self, mocker):
    write_profile(self.persistent, "secure.nmconnection", "Secure")
    write_profile(self.persistent, "open.nmconnection", "Open", psk=None)
    self.patch_reads(mocker)

    store = self.make_store()

    assert require_entry(store, "Secure")["psk"] == "password123"
    assert require_entry(store, "Open")["psk"] == ""

  def test_skips_profiles_that_cannot_be_reproduced_safely(self, mocker):
    write_profile(self.persistent, "enterprise.nmconnection", "Enterprise", psk=None, key_mgmt="wpa-eap", extra_security="identity=user")
    write_profile(self.persistent, "agent-secret.nmconnection", "AgentSecret", psk=None, extra_security="psk-flags=1")
    write_profile(self.persistent, "wep.nmconnection", "Wep", psk=None, key_mgmt="none", extra_security="wep-key0=abcde")
    write_profile(self.persistent, "disabled.nmconnection", "Disabled", autoconnect=False)
    write_profile(self.persistent, "hotspot.nmconnection", "Hotspot", psk=None, mode="ap")
    self.patch_reads(mocker)

    store = self.make_store()

    assert store.get_all() == {}

  def test_runtime_profiles_remain_live_sources_despite_stale_marker(self, mocker):
    runtime_path = write_profile(self.runtime, "netplan.nmconnection", "Runtime")
    Path(self.persistent, ".wpa_supplicant-import-complete").write_text("complete\n")
    self.patch_reads(mocker)
    run = mocker.patch.object(store_module.subprocess, "run")

    store = self.make_store()

    assert require_entry(store, "Runtime")["psk"] == "password123"
    assert os.path.exists(runtime_path)
    assert os.listdir(self.persistent) == [".wpa_supplicant-import-complete"]
    run.assert_not_called()

  def test_persistent_profile_wins_runtime_duplicate(self, mocker):
    write_profile(self.persistent, "persistent.nmconnection", "Duplicate", psk="persistent")
    write_profile(self.runtime, "runtime.nmconnection", "Duplicate", psk="runtime")
    self.patch_reads(mocker)

    store = self.make_store()

    assert require_entry(store, "Duplicate")["psk"] == "persistent"

  def test_unsupported_persistent_profile_blocks_runtime_duplicate(self, mocker):
    write_profile(self.persistent, "persistent.nmconnection", "Enterprise", psk=None, key_mgmt="wpa-eap", extra_security="identity=user")
    write_profile(self.runtime, "runtime.nmconnection", "Enterprise")
    self.patch_reads(mocker)

    store = self.make_store()

    assert store.get("Enterprise") is None

  def test_forget_runtime_profile_removes_netplan_source(self, mocker):
    write_profile(self.runtime, "netplan.nmconnection", "Runtime", file_uuid="runtime-uuid")
    netplan_path = Path(self.netplan, "90-NM-runtime-uuid.yaml")
    netplan_path.write_text("network:\n  version: 2\n")
    self.patch_reads(mocker)
    run = mocker.patch.object(store_module.subprocess, "run", return_value=MagicMock(returncode=0))
    store = self.make_store()

    assert store.remove("Runtime")

    removed = [args.args[0][-1] for args in run.call_args_list if args.args[0][:3] == ["sudo", "rm", "-f"]]
    assert str(netplan_path) in removed
    assert store.get("Runtime") is None

  def test_forget_keeps_profile_when_disk_removal_fails(self, mocker):
    write_profile(self.runtime, "netplan.nmconnection", "Runtime", file_uuid="runtime-uuid")
    self.patch_reads(mocker)
    mocker.patch.object(store_module.subprocess, "run", return_value=MagicMock(returncode=1))
    store = self.make_store()

    assert not store.remove("Runtime")
    assert store.get("Runtime") is not None

  def test_edit_runtime_profile_installs_keyfile_before_removing_netplan(self, mocker):
    write_profile(self.runtime, "netplan.nmconnection", "Runtime", file_uuid="runtime-uuid")
    netplan_path = Path(self.netplan, "90-NM-runtime-uuid.yaml")
    netplan_path.write_text("network:\n  version: 2\n")
    self.patch_reads(mocker)
    run = mocker.patch.object(store_module.subprocess, "run", return_value=MagicMock(returncode=0))
    store = self.make_store()

    store.save_network("Runtime", psk="replacement")

    commands = [item.args[0] for item in run.call_args_list]
    install_index = next(i for i, command in enumerate(commands)
                         if command[:2] == ["sudo", "install"] and command[-1].endswith("runtime-uuid-Runtime.nmconnection"))
    remove_index = next(i for i, command in enumerate(commands)
                        if command[:3] == ["sudo", "rm", "-f"] and command[-1] == str(netplan_path))
    assert install_index < remove_index
    assert require_entry(store, "Runtime")["psk"] == "replacement"
    assert require_entry(store, "Runtime")["_netplan_filename"] is None

  def test_edit_runtime_profile_rolls_back_when_netplan_remove_fails(self, mocker):
    write_profile(self.runtime, "netplan.nmconnection", "Runtime", file_uuid="runtime-uuid")
    netplan_path = Path(self.netplan, "90-NM-runtime-uuid.yaml")
    netplan_path.write_text("network:\n  version: 2\n")
    self.patch_reads(mocker)
    store = self.make_store()

    def run(command, **_):
      return MagicMock(returncode=1 if command[-1] == str(netplan_path) else 0)

    process = mocker.patch.object(store_module.subprocess, "run", side_effect=run)
    keyfile_path = os.path.join(self.persistent, "runtime-uuid-Runtime.nmconnection")

    try:
      store.save_network("Runtime", psk="replacement")
      raise AssertionError("save_network should fail when the netplan source survives")
    except OSError:
      pass

    commands = [item.args[0] for item in process.call_args_list]
    assert ["sudo", "rm", "-f", keyfile_path] in commands
    assert require_entry(store, "Runtime")["psk"] == "password123"
    assert require_entry(store, "Runtime")["_netplan_filename"] == "90-NM-runtime-uuid.yaml"

  def test_saved_profile_uses_nm_keyfile_compatible_name_and_mode(self, mocker):
    run = mocker.patch.object(store_module.subprocess, "run", return_value=MagicMock(returncode=0))
    store = self.make_store()

    store.save_network("Cafe/Wifi", psk="password123")

    install = next(item.args[0] for item in run.call_args_list
                   if item.args[0][:2] == ["sudo", "install"] and "-d" not in item.args[0])
    assert install[-1].endswith("-Cafe_Wifi.nmconnection")
    assert install[install.index("-m") + 1] == "600"

  def test_rejects_boundary_whitespace_that_keyfiles_cannot_round_trip(self, mocker):
    run = mocker.patch.object(store_module.subprocess, "run")
    store = self.make_store()

    store.save_network(" Leading", psk="password123")
    store.save_network("Trailing ", psk="password123")
    store.save_network("Valid", psk=" password123")

    assert store.get_all() == {}
    run.assert_not_called()

  def test_get_returns_copy(self):
    store = self.make_store()
    store._networks["Test"] = {"psk": "password123"}

    entry = require_entry(store, "Test")
    entry["psk"] = "changed"

    assert require_entry(store, "Test")["psk"] == "password123"
