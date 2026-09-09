import configparser
import json
import queue
import subprocess
import tempfile
import time
import uuid
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import TestCase
from unittest.mock import patch

from openpilot.common import wifi
from openpilot.system.ui.lib import wifi_controller, wifi_manager, wifi_network_store, wifi_tethering_store, wpa_supplicant
from openpilot.system.ui.lib.wifi_controller import WifiController
from openpilot.system.ui.lib.dhcp_client import DhcpClient
from openpilot.system.ui.lib.wifi_network_store import NetworkStore
from openpilot.system.ui.lib.wifi_tethering_store import TetheringStore


class Supplicant:
  def __init__(self, config):
    self.config = config
    self.networks = {}
    self.current = None
    self.events = queue.Queue()

  def open(self):
    pass

  def close(self):
    pass

  def recv(self, timeout):
    try:
      return self.events.get(timeout=timeout)
    except queue.Empty:
      return None

  def request(self, command):
    verb, _, args = command.partition(" ")
    if verb == "RECONFIGURE":
      active_uuid = self.networks.get(self.current, {}).get("id_str")
      self.networks = {}
      for block in self.config.read_text().split("network={")[1:]:
        fields = dict(line.strip().split("=", 1) for line in block.split("}", 1)[0].splitlines() if "=" in line)
        self.networks[str(len(self.networks))] = fields
      self.current = next((key for key, value in self.networks.items() if value.get("id_str") == active_uuid), None)
    elif verb == "LIST_NETWORKS":
      return "network id / ssid / bssid / flags\n" + "\n".join(
        f"{key}\t{bytes.fromhex(value['ssid']).decode()}\tany\t" for key, value in self.networks.items())
    elif verb == "STATUS":
      if self.current is None:
        return "wpa_state=DISCONNECTED\n"
      network = self.networks[self.current]
      ssid = "".join(f"\\x{byte:02x}" for byte in bytes.fromhex(network["ssid"]))
      return f"wpa_state=COMPLETED\nssid={ssid}\nid={self.current}\nid_str={network['id_str']}\n"
    elif verb == "SCAN_RESULTS":
      return "bssid / frequency / signal level / flags / ssid\n"
    elif verb == "GET_NETWORK":
      key, field = args.split()
      return self.networks[key][field]
    elif verb == "ADD_NETWORK":
      key = str(max(map(int, self.networks), default=-1) + 1)
      self.networks[key] = {"disabled": "1"}
      return key
    elif verb == "SET_NETWORK":
      key, field, value = args.split(" ", 2)
      self.networks[key][field] = value
    elif verb in ("ENABLE_NETWORK", "DISABLE_NETWORK", "SELECT_NETWORK"):
      for key, fields in self.networks.items():
        if args == "all" or key == args or verb == "SELECT_NETWORK":
          fields["disabled"] = str(int(verb == "DISABLE_NETWORK" or (verb == "SELECT_NETWORK" and key != args)))
      if self.current is not None and self.networks[self.current].get("disabled", "0") == "1":
        self.current = None
    elif verb == "REMOVE_NETWORK":
      self.networks.pop(args)
      if self.current == args:
        self.current = None
    else:
      assert verb in ("SCAN", "REASSOCIATE"), command
    return "OK\n"

  def associate(self, ssid, wrong_key=False):
    key = next(key for key, value in self.networks.items()
               if value.get("ssid") == ssid.encode().hex() and value.get("disabled", "0") == "0")
    if wrong_key:
      self.events.put(f'CTRL-EVENT-SSID-TEMP-DISABLED id={key} ssid="{ssid}" reason=WRONG_KEY')
    else:
      self.current = key


class Lease:
  running = False
  address = ""
  stop_ok = True

  def start(self):
    self.running = True
    return True

  def stop(self):
    if not self.stop_ok:
      return False
    self.running, self.address = False, ""
    return True

  def clear_ipv6(self):
    return True

  def ready(self):
    return self.running and bool(self.address)

  def ipv4_address(self):
    return self.address


class TestWifiFlows(TestCase):
  def setUp(self):
    self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
    self.saved, self.runtime = self.root / "saved", self.root / "runtime"
    self.saved.mkdir()
    self.runtime.mkdir()
    self.netplan = self.root / "netplan"
    self.netplan.mkdir()
    self.station, self.ap = self.root / "sta.conf", self.root / "ap.conf"
    self.ctrl, self.lease = Supplicant(self.station), Lease()
    self.mode, self.ap_active, self.forwarding = None, False, False
    self.manager = None
    self.events = []
    self.fail_file = lambda command: False
    self.real_run = subprocess.run
    commands = SimpleNamespace(run=self.run_file_command, SubprocessError=subprocess.SubprocessError)
    for module in (wifi, wifi_network_store, wifi_tethering_store):
      self.enterContext(patch.object(module, "subprocess", commands))
    for module in (wifi_network_store, wifi_tethering_store):
      self.enterContext(patch.object(module, "sudo_read", lambda path: Path(path).read_text()))
    self.enterContext(patch.object(wifi, "WIFI_RUNTIME_DIR", str(self.root)))
    self.enterContext(patch.object(wifi, "ACTIVE_PROFILE_PATH", str(self.root / "active_profile")))
    self.enterContext(patch.object(wifi_controller, "RECONCILE_PERIOD_SECONDS", 0.01))
    for module in (wifi_controller, wpa_supplicant):
      self.enterContext(patch.object(module, "WpaCtrl", return_value=self.ctrl))
    self.enterContext(patch.object(wifi_controller, "WpaCtrlMonitor", return_value=self.ctrl))
    for name, value in {
      "WPA_SUPPLICANT_CONF": str(self.station), "WPA_AP_CONF": str(self.ap),
      "write_station_config": partial(wpa_supplicant.write_station_config, path=str(self.station)),
      "write_ap_config": partial(wpa_supplicant.write_ap_config, path=str(self.ap)),
      "is_running": lambda conf: self.mode == conf,
      "begin_station": self.begin_station,
      "start": self.start_mode, "stop": self.stop_mode,
      "restore_networkmanager": lambda: True,
    }.items():
      self.enterContext(patch.object(wpa_supplicant, name, value))
    session = SimpleNamespace(start=self.start_ap, stop=self.stop_ap, adopt=lambda: self.ap_active)
    sessions = self.enterContext(patch.object(wifi_controller.wifi_tethering, "TetheringSession", return_value=session))
    sessions.cleanup_stale.return_value = True
    for name, value in {
      "get_ipv4_forward": lambda: self.forwarding, "set_ipv4_forward": self.set_forwarding,
      "dnsmasq_running": lambda: self.ap_active, "interface_ready": lambda: self.ap_active,
      "firewall_ready": lambda: self.ap_active, "wait_for_ap_ready": lambda: self.mode == str(self.ap),
    }.items():
      self.enterContext(patch.object(wifi_controller.wifi_tethering, name, value))
    self.enterContext(patch.object(wifi_manager, "Params", None))
    self.enterContext(patch.object(wifi_manager.atexit, "register"))
    self.enterContext(patch.object(wifi_manager, "WifiController", side_effect=lambda **kwargs: WifiController(
      store=self.store(), dhcp=cast(DhcpClient, self.lease),
      tethering_store=TetheringStore(str(self.saved), str(self.runtime)), **kwargs)))
    self.addCleanup(lambda: self.manager.stop() if self.manager is not None else None)

  def run_file_command(self, command, **kwargs):
    if command[0] == "/usr/bin/python3":
      # JSON fixtures are also YAML; the system YAML parser is an external dependency.
      configs = [json.loads(raw) if raw.strip() and not raw.lstrip().startswith("#") else None for raw in json.loads(kwargs["input"])]
      return subprocess.CompletedProcess(command, 0, stdout=json.dumps(configs))
    if command[:2] == ["netplan", "get"]:
      def merge(target, source):
        for key, value in source.items():
          if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            merge(target[key], value)
          elif key in target and isinstance(target[key], list) and isinstance(value, list):
            target[key] += value
          else:
            target[key] = value

      config = {}
      for path in sorted((Path(command[-1]) / "etc/netplan").glob("*.yaml")):
        raw = path.read_text()
        if raw.strip() and not raw.lstrip().startswith("#"):
          merge(config, json.loads(raw))
          if any(not definition.get("access-points") for definition in config.get("network", {}).get("wifis", {}).values()):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="Command failed: No access points defined\n")
      config.setdefault("network", {}).setdefault("version", 2)
      return subprocess.CompletedProcess(command, 0, stdout="" if set(config["network"]) == {"version"} else json.dumps(config))
    assert command[0] == "sudo" and command[1] in ("install", "mv", "rm", "touch", "ln", "cat"), command
    assert Path(command[-1]).resolve().is_relative_to(self.root), command
    if self.fail_file(command):
      if kwargs.get("check"):
        raise subprocess.CalledProcessError(1, command)
      return subprocess.CompletedProcess(command, 1)
    return self.real_run(command[1:], **kwargs)

  def store(self):
    return NetworkStore(str(self.saved), str(self.runtime), netplan_directory=str(self.netplan))

  def seed_netplan(self, ssid="Test"):
    path = self.seed(ssid, runtime=True)
    source = self.netplan / f"90-NM-{path.stem}.yaml"
    source.write_text(json.dumps({"network": {"version": 2, "wifis": {
      f"NM-{path.stem}": {"renderer": "NetworkManager", "dhcp4": True, "access-points": {
        ssid: {"networkmanager": {"uuid": path.stem}},
      }},
    }}}))
    return path, source

  def start_mode(self, conf):
    self.mode = conf
    return True

  def stop_mode(self, conf):
    assert self.mode in (None, conf)
    self.mode = None
    return True

  def begin_station(self):
    self.start_mode(str(self.station))
    return SimpleNamespace(commit=lambda: True, rollback=lambda: True)

  def start_ap(self, forwarding):
    self.ap_active, self.forwarding = True, forwarding
    return True

  def stop_ap(self):
    self.ap_active = False
    return True

  def set_forwarding(self, enabled):
    self.forwarding = enabled

  def seed(self, ssid="Test", runtime=False):
    identifier = str(uuid.uuid4())
    path = (self.runtime if runtime else self.saved) / f"{identifier}.nmconnection"
    path.write_text(f"""[connection]
id=openpilot connection {ssid}
uuid={identifier}
type=wifi
autoconnect-retries=0
[wifi]
ssid={ssid}
[wifi-security]
key-mgmt=wpa-psk
psk=password123
[ipv4]
method=auto
dns-priority=600
[ipv6]
method=ignore
""")
    return path

  def start(self):
    self.manager = wifi_manager.WifiManager()
    self.manager.add_callbacks(
      forgotten=lambda ssid: self.events.append(("forgotten", ssid)),
      forget_failed=lambda ssid: self.events.append(("forget_failed", ssid)),
      need_auth=lambda ssid: self.events.append(("need_auth", ssid)),
      networks_updated=lambda _: self.events.append(("updated", None)),
    )
    self.wait(lambda: self.mode == str(self.station) and self.station.exists())

  def wait(self, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
      self.manager.process_callbacks()
      if predicate():
        return
      time.sleep(0.01)
    self.fail(f"Wi-Fi operation did not complete: {self.manager.wifi_state}; events={self.events}")

  def connect(self, ssid="Test", password="password123", saved=False):
    if saved:
      self.manager.activate_connection(ssid)
    else:
      self.manager.connect_to_network(ssid, password)
    self.wait(lambda: self.manager.connecting_to_ssid == ssid and any(
      value.get("ssid") == ssid.encode().hex() and value.get("disabled", "0") == "0" for value in self.ctrl.networks.values()))
    self.ctrl.associate(ssid)
    self.wait(lambda: self.lease.running)
    self.lease.address = "10.0.0.2"
    self.wait(lambda: self.manager.connected_ssid == ssid)

  def read_profile(self, ssid):
    for path in self.saved.glob("*.nmconnection"):
      cp = configparser.ConfigParser(interpolation=None)
      cp.read(path)
      value = cp.get("wifi", "ssid")
      if value == ssid or value == ";".join(map(str, ssid.encode())) + ";":
        return cp
    self.fail(f"No saved profile for {ssid}")

  def test_connect_persists_and_metering_survives_reopen(self):
    self.start()
    self.connect()
    self.manager.set_current_network_metered(wifi_manager.MeteredType.YES)
    self.wait(lambda: self.manager.current_network_metered == wifi_manager.MeteredType.YES)
    cp = self.read_profile("Test")
    assert cp.get("wifi-security", "psk") == "password123"
    assert cp.getint("connection", "metered") == 1
    self.wait(lambda: (self.root / "active_profile").read_text().split() == [cp.get("connection", "uuid"), "1"])
    self.manager.stop()
    self.start()
    self.wait(lambda: self.manager.connected_ssid == "Test")
    assert self.manager.current_network_metered == wifi_manager.MeteredType.YES

  def test_wrong_password_preserves_saved_credentials_and_allows_retry(self):
    path = self.seed()
    before = path.read_bytes()
    self.start()
    self.manager.connect_to_network("Test", "incorrect123")
    self.wait(lambda: self.manager.connecting_to_ssid == "Test")
    self.ctrl.associate("Test", wrong_key=True)
    self.wait(lambda: ("need_auth", "Test") in self.events)
    assert path.read_bytes() == before
    self.connect(saved=True)

  def test_forget_removes_files_and_runtime_profile_but_keeps_other_networks(self):
    path, other = self.seed(), self.seed("Other")
    shadow = self.runtime / path.name
    shadow.write_bytes(path.read_bytes())
    identifier = path.stem
    self.start()
    self.connect(saved=True)
    self.manager.forget_connection("Test")
    self.wait(lambda: ("forgotten", "Test") in self.events)
    assert not self.manager.is_connection_saved("Test")
    assert not path.exists() and not shadow.exists()
    assert other.exists()
    assert identifier not in self.station.read_text()
    assert all(value.get("id_str", "").strip('"') != identifier for value in self.ctrl.networks.values())
    store = NetworkStore(str(self.saved), str(self.runtime))
    store.recover()
    assert not store.profiles_for_ssid("Test")
    self.connect("Other", saved=True)

  def test_forget_cancels_an_unsaved_selection(self):
    self.start()
    self.manager.connect_to_network("Missing", "password123", hidden=True)
    self.wait(lambda: self.manager.connecting_to_ssid == "Missing")
    self.manager.forget_connection("Missing")
    self.wait(lambda: ("forgotten", "Missing") in self.events)
    assert not self.manager.is_connection_saved("Missing")
    assert self.manager.connecting_to_ssid is None
    assert not self.ctrl.networks
    assert not NetworkStore(str(self.saved), str(self.runtime)).profiles_for_ssid("Missing")

  def check_failed_forget(self, failure):
    path = self.seed()
    before = path.read_bytes()
    self.start()
    self.wait(lambda: self.manager.is_connection_saved("Test"))
    self.fail_file = failure
    self.manager.forget_connection("Test")
    self.wait(lambda: ("forget_failed", "Test") in self.events)
    assert ("forgotten", "Test") not in self.events
    assert self.manager.is_connection_saved("Test")
    assert path.read_bytes() == before
    assert NetworkStore(str(self.saved), str(self.runtime)).profiles_for_ssid("Test")
    self.fail_file = lambda command: False
    self.events.clear()
    self.manager.forget_connection("Test")
    self.wait(lambda: ("forgotten", "Test") in self.events)
    assert not path.exists()

  def test_failed_forget_stage_preserves_profile_and_allows_retry(self):
    self.check_failed_forget(lambda command: command[1] == "mv" and ".openpilot-forget-" in command[-1])

  def test_failed_forget_commit_preserves_profile_and_allows_retry(self):
    self.check_failed_forget(lambda command: command[1] == "touch")

  def test_runtime_only_profile_reports_failure_without_deleting_source(self):
    path = self.seed(runtime=True)
    self.start()
    self.connect(saved=True)
    address = self.manager.ipv4_address
    self.manager.forget_connection("Test")
    self.wait(lambda: ("forget_failed", "Test") in self.events)
    assert ("forgotten", "Test") not in self.events
    assert path.exists() and self.manager.is_connection_saved("Test")
    assert self.ctrl.current is not None
    assert self.lease.running and self.lease.address == address

  def test_forget_netplan_profile_preserves_other_access_points_and_definitions(self):
    path, source = self.seed_netplan()
    other, other_source = self.seed_netplan("Other")
    config = json.loads(source.read_text())
    config["network"]["wifis"][f"NM-{path.stem}"]["access-points"]["Shared"] = {}
    config["network"]["ethernets"] = {"eth0": {"dhcp4": True}}
    source.write_text(json.dumps(config))
    expected = json.loads(source.read_text())
    del expected["network"]["wifis"][f"NM-{path.stem}"]["access-points"]["Test"]
    other_before = other_source.read_bytes()
    self.start()
    self.connect(saved=True)

    self.manager.forget_connection("Test")

    self.wait(lambda: ("forgotten", "Test") in self.events)
    assert not self.manager.is_connection_saved("Test")
    assert not path.exists()
    assert json.loads(source.read_text()) == expected
    assert other.exists() and other_source.read_bytes() == other_before
    self.store().recover()
    assert not self.store().profiles_for_ssid("Test")
    assert path.stem not in self.station.read_text()

  def test_failed_netplan_forget_restores_sources_and_allows_retry(self):
    path, source = self.seed_netplan()
    before = source.read_bytes(), path.read_bytes()
    self.start()
    self.wait(lambda: self.manager.is_connection_saved("Test"))
    self.fail_file = lambda command: command[1] == "touch"

    self.manager.forget_connection("Test")

    self.wait(lambda: ("forget_failed", "Test") in self.events)
    assert (source.read_bytes(), path.read_bytes()) == before
    assert self.manager.is_connection_saved("Test")
    self.fail_file = lambda command: False
    self.manager.forget_connection("Test")
    self.wait(lambda: ("forgotten", "Test") in self.events)
    assert not path.exists()
    assert not source.exists()

  def test_forget_keeps_other_netplan_definitions_in_their_files_during_removal(self):
    path, source = self.seed_netplan()
    config = json.loads(source.read_text())
    config["network"]["ethernets"] = {"eth0": {"addresses": ["192.0.2.10/24"]}}
    source.write_text(json.dumps(config))
    override = self.netplan / "99-ethernet.yaml"
    override.write_text(json.dumps({"network": {"version": 2, "ethernets": {"eth0": {"dhcp4": True}}}}))
    before = source.read_bytes(), override.read_bytes(), path.read_bytes()

    def run(command, **kwargs):
      result = self.run_file_command(command, **kwargs)
      if command[:2] in (["sudo", "mv"], ["sudo", "rm"]) and command[-1] == str(source):
        assert json.loads(source.read_text())["network"]["ethernets"] == {"eth0": {"addresses": ["192.0.2.10/24"]}}
      return result

    with patch.object(wifi_network_store.subprocess, "run", side_effect=run):
      self.fail_file = lambda command: command[1] == "touch"
      assert not self.store().remove_ssid("Test")
      assert (source.read_bytes(), override.read_bytes(), path.read_bytes()) == before
      self.fail_file = lambda command: False
      assert self.store().remove_ssid("Test")

    assert not path.exists()
    assert override.read_bytes() == before[1]
    assert json.loads(source.read_text())["network"]["ethernets"] == {"eth0": {"addresses": ["192.0.2.10/24"]}}

  def test_forget_removes_all_files_of_a_split_netplan_definition(self):
    path, source = self.seed_netplan()
    override = self.netplan / "99-override.yaml"
    override.write_text(json.dumps({"network": {"version": 2, "wifis": {f"NM-{path.stem}": {"dhcp4": True}}}}))
    saved = self.saved / path.name
    saved.write_bytes(path.read_bytes())

    assert self.store().remove_ssid("Test")

    assert not source.exists() and not override.exists()
    assert not path.exists() and not saved.exists()

  def test_forget_netplan_access_points_split_across_files(self):
    path, original = self.seed_netplan()
    source = original.rename(self.netplan / "01-wifi.yaml")
    other = self.seed("Other", runtime=True)
    override = self.netplan / "99-wifi.yaml"
    override.write_text(json.dumps({"network": {"version": 2, "wifis": {f"NM-{path.stem}": {
      "access-points": {"Other": {"networkmanager": {"uuid": other.stem}}},
    }}}}))
    before = source.read_bytes(), override.read_bytes(), path.read_bytes(), other.read_bytes()
    store = self.store()

    assert store.can_remove_ssid("Test")
    self.fail_file = lambda command: command[1] == "touch"
    assert not store.remove_ssid("Test")
    assert (source.read_bytes(), override.read_bytes(), path.read_bytes(), other.read_bytes()) == before
    self.fail_file = lambda command: False
    assert store.remove_ssid("Test")

    assert not path.exists() and not store.profiles_for_ssid("Test")
    assert store.profiles_for_ssid("Other")
    assert override.read_bytes() == before[1] and other.read_bytes() == before[3]
    assert store.remove_ssid("Other")
    assert not source.exists() and not override.exists() and not other.exists()

  def test_forget_netplan_profile_with_uuid_in_another_file(self):
    path, source = self.seed_netplan()
    name = f"NM-{path.stem}"
    config = json.loads(source.read_text())
    del config["network"]["wifis"][name]["access-points"]["Test"]["networkmanager"]
    source.write_text(json.dumps(config))
    override = self.netplan / "99-uuid.yaml"
    override.write_text(json.dumps({"network": {"version": 2, "wifis": {name: {"networkmanager": {"uuid": path.stem}}}}}))
    store = self.store()

    assert store.can_remove_ssid("Test")
    assert store.remove_ssid("Test")

    assert not store.profiles_for_ssid("Test")
    assert not path.exists() and not source.exists() and not override.exists()

  def test_split_netplan_definition_stays_valid_during_removal_and_recovery(self):
    class Interrupted(BaseException):
      pass

    path, original = self.seed_netplan()
    source = original.rename(self.netplan / "01-wifi.yaml")
    fragment = self.netplan / "99-wifi.yaml"
    fragment.write_text(json.dumps({"network": {"version": 2, "wifis": {f"NM-{path.stem}": {"dhcp4": True}}}}))
    before = source.read_bytes(), fragment.read_bytes(), path.read_bytes()

    def run(command, **kwargs):
      if command[:2] == ["sudo", "touch"]:
        raise Interrupted
      result = self.run_file_command(command, **kwargs)
      assert not fragment.exists() or source.exists()
      return result

    with patch.object(wifi_network_store.subprocess, "run", side_effect=run):
      with self.assertRaises(Interrupted):
        self.store().remove_ssid("Test")
      self.fail_file = lambda command: command[:2] == ["sudo", "mv"] and command[-1] == str(source)
      with self.assertRaises(OSError):
        self.store().recover()
      assert not fragment.exists()
      self.fail_file = lambda command: False
      self.store().recover()

    assert (source.read_bytes(), fragment.read_bytes(), path.read_bytes()) == before
    assert self.store().remove_ssid("Test")

  def test_empty_netplan_documents_do_not_block_forget(self):
    for content in ("", "# intentionally empty configuration\n"):
      with self.subTest(content=content):
        path = self.seed()
        source = self.netplan / "01-empty.yaml"
        source.write_text(content)
        store = self.store()

        assert store.can_remove_ssid("Test")
        assert store.remove_ssid("Test")

        assert not path.exists()
        assert source.read_text() == content

  def test_netplan_uuid_mismatch_refuses_forget_without_disconnect(self):
    path, source = self.seed_netplan()
    source.write_text(source.read_text().replace(path.stem, str(uuid.uuid4())))
    before = source.read_bytes()
    self.start()
    self.connect(saved=True)
    address = self.manager.ipv4_address

    self.manager.forget_connection("Test")

    self.wait(lambda: ("forget_failed", "Test") in self.events)
    assert source.read_bytes() == before and path.exists()
    assert self.ctrl.current is not None
    assert self.lease.running and self.lease.address == address

  def test_netplan_read_and_parse_errors_preserve_saved_profiles(self):
    path, source = self.seed_netplan()
    before = path.read_bytes()
    self.fail_file = lambda command: command[1] == "cat"
    store = self.store()
    assert not store.can_remove_ssid("Test")
    assert not store.remove_ssid("Test")
    assert path.read_bytes() == before

    self.fail_file = lambda command: False
    source.write_text("{")
    assert not store.can_remove_ssid("Test")
    assert not store.remove_ssid("Test")
    assert path.read_bytes() == before

  def test_netplan_validation_errors_preserve_saved_profiles(self):
    path, source = self.seed_netplan()
    saved = self.saved / path.name
    saved.write_bytes(path.read_bytes())
    invalid = self.netplan / "99-invalid.yaml"
    invalid.write_text(json.dumps({"network": {"version": 2, "wifis": {"incomplete": {"dhcp4": True}}}}))
    before = path.read_bytes(), saved.read_bytes(), source.read_bytes(), invalid.read_bytes()
    store = self.store()

    assert not store.can_remove_ssid("Test")
    assert not store.remove_ssid("Test")

    assert (path.read_bytes(), saved.read_bytes(), source.read_bytes(), invalid.read_bytes()) == before
    assert store.profiles_for_ssid("Test")
    invalid.unlink()
    assert store.can_remove_ssid("Test")
    assert store.remove_ssid("Test")
    assert not path.exists() and not saved.exists() and not source.exists()

  def test_netplan_candidate_validation_failure_preserves_profiles(self):
    path, source = self.seed_netplan()
    before = path.read_bytes(), source.read_bytes()
    store = self.store()

    def run(command, **kwargs):
      result = self.run_file_command(command, **kwargs)
      if command[:2] == ["netplan", "get"] and not result.stdout:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="Command failed: failed to read configuration\n")
      return result

    with patch.object(wifi_network_store.subprocess, "run", side_effect=run):
      assert not store.can_remove_ssid("Test")
      assert not store.remove_ssid("Test")

    assert (path.read_bytes(), source.read_bytes()) == before
    assert store.profiles_for_ssid("Test")
    assert store.remove_ssid("Test")
    assert not path.exists() and not source.exists()

  def test_netplan_file_failures_preserve_shared_source_and_allow_retry(self):
    for operation in ("backup", "backup_commit", "ln", "install", "replace", "shadow", "touch"):
      with self.subTest(operation=operation):
        path, source = self.seed_netplan()
        config = json.loads(source.read_text())
        config["network"]["wifis"][f"NM-{path.stem}"]["access-points"]["Other"] = {}
        source.write_text(json.dumps(config))
        before = source.read_bytes(), path.read_bytes()

        def fail(command, operation=operation):
          if operation == "backup":
            return command[1] == "install" and ".openpilot-update-" in command[-1]
          if operation == "backup_commit":
            return command[1] == "mv" and ".openpilot-update-" in command[-2]
          if operation == "install":
            return command[1] == "install" and ".openpilot-netplan-update-" in command[-1]
          if operation == "replace":
            return command[1] == "mv" and ".openpilot-netplan-update-" in command[-2]
          if operation == "shadow":
            return command[1] == "mv" and Path(command[-2]).parent == self.runtime and ".openpilot-shadow-" in command[-1]
          return command[1] == operation

        self.fail_file = fail
        assert not self.store().remove_ssid("Test")
        assert (source.read_bytes(), path.read_bytes()) == before
        self.fail_file = lambda command: False
        assert self.store().remove_ssid("Test")
        assert not path.exists()
        assert json.loads(source.read_text())["network"]["wifis"][f"NM-{path.stem}"]["access-points"] == {"Other": {}}

  def test_netplan_forget_recovers_before_and_after_commit(self):
    class Interrupted(BaseException):
      pass

    for committed, reboot in ((False, False), (False, True), (True, False), (True, True)):
      with self.subTest(committed=committed, reboot=reboot):
        self.runtime.mkdir(exist_ok=True)
        path, source = self.seed_netplan()
        before = source.read_bytes(), path.read_bytes()

        def interrupt(command, committed=committed):
          if command[1] == ("rm" if committed else "touch") and ("openpilot-" in command[-1]):
            raise Interrupted
          return False

        self.fail_file = interrupt
        with self.assertRaises(Interrupted):
          self.store().remove_ssid("Test")
        self.fail_file = lambda command: False
        if reboot:
          for runtime_path in self.runtime.iterdir():
            runtime_path.unlink()
          self.runtime.rmdir()
        store = self.store()
        store.recover()
        if committed:
          assert not source.exists() and not path.exists()
          assert not store.profiles_for_ssid("Test")
        else:
          assert (source.read_bytes(), path.read_bytes()) == before
          assert not store.profiles_for_ssid("Test")[0].persistent
          assert store.remove_ssid("Test")

  def test_failed_netplan_runtime_recovery_keeps_durable_backup_for_retry(self):
    path, source = self.seed_netplan()
    before = path.read_bytes(), source.read_bytes()
    store = self.store()
    self.fail_file = lambda command: command[1] == "touch" or command[1] == "install" and Path(command[-1]).parent == self.runtime

    assert not store.remove_ssid("Test")
    for runtime_path in self.runtime.iterdir():
      runtime_path.unlink()
    with self.assertRaises(OSError):
      self.store().recover()

    self.fail_file = lambda command: False
    store = self.store()
    store.recover()
    assert (path.read_bytes(), source.read_bytes()) == before
    assert not store.profiles_for_ssid("Test")[0].persistent
    assert not list(self.saved.iterdir())
    assert store.remove_ssid("Test")

  def test_tethering_password_and_forwarding_then_return_to_station(self):
    self.start()
    self.connect()
    self.manager.set_ipv4_forward(True)
    self.manager.set_tethering_active(True)
    self.wait(self.manager.is_tethering_active)
    assert self.forwarding and self.ap_active
    self.manager.set_tethering_password("newpassword")
    self.wait(lambda: self.manager.tethering_password == "newpassword" and self.manager.is_tethering_active())
    assert 'psk="newpassword"' in self.ap.read_text()
    store = TetheringStore(str(self.saved), str(self.runtime))
    assert store.get("weedle").password == "newpassword"
    self.manager.set_tethering_active(False)
    self.wait(lambda: not self.manager.is_tethering_active())
    assert not self.ap_active
    self.connect(saved=True)
