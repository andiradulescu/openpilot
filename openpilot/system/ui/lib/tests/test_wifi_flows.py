import configparser
import queue
import subprocess
import tempfile
import time
import uuid
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from openpilot.common import wifi
from openpilot.system.ui.lib import wifi_controller, wifi_manager, wifi_network_store, wifi_tethering_store, wpa_supplicant
from openpilot.system.ui.lib.wifi_controller import WifiController
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
      store=NetworkStore(str(self.saved), str(self.runtime)), dhcp=self.lease,
      tethering_store=TetheringStore(str(self.saved), str(self.runtime)), **kwargs)))
    self.addCleanup(lambda: self.manager.stop() if self.manager is not None else None)

  def run_file_command(self, command, **kwargs):
    assert command[0] == "sudo" and command[1] in ("install", "mv", "rm", "touch"), command
    assert Path(command[-1]).resolve().is_relative_to(self.root), command
    if self.fail_file(command):
      if kwargs.get("check"):
        raise subprocess.CalledProcessError(1, command)
      return subprocess.CompletedProcess(command, 1)
    return self.real_run(command[1:], **kwargs)

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
