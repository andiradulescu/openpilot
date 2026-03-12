import atexit
import json
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.wpa_ctrl import (WpaCtrl, WpaCtrlMonitor, SecurityType,
                                               parse_scan_results, flags_to_security_type,
                                               parse_status, dbm_to_percent)

try:
  from openpilot.common.params import Params
except Exception:
  Params = None

TETHERING_IP_ADDRESS = "192.168.43.1"
DEFAULT_TETHERING_PASSWORD = "swagswagcomma"
SCAN_PERIOD_SECONDS = 5

WPA_SUPPLICANT_CONF = "/data/wpa_supplicant.conf"
WIFI_NETWORKS_JSON = "/data/wifi_networks.json"
WIFI_MIGRATED_FLAG = "/data/.wifi_migrated"
NM_CONNECTIONS_DIR = "/data/etc/NetworkManager/system-connections"

WPA_CTRL_PATH = "/var/run/wpa_supplicant/wlan0"
WPA_AP_CONF = "/tmp/wpa_supplicant_ap.conf"

DEBUG = False


def normalize_ssid(ssid: str) -> str:
  return ssid.replace("\u2019", "'")  # for iPhone hotspots


class MeteredType(IntEnum):
  UNKNOWN = 0
  YES = 1
  NO = 2


@dataclass(frozen=True)
class Network:
  ssid: str
  strength: int
  security_type: SecurityType
  is_tethering: bool


class ConnectStatus(IntEnum):
  DISCONNECTED = 0
  CONNECTING = 1
  CONNECTED = 2


@dataclass(frozen=True)
class WifiState:
  ssid: str | None = None
  status: ConnectStatus = ConnectStatus.DISCONNECTED


# ---------------------------------------------------------------------------
# Network storage: /data/wifi_networks.json
# ---------------------------------------------------------------------------

class NetworkStore:
  """Persistent storage for saved WiFi networks."""

  def __init__(self, path: str = WIFI_NETWORKS_JSON):
    self._path = path
    self._lock = threading.Lock()
    self._networks: dict[str, dict] = {}
    self._load()

  def _load(self):
    try:
      with open(self._path) as f:
        self._networks = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
      self._networks = {}

  def _save(self):
    tmp = self._path + ".tmp"
    with open(tmp, "w") as f:
      json.dump(self._networks, f, indent=2)
    os.replace(tmp, self._path)

  def get_all(self) -> dict[str, dict]:
    with self._lock:
      return dict(self._networks)

  def get(self, ssid: str) -> dict | None:
    with self._lock:
      return self._networks.get(ssid)

  def save_network(self, ssid: str, psk: str = "", metered: int = 0, hidden: bool = False):
    with self._lock:
      self._networks[ssid] = {"psk": psk, "metered": metered, "hidden": hidden}
      self._save()

  def remove(self, ssid: str) -> bool:
    with self._lock:
      if ssid in self._networks:
        del self._networks[ssid]
        self._save()
        return True
      return False

  def set_metered(self, ssid: str, metered: int):
    with self._lock:
      if ssid in self._networks:
        self._networks[ssid]["metered"] = metered
        self._save()

  def get_metered(self, ssid: str) -> MeteredType:
    with self._lock:
      entry = self._networks.get(ssid)
      if entry:
        m = entry.get("metered", 0)
        if m == MeteredType.YES:
          return MeteredType.YES
        elif m == MeteredType.NO:
          return MeteredType.NO
    return MeteredType.UNKNOWN

  def contains(self, ssid: str) -> bool:
    with self._lock:
      return ssid in self._networks

  def get_psk(self, ssid: str) -> str:
    with self._lock:
      entry = self._networks.get(ssid)
      return entry.get("psk", "") if entry else ""


# ---------------------------------------------------------------------------
# DHCP client management
# ---------------------------------------------------------------------------

class DhcpClient:
  """Manage udhcpc for DHCP on wlan0."""

  def __init__(self, iface: str = "wlan0"):
    self._iface = iface
    self._proc: subprocess.Popen | None = None

  def start(self):
    self.stop()
    try:
      self._proc = subprocess.Popen(
        ["sudo", "udhcpc", "-i", self._iface, "-f", "-q", "-t", "5", "-n"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
      )
    except Exception:
      cloudlog.exception("Failed to start udhcpc")

  def stop(self):
    if self._proc is not None:
      try:
        self._proc.terminate()
        self._proc.wait(timeout=3)
      except Exception:
        try:
          self._proc.kill()
        except Exception:
          pass
      self._proc = None
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", self._iface], capture_output=True, check=False)


# ---------------------------------------------------------------------------
# GSM manager: NM stays for cellular
# ---------------------------------------------------------------------------

class _GsmManager:
  """Manages cellular/GSM via NetworkManager DBus (unchanged from NM era)."""

  def __init__(self):
    self._router = None

  def _ensure_router(self):
    if self._router is not None:
      return True
    try:
      from jeepney.io.threading import DBusRouter, open_dbus_connection
      self._router = DBusRouter(open_dbus_connection(bus="SYSTEM"))
      return True
    except Exception:
      cloudlog.exception("Failed to connect to system D-Bus for GSM")
      return False

  def update_gsm_settings(self, roaming: bool, apn: str, metered: bool):
    if not self._ensure_router():
      return
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.low_level import MessageType

      NM = "org.freedesktop.NetworkManager"
      NM_CONNECTION_IFACE = 'org.freedesktop.NetworkManager.Settings.Connection'

      lte_path = self._get_lte_connection_path()
      if not lte_path:
        cloudlog.warning("No LTE connection found")
        return

      conn_addr = DBusAddress(lte_path, bus_name=NM, interface=NM_CONNECTION_IFACE)
      reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'GetSettings'))
      if reply.header.message_type == MessageType.error:
        cloudlog.warning(f'Failed to get connection settings: {reply}')
        return
      settings = dict(reply.body[0])

      if 'gsm' not in settings:
        settings['gsm'] = {}
      if 'connection' not in settings:
        settings['connection'] = {}

      changes = False
      auto_config = apn == ""

      if settings['gsm'].get('auto-config', ('b', False))[1] != auto_config:
        settings['gsm']['auto-config'] = ('b', auto_config)
        changes = True

      if settings['gsm'].get('apn', ('s', ''))[1] != apn:
        settings['gsm']['apn'] = ('s', apn)
        changes = True

      if settings['gsm'].get('home-only', ('b', False))[1] == roaming:
        settings['gsm']['home-only'] = ('b', not roaming)
        changes = True

      metered_int = int(MeteredType.UNKNOWN if metered else MeteredType.NO)
      if settings['connection'].get('metered', ('i', 0))[1] != metered_int:
        settings['connection']['metered'] = ('i', metered_int)
        changes = True

      if changes:
        reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'UpdateUnsaved', 'a{sa{sv}}', (settings,)))
        if reply.header.message_type == MessageType.error:
          cloudlog.warning(f"Failed to update GSM settings: {reply}")
          return
        self._activate_modem_connection(lte_path)
    except Exception as e:
      cloudlog.exception(f"Error updating GSM settings: {e}")

  def _get_lte_connection_path(self) -> str | None:
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.low_level import MessageType

      NM = "org.freedesktop.NetworkManager"
      NM_SETTINGS_PATH = '/org/freedesktop/NetworkManager/Settings'
      NM_SETTINGS_IFACE = 'org.freedesktop.NetworkManager.Settings'
      NM_CONNECTION_IFACE = 'org.freedesktop.NetworkManager.Settings.Connection'

      settings_addr = DBusAddress(NM_SETTINGS_PATH, bus_name=NM, interface=NM_SETTINGS_IFACE)
      known = self._router.send_and_get_reply(new_method_call(settings_addr, 'ListConnections')).body[0]

      for conn_path in known:
        conn_addr = DBusAddress(conn_path, bus_name=NM, interface=NM_CONNECTION_IFACE)
        reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'GetSettings'))
        if reply.header.message_type == MessageType.error:
          continue
        settings = dict(reply.body[0])
        if settings.get('connection', {}).get('id', ('s', ''))[1] == 'lte':
          return str(conn_path)
    except Exception as e:
      cloudlog.exception(f"Error finding LTE connection: {e}")
    return None

  def _activate_modem_connection(self, connection_path: str):
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.wrappers import Properties

      NM = "org.freedesktop.NetworkManager"
      NM_PATH = '/org/freedesktop/NetworkManager'
      NM_IFACE = 'org.freedesktop.NetworkManager'
      NM_DEVICE_IFACE = 'org.freedesktop.NetworkManager.Device'
      NM_DEVICE_TYPE_MODEM = 8

      nm = DBusAddress(NM_PATH, bus_name=NM, interface=NM_IFACE)
      device_paths = self._router.send_and_get_reply(new_method_call(nm, 'GetDevices')).body[0]
      for device_path in device_paths:
        dev_addr = DBusAddress(device_path, bus_name=NM, interface=NM_DEVICE_IFACE)
        dev_type = self._router.send_and_get_reply(Properties(dev_addr).get('DeviceType')).body[0][1]
        if dev_type == NM_DEVICE_TYPE_MODEM:
          self._router.send_and_get_reply(new_method_call(nm, 'ActivateConnection', 'ooo',
                                                          (connection_path, str(device_path), "/")))
          return
    except Exception as e:
      cloudlog.exception(f"Error activating modem connection: {e}")

  def close(self):
    if self._router is not None:
      try:
        self._router.close()
        self._router.conn.close()
      except Exception:
        pass
      self._router = None


# ---------------------------------------------------------------------------
# wpa_supplicant.conf generation
# ---------------------------------------------------------------------------

def _sanitize_for_conf(value: str) -> str:
  """Remove characters that could break wpa_supplicant.conf quoting."""
  return value.replace('"', '').replace('\n', '').replace('\r', '').replace('\\', '')


def _generate_wpa_conf(store: NetworkStore, path: str = WPA_SUPPLICANT_CONF):
  """Write wpa_supplicant.conf from NetworkStore (STA networks only)."""
  lines = [
    "ctrl_interface=/var/run/wpa_supplicant",
    "update_config=0",
    "p2p_disabled=1",
    "",
  ]

  for ssid, entry in store.get_all().items():
    psk = entry.get("psk", "")
    hidden = entry.get("hidden", False)
    safe_ssid = _sanitize_for_conf(ssid)
    safe_psk = _sanitize_for_conf(psk)
    if not safe_ssid:
      continue
    lines.append("network={")
    lines.append(f'  ssid="{safe_ssid}"')
    if safe_psk:
      lines.append(f'  psk="{safe_psk}"')
      lines.append("  key_mgmt=WPA-PSK")
    else:
      lines.append("  key_mgmt=NONE")
    if hidden:
      lines.append("  scan_ssid=1")
    lines.append("}")
    lines.append("")

  tmp = path + ".tmp"
  with open(tmp, "w") as f:
    f.write("\n".join(lines))
  os.replace(tmp, path)


# ---------------------------------------------------------------------------
# WifiManager
# ---------------------------------------------------------------------------

class WifiManager:
  def __init__(self):
    self._networks: list[Network] = []
    self._active = True
    self._exit = False

    self._store = NetworkStore()
    self._ctrl: WpaCtrl | None = None
    self._dhcp = DhcpClient()
    self._gsm = _GsmManager()

    # State
    self._wifi_state: WifiState = WifiState()
    self._user_epoch: int = 0
    self._ipv4_address: str = ""
    self._current_network_metered: MeteredType = MeteredType.UNKNOWN
    self._tethering_password: str = ""
    self._ipv4_forward = False
    self._tethering_active = False

    self._last_network_scan: float = 0.0
    self._callback_queue: list[Callable] = []

    self._tethering_ssid = "weedle"
    if Params is not None:
      dongle_id = Params().get("DongleId")
      if dongle_id:
        self._tethering_ssid += "-" + dongle_id[:4]

    # Callbacks
    self._need_auth: list[Callable[[str], None]] = []
    self._activated: list[Callable[[], None]] = []
    self._forgotten: list[Callable[[str | None], None]] = []
    self._networks_updated: list[Callable[[list[Network]], None]] = []
    self._disconnected: list[Callable[[], None]] = []

    self._scan_lock = threading.Lock()
    self._scan_thread = threading.Thread(target=self._network_scanner, daemon=True)
    self._state_thread = threading.Thread(target=self._monitor_state, daemon=True)
    self._initialize()
    atexit.register(self.stop)

  def _initialize(self):
    def worker():
      self._migrate_nm_connections()

      # Ensure conf exists
      if not os.path.exists(WPA_SUPPLICANT_CONF):
        _generate_wpa_conf(self._store)

      # Ensure tethering password is stored
      if not self._store.contains(self._tethering_ssid):
        self._store.save_network(self._tethering_ssid, psk=DEFAULT_TETHERING_PASSWORD)

      self._tethering_password = self._store.get_psk(self._tethering_ssid)

      self._wait_for_wpa_supplicant()

      self._init_wifi_state()

      self._scan_thread.start()
      self._state_thread.start()

      cloudlog.debug("WifiManager initialized")

    threading.Thread(target=worker, daemon=True).start()

  def _wait_for_wpa_supplicant(self):
    """Wait until wpa_supplicant control socket is available."""
    while not self._exit:
      try:
        ctrl = WpaCtrl()
        ctrl.open()
        self._ctrl = ctrl
        return
      except (OSError, ConnectionRefusedError):
        time.sleep(1)

  def _migrate_nm_connections(self):
    """One-time migration from NM .nmconnection files to NetworkStore."""
    if os.path.exists(WIFI_MIGRATED_FLAG):
      return
    if not os.path.isdir(NM_CONNECTIONS_DIR):
      # No NM connections to migrate
      Path(WIFI_MIGRATED_FLAG).touch()
      return

    try:
      import configparser
      for fname in os.listdir(NM_CONNECTIONS_DIR):
        if not fname.endswith(".nmconnection"):
          continue
        fpath = os.path.join(NM_CONNECTIONS_DIR, fname)
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(fpath)

        if not cp.has_section("wifi"):
          continue

        ssid = cp.get("wifi", "ssid", fallback="")
        mode = cp.get("wifi", "mode", fallback="infrastructure")
        if not ssid or mode == "ap":
          continue

        psk = ""
        if cp.has_section("wifi-security"):
          psk = cp.get("wifi-security", "psk", fallback="")

        metered = 0
        if cp.has_section("connection"):
          metered = cp.getint("connection", "metered", fallback=0)

        hidden = False
        if cp.has_option("wifi", "hidden"):
          hidden = cp.getboolean("wifi", "hidden", fallback=False)

        if not self._store.contains(ssid):
          self._store.save_network(ssid, psk=psk, metered=metered, hidden=hidden)
          cloudlog.info(f"Migrated NM connection: {ssid}")

      _generate_wpa_conf(self._store)
    except Exception:
      cloudlog.exception("Failed to migrate NM connections")

    Path(WIFI_MIGRATED_FLAG).touch()

  def _init_wifi_state(self, block: bool = True):
    def worker():
      if self._ctrl is None:
        return

      epoch = self._user_epoch

      try:
        status = parse_status(self._ctrl.request("STATUS"))
      except Exception:
        cloudlog.exception("Failed to get wpa_supplicant status")
        return

      wpa_state = status.get("wpa_state", "")
      ssid = status.get("ssid")

      if wpa_state == "COMPLETED":
        new_status = ConnectStatus.CONNECTED
      elif wpa_state in ("ASSOCIATING", "ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE"):
        new_status = ConnectStatus.CONNECTING
      else:
        new_status = ConnectStatus.DISCONNECTED
        ssid = None

      if self._user_epoch != epoch:
        return

      self._wifi_state = WifiState(ssid=ssid, status=new_status)

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def add_callbacks(self, need_auth: Callable[[str], None] | None = None,
                    activated: Callable[[], None] | None = None,
                    forgotten: Callable[[str], None] | None = None,
                    networks_updated: Callable[[list[Network]], None] | None = None,
                    disconnected: Callable[[], None] | None = None):
    if need_auth is not None:
      self._need_auth.append(need_auth)
    if activated is not None:
      self._activated.append(activated)
    if forgotten is not None:
      self._forgotten.append(forgotten)
    if networks_updated is not None:
      self._networks_updated.append(networks_updated)
    if disconnected is not None:
      self._disconnected.append(disconnected)

  @property
  def networks(self) -> list[Network]:
    return sorted(self._networks, key=lambda n: (n.ssid != self._wifi_state.ssid, not self.is_connection_saved(n.ssid), -n.strength, n.ssid.lower()))

  @property
  def wifi_state(self) -> WifiState:
    return self._wifi_state

  @property
  def ipv4_address(self) -> str:
    return self._ipv4_address

  @property
  def current_network_metered(self) -> MeteredType:
    return self._current_network_metered

  @property
  def connecting_to_ssid(self) -> str | None:
    wifi_state = self._wifi_state
    return wifi_state.ssid if wifi_state.status == ConnectStatus.CONNECTING else None

  @property
  def connected_ssid(self) -> str | None:
    wifi_state = self._wifi_state
    return wifi_state.ssid if wifi_state.status == ConnectStatus.CONNECTED else None

  @property
  def tethering_password(self) -> str:
    return self._tethering_password

  def _set_connecting(self, ssid: str | None):
    self._user_epoch += 1
    self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.DISCONNECTED if ssid is None else ConnectStatus.CONNECTING)

  def _enqueue_callbacks(self, cbs: list[Callable], *args):
    for cb in cbs:
      self._callback_queue.append(lambda _cb=cb: _cb(*args))

  def process_callbacks(self):
    to_run, self._callback_queue = self._callback_queue, []
    for cb in to_run:
      cb()

  def set_active(self, active: bool):
    self._active = active
    if active:
      self._init_wifi_state(block=False)
      self._update_networks(block=False)

  # ---------------------------------------------------------------------------
  # Monitor thread: wpa_supplicant events
  # ---------------------------------------------------------------------------

  def _monitor_state(self):
    while not self._exit:
      monitor = None
      try:
        monitor = WpaCtrlMonitor()
        monitor.open()
        while not self._exit:
          event = monitor.recv(timeout=1.0)
          if event is None:
            continue
          self._handle_event(event)
      except Exception:
        cloudlog.exception("wpa_supplicant monitor error, reconnecting...")
        if monitor is not None:
          try:
            monitor.close()
          except Exception:
            pass
        time.sleep(2)

  def _handle_event(self, event: str):
    """Dispatch wpa_supplicant event to state machine."""
    if DEBUG:
      cloudlog.debug(f"[WPA EVENT] {event}")

    if "CTRL-EVENT-SCAN-RESULTS" in event:
      self._update_networks()

    elif "CTRL-EVENT-CONNECTED" in event:
      # Extract SSID from "Connection to xx:xx:xx:xx:xx:xx completed [id=N id_str=]"
      epoch = self._user_epoch
      ssid = self._wifi_state.ssid

      # Get actual SSID from STATUS
      if self._ctrl:
        try:
          status = parse_status(self._ctrl.request("STATUS"))
          ssid = status.get("ssid", ssid)
        except Exception:
          pass

      if self._user_epoch != epoch:
        return

      self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTED)
      self._dhcp.start()
      self._enqueue_callbacks(self._activated)
      self._update_active_connection_info()

    elif "CTRL-EVENT-DISCONNECTED" in event:
      if self._tethering_active:
        return  # Ignore disconnects during tethering transitions

      # Don't clear state if we're connecting to something (user action in progress)
      if self._wifi_state.status == ConnectStatus.CONNECTING:
        return

      self._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
      self._dhcp.stop()
      self._ipv4_address = ""
      self._current_network_metered = MeteredType.UNKNOWN
      self._enqueue_callbacks(self._disconnected)

    elif "TEMP-DISABLED" in event and "reason=WRONG_KEY" in event:
      if self._wifi_state.ssid:
        self._enqueue_callbacks(self._need_auth, self._wifi_state.ssid)
        self._set_connecting(None)

    elif "CTRL-EVENT-ASSOC-REJECT" in event or "CTRL-EVENT-AUTH-REJECT" in event:
      # Could be wrong password or AP rejected
      pass

    elif "Trying to associate with" in event or "Associated with" in event:
      # Auto-connect case: wpa_supplicant is connecting on its own
      if self._wifi_state.status == ConnectStatus.DISCONNECTED:
        epoch = self._user_epoch
        ssid = None
        if self._ctrl:
          try:
            status = parse_status(self._ctrl.request("STATUS"))
            ssid = status.get("ssid")
          except Exception:
            pass
        if self._user_epoch != epoch:
          return
        self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)

  # ---------------------------------------------------------------------------
  # Scanner thread
  # ---------------------------------------------------------------------------

  def _network_scanner(self):
    while not self._exit:
      if self._active and not self._tethering_active:
        if time.monotonic() - self._last_network_scan > SCAN_PERIOD_SECONDS:
          self._request_scan()
          self._last_network_scan = time.monotonic()
      time.sleep(1 / 2.)

  def _request_scan(self):
    if self._ctrl is None:
      return
    try:
      self._ctrl.request("SCAN")
    except Exception:
      cloudlog.exception("Failed to request scan")

  def _update_networks(self, block: bool = True):
    if not self._active:
      return

    def worker():
      with self._scan_lock:
        if self._ctrl is None:
          return

        try:
          raw = self._ctrl.request("SCAN_RESULTS")
        except Exception:
          cloudlog.exception("Failed to get scan results")
          return

        results = parse_scan_results(raw)

        # Group by SSID, keep strongest signal
        ssid_map: dict[str, list] = {}
        for r in results:
          if not r.ssid:
            continue
          if r.ssid not in ssid_map:
            ssid_map[r.ssid] = []
          ssid_map[r.ssid].append(r)

        networks = []
        for ssid, aps in ssid_map.items():
          strongest = max(aps, key=lambda a: a.signal)
          security = flags_to_security_type(strongest.flags)
          is_tethering = ssid == self._tethering_ssid
          strength = 100 if is_tethering else dbm_to_percent(strongest.signal)
          networks.append(Network(ssid=ssid, strength=strength, security_type=security, is_tethering=is_tethering))

        self._networks = networks
        self._update_active_connection_info()
        self._enqueue_callbacks(self._networks_updated, self.networks)

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def _update_active_connection_info(self):
    ipv4_address = ""
    metered = MeteredType.UNKNOWN

    if self._wifi_state.status == ConnectStatus.CONNECTED:
      # Try wpa_cli STATUS for ip_address first (works regardless of network namespace)
      if self._ctrl:
        try:
          status = parse_status(self._ctrl.request("STATUS"))
          ipv4_address = status.get("ip_address", "")
        except Exception:
          pass

      # Fallback to ip command
      if not ipv4_address:
        try:
          result = subprocess.run(["ip", "-4", "-o", "addr", "show", "wlan0"],
                                  capture_output=True, text=True, timeout=2)
          for line in result.stdout.strip().split("\n"):
            if "inet " in line:
              parts = line.split()
              inet_idx = parts.index("inet")
              ipv4_address = parts[inet_idx + 1].split("/")[0]
              break
        except Exception:
          pass

      # Metered from store
      ssid = self._wifi_state.ssid
      if ssid:
        metered = self._store.get_metered(ssid)

    self._ipv4_address = ipv4_address
    self._current_network_metered = metered

  # ---------------------------------------------------------------------------
  # Connection management
  # ---------------------------------------------------------------------------

  def connect_to_network(self, ssid: str, password: str, hidden: bool = False):
    self._set_connecting(ssid)

    def worker():
      # Save to persistent store and regenerate conf (for next boot)
      self._store.save_network(ssid, psk=password, hidden=hidden)
      _generate_wpa_conf(self._store)

      if self._ctrl is None:
        cloudlog.warning("No wpa_supplicant connection")
        self._init_wifi_state()
        return

      try:
        # Remove any existing network entry for this SSID
        self._remove_wpa_network(ssid)

        # Add network via wpa_supplicant control commands (works even if NM started wpa_supplicant)
        net_id = self._ctrl.request("ADD_NETWORK").strip()
        safe_ssid = _sanitize_for_conf(ssid)
        safe_psk = _sanitize_for_conf(password)
        self._ctrl.request(f'SET_NETWORK {net_id} ssid "{safe_ssid}"')
        if safe_psk:
          self._ctrl.request(f'SET_NETWORK {net_id} psk "{safe_psk}"')
        else:
          self._ctrl.request(f"SET_NETWORK {net_id} key_mgmt NONE")
        if hidden:
          self._ctrl.request(f"SET_NETWORK {net_id} scan_ssid 1")

        self._ctrl.request(f"SELECT_NETWORK {net_id}")
      except Exception:
        cloudlog.exception(f"Failed to connect to {ssid}")
        self._init_wifi_state()

    threading.Thread(target=worker, daemon=True).start()

  def forget_connection(self, ssid: str, block: bool = False):
    def worker():
      was_connected = self._wifi_state.ssid == ssid and self._wifi_state.status == ConnectStatus.CONNECTED

      removed = self._store.remove(ssid)
      if not removed:
        cloudlog.warning(f"Trying to forget unknown connection: {ssid}")

      _generate_wpa_conf(self._store)

      if self._ctrl:
        try:
          if was_connected:
            self._ctrl.request("DISCONNECT")
          self._remove_wpa_network(ssid)
          self._ctrl.request("ENABLE_NETWORK all")
          if not was_connected:
            self._ctrl.request("REASSOCIATE")
        except Exception:
          cloudlog.exception(f"Failed to reconfigure after forgetting {ssid}")

      self._enqueue_callbacks(self._forgotten, ssid)

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def activate_connection(self, ssid: str, block: bool = False):
    self._set_connecting(ssid)

    def worker():
      if self._ctrl is None:
        cloudlog.warning(f"No wpa_supplicant connection for activate {ssid}")
        self._init_wifi_state()
        return

      try:
        net_id = self._find_network_id(ssid)
        if net_id is not None:
          self._ctrl.request(f"SELECT_NETWORK {net_id}")
        else:
          # Network not in wpa_supplicant's runtime list — add from store
          entry = self._store.get(ssid)
          if entry:
            net_id = self._ctrl.request("ADD_NETWORK").strip()
            safe_ssid = _sanitize_for_conf(ssid)
            self._ctrl.request(f'SET_NETWORK {net_id} ssid "{safe_ssid}"')
            psk = entry.get("psk", "")
            safe_psk = _sanitize_for_conf(psk)
            if safe_psk:
              self._ctrl.request(f'SET_NETWORK {net_id} psk "{safe_psk}"')
            else:
              self._ctrl.request(f"SET_NETWORK {net_id} key_mgmt NONE")
            if entry.get("hidden"):
              self._ctrl.request(f"SET_NETWORK {net_id} scan_ssid 1")
            self._ctrl.request(f"SELECT_NETWORK {net_id}")
          else:
            cloudlog.warning(f"Network {ssid} not found for activation")
            self._init_wifi_state()
      except Exception:
        cloudlog.exception(f"Failed to activate {ssid}")
        self._init_wifi_state()

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def _find_network_id(self, ssid: str) -> str | None:
    """Find wpa_supplicant network id for given SSID via LIST_NETWORKS."""
    if self._ctrl is None:
      return None
    try:
      raw = self._ctrl.request("LIST_NETWORKS")
      for line in raw.strip().split("\n")[1:]:  # skip header
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1] == ssid:
          return parts[0]
    except Exception:
      cloudlog.exception("Failed to list networks")
    return None

  def _remove_wpa_network(self, ssid: str):
    """Remove all wpa_supplicant network entries matching SSID."""
    if self._ctrl is None:
      return
    try:
      raw = self._ctrl.request("LIST_NETWORKS")
      for line in raw.strip().split("\n")[1:]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1] == ssid:
          self._ctrl.request(f"REMOVE_NETWORK {parts[0]}")
    except Exception:
      cloudlog.exception(f"Failed to remove network {ssid}")

  def is_tethering_active(self) -> bool:
    return self._tethering_active

  def is_connection_saved(self, ssid: str) -> bool:
    return self._store.contains(ssid)

  def set_tethering_password(self, password: str):
    def worker():
      self._store.save_network(self._tethering_ssid, psk=password)
      self._tethering_password = password
      if self._tethering_active:
        # Restart tethering with new password
        self._stop_tethering()
        self._start_tethering()
    threading.Thread(target=worker, daemon=True).start()

  def set_ipv4_forward(self, enabled: bool):
    self._ipv4_forward = enabled

  def set_tethering_active(self, active: bool):
    def worker():
      if active:
        self._start_tethering()
        if not self._ipv4_forward:
          time.sleep(5)
          cloudlog.warning("net.ipv4.ip_forward = 0")
          subprocess.run(["sudo", "sysctl", "net.ipv4.ip_forward=0"], check=False)
      else:
        self._stop_tethering()
    threading.Thread(target=worker, daemon=True).start()

  def _start_tethering(self):
    self._set_connecting(self._tethering_ssid)
    self._tethering_active = True

    psk = self._store.get_psk(self._tethering_ssid)
    if not psk:
      psk = DEFAULT_TETHERING_PASSWORD

    # Close existing control socket
    if self._ctrl:
      self._ctrl.close()
      self._ctrl = None

    # Stop STA wpa_supplicant
    subprocess.run(["sudo", "killall", "-q", "wpa_supplicant"], check=False)
    self._dhcp.stop()
    time.sleep(0.5)

    # Write AP config
    safe_tether_ssid = _sanitize_for_conf(self._tethering_ssid)
    safe_tether_psk = _sanitize_for_conf(psk)
    lines = ["ctrl_interface=/var/run/wpa_supplicant", "ap_scan=2", "",
             "network={", f'  ssid="{safe_tether_ssid}"', "  mode=2",
             "  frequency=2437", "  key_mgmt=WPA-PSK", f'  psk="{safe_tether_psk}"', "}", ""]
    ap_conf = "\n".join(lines)
    with open(WPA_AP_CONF, "w") as f:
      f.write(ap_conf)

    # Start AP wpa_supplicant
    subprocess.run(["sudo", "wpa_supplicant", "-B", "-i", "wlan0", "-c", WPA_AP_CONF, "-D", "nl80211"], check=False)
    time.sleep(1)

    # Configure AP interface
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=False)
    subprocess.run(["sudo", "ip", "addr", "add", f"{TETHERING_IP_ADDRESS}/24", "dev", "wlan0"], check=False)
    subprocess.run(["sudo", "ip", "link", "set", "wlan0", "up"], check=False)

    # Start dnsmasq for DHCP
    subprocess.run(["sudo", "killall", "-q", "dnsmasq"], check=False)
    subprocess.run([
      "sudo", "dnsmasq",
      "--interface=wlan0",
      "--bind-interfaces",
      "--dhcp-range=192.168.43.2,192.168.43.254,24h",
      "--no-daemon", "--log-queries",
    ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
      start_new_session=True)

    # NAT
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wwan0", "-j", "MASQUERADE"], check=False)
    if self._ipv4_forward:
      subprocess.run(["sudo", "sysctl", "net.ipv4.ip_forward=1"], check=False)

    # Reconnect control socket
    try:
      ctrl = WpaCtrl()
      ctrl.open()
      self._ctrl = ctrl
    except Exception:
      cloudlog.exception("Failed to reconnect wpa_ctrl after tethering start")

    self._wifi_state = WifiState(ssid=self._tethering_ssid, status=ConnectStatus.CONNECTED)
    self._ipv4_address = TETHERING_IP_ADDRESS
    self._enqueue_callbacks(self._activated)

  def _stop_tethering(self):
    # Kill dnsmasq
    subprocess.run(["sudo", "killall", "-q", "dnsmasq"], check=False)

    # Remove NAT
    subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "wwan0", "-j", "MASQUERADE"], check=False)

    # Close control socket
    if self._ctrl:
      self._ctrl.close()
      self._ctrl = None

    # Stop AP wpa_supplicant
    subprocess.run(["sudo", "killall", "-q", "wpa_supplicant"], check=False)
    time.sleep(0.5)

    # Flush AP IP
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=False)

    # Restart STA wpa_supplicant
    _generate_wpa_conf(self._store)
    subprocess.run(["sudo", "wpa_supplicant", "-B", "-i", "wlan0", "-c", WPA_SUPPLICANT_CONF, "-D", "nl80211"], check=False)
    time.sleep(1)

    # Reconnect control socket
    try:
      ctrl = WpaCtrl()
      ctrl.open()
      self._ctrl = ctrl
      # Re-enable all networks
      self._ctrl.request("ENABLE_NETWORK all")
    except Exception:
      cloudlog.exception("Failed to reconnect wpa_ctrl after tethering stop")

    self._tethering_active = False
    self._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
    self._ipv4_address = ""
    self._enqueue_callbacks(self._disconnected)

  def set_current_network_metered(self, metered: MeteredType):
    def worker():
      if self._tethering_active:
        return
      ssid = self._wifi_state.ssid
      if ssid:
        self._store.set_metered(ssid, int(metered))
        self._current_network_metered = metered
    threading.Thread(target=worker, daemon=True).start()

  def update_gsm_settings(self, roaming: bool, apn: str, metered: bool):
    def worker():
      self._gsm.update_gsm_settings(roaming, apn, metered)
    threading.Thread(target=worker, daemon=True).start()

  def __del__(self):
    self.stop()

  def stop(self):
    if not self._exit:
      self._exit = True
      if self._scan_thread.is_alive():
        self._scan_thread.join()
      if self._state_thread.is_alive():
        self._state_thread.join()
      if self._ctrl is not None:
        self._ctrl.close()
      self._dhcp.stop()
      self._gsm.close()
