import queue
import threading
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.dhcp_client import DhcpClient
from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkProfile, NetworkStore
from openpilot.system.ui.lib.wpa_ctrl import (SecurityType, WpaCtrl, WpaCtrlMonitor, dbm_to_percent,
                                               flags_to_security_type, is_valid_ssid, parse_event_network_id,
                                               parse_event_ssid, parse_scan_results, parse_status)
from openpilot.system.ui.lib import wpa_supplicant


SCAN_PERIOD_SECONDS = 5.0
RECONCILE_PERIOD_SECONDS = 0.5
CONNECT_TIMEOUT_SECONDS = 20.0


class ConnectStatus(IntEnum):
  DISCONNECTED = 0
  CONNECTING = 1
  CONNECTED = 2


@dataclass(frozen=True)
class WifiState:
  ssid: str | None = None
  status: ConnectStatus = ConnectStatus.DISCONNECTED
  profile_uuid: str | None = None
  ipv4_address: str = ""
  metered: MeteredType = MeteredType.UNKNOWN


@dataclass(frozen=True)
class Network:
  ssid: str
  strength: int
  security_type: SecurityType


@dataclass(frozen=True)
class _Connect:
  ssid: str
  password: str
  hidden: bool
  security: SecurityType


@dataclass(frozen=True)
class _Activate:
  ssid: str


@dataclass(frozen=True)
class _SetActive:
  active: bool


class _Stop:
  pass


class WifiController:
  def __init__(self, store: NetworkStore | None = None, dhcp: DhcpClient | None = None, start: bool = True):
    self._store = store or NetworkStore()
    self._dhcp = dhcp or DhcpClient()
    self._commands: queue.Queue[object] = queue.Queue()
    self._callbacks: queue.Queue[tuple[str, object | None]] = queue.Queue()
    self._state = WifiState()
    self._networks: tuple[Network, ...] = ()
    self._active = False
    self._ctrl: WpaCtrl | None = None
    self._monitor: WpaCtrlMonitor | None = None
    self._runtime_profiles: dict[str, str] = {}
    self._pending_profile: NetworkProfile | None = None
    self._requested_ssid: str | None = None
    self._connecting_since = 0.0
    self._last_scan = 0.0
    self._last_reconcile = 0.0
    self._owner_ident: int | None = None
    self._thread: threading.Thread | None = None
    self._exit = False
    if start:
      self.start()

  @property
  def state(self) -> WifiState:
    return self._state

  @property
  def networks(self) -> tuple[Network, ...]:
    saved = {profile.ssid for profile in self._store.profiles()}
    return tuple(sorted(self._networks, key=lambda network: (
      network.ssid != self._state.ssid,
      network.ssid not in saved,
      -network.strength,
      network.ssid.lower(),
    )))

  def is_connection_saved(self, ssid: str) -> bool:
    return bool(self._store.profiles_for_ssid(ssid))

  def start(self):
    if self._thread is not None:
      return
    self._thread = threading.Thread(target=self._run, daemon=True)
    self._thread.start()

  def stop(self):
    if self._thread is None:
      return
    self._commands.put(_Stop())
    self._thread.join(timeout=5)
    self._thread = None

  def set_active(self, active: bool):
    self._commands.put(_SetActive(active))

  def connect(self, ssid: str, password: str, hidden: bool = False, security: SecurityType = SecurityType.WPA):
    self._commands.put(_Connect(ssid, password, hidden, security))

  def activate(self, ssid: str):
    self._commands.put(_Activate(ssid))

  def get_callback(self) -> tuple[str, object | None] | None:
    try:
      return self._callbacks.get_nowait()
    except queue.Empty:
      return None

  def _assert_owner(self):
    assert threading.get_ident() == self._owner_ident

  def _request(self, command: str) -> str:
    self._assert_owner()
    if self._ctrl is None:
      raise OSError("wpa_supplicant control unavailable")
    response = self._ctrl.request(command)
    if response.startswith("FAIL"):
      raise RuntimeError(f"wpa_supplicant rejected {command.split(' ', 1)[0]}")
    return response

  def _run(self):
    self._owner_ident = threading.get_ident()
    try:
      self._initialize_station()
      while not self._exit:
        self._drain_commands()
        if self._exit:
          break

        if self._monitor is not None:
          event = self._monitor.recv(timeout=0.05)
          if event is not None:
            self._handle_wpa_event(event)

        now = time.monotonic()
        if self._active and now - self._last_scan >= SCAN_PERIOD_SECONDS:
          self._scan()
          self._last_scan = now
        if now - self._last_reconcile >= RECONCILE_PERIOD_SECONDS:
          self._reconcile()
          self._last_reconcile = now
    except Exception:
      cloudlog.exception("Wi-Fi controller failed")
    finally:
      if self._monitor is not None:
        self._monitor.close()
      if self._ctrl is not None:
        self._ctrl.close()
      self._owner_ident = None

  def _drain_commands(self):
    self._assert_owner()
    while True:
      try:
        command = self._commands.get_nowait()
      except queue.Empty:
        return

      if isinstance(command, _Stop):
        self._exit = True
        return
      if isinstance(command, _SetActive):
        self._active = command.active
        if command.active:
          self._scan()
          self._last_scan = time.monotonic()
      elif isinstance(command, _Connect):
        self._connect(command)
      elif isinstance(command, _Activate):
        self._activate(command.ssid)

  def _initialize_station(self):
    self._assert_owner()
    wpa_supplicant.write_station_config([profile.as_wpa_network() for profile in self._store.profiles()])
    if not wpa_supplicant.start(wpa_supplicant.WPA_SUPPLICANT_CONF):
      raise RuntimeError("failed to start station wpa_supplicant")

    self._ctrl = WpaCtrl()
    self._ctrl.open()
    self._monitor = WpaCtrlMonitor()
    self._monitor.open()
    self._sync_runtime_profiles()
    self._adopt_status(parse_status(self._request("STATUS")))

  def _sync_runtime_profiles(self):
    self._assert_owner()
    runtime_profiles: dict[str, str] = {}
    raw = self._request("LIST_NETWORKS")
    for line in raw.splitlines()[1:]:
      fields = line.split("\t")
      if not fields or not fields[0].isdigit():
        continue
      network_id = fields[0]
      try:
        profile_uuid = self._request(f"GET_NETWORK {network_id} id_str").strip().strip('"')
      except RuntimeError:
        continue
      if self._store.get(profile_uuid) is not None:
        runtime_profiles[profile_uuid] = network_id
    self._runtime_profiles = runtime_profiles

  def _scan(self):
    self._assert_owner()
    try:
      self._request("SCAN")
      results = parse_scan_results(self._request("SCAN_RESULTS"))
    except (OSError, RuntimeError):
      return

    grouped: dict[str, list] = {}
    for result in results:
      if result.ssid:
        grouped.setdefault(result.ssid, []).append(result)

    networks = []
    for ssid, aps in grouped.items():
      security_types = {flags_to_security_type(ap.flags) for ap in aps}
      security = security_types.pop() if len(security_types) == 1 else SecurityType.UNSUPPORTED
      networks.append(Network(ssid, max(dbm_to_percent(ap.signal) for ap in aps), security))
    self._networks = tuple(networks)
    self._callbacks.put(("networks_updated", None))

  @staticmethod
  def _psk_value(password: str) -> str:
    if len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password):
      return password
    return '"' + password.replace("\\", "\\\\").replace('"', '\\"') + '"'

  def _connect(self, command: _Connect):
    self._assert_owner()
    if not is_valid_ssid(command.ssid):
      self._callbacks.put(("need_auth", command.ssid))
      return
    if command.security == SecurityType.WPA:
      try:
        password_size = len(command.password.encode("utf-8"))
      except UnicodeEncodeError:
        password_size = 0
      raw_psk = len(command.password) == 64 and all(char in "0123456789abcdefABCDEF" for char in command.password)
      if not raw_psk and not 8 <= password_size <= 63:
        self._callbacks.put(("need_auth", command.ssid))
        return

    self._begin_selection(command.ssid)
    profile = NetworkProfile(
      uuid=str(uuid.uuid4()),
      ssid=command.ssid,
      security=command.security,
      psk=command.password if command.security == SecurityType.WPA else "",
      hidden=command.hidden,
      ipv6_enabled=False,
    )

    try:
      network_id = self._request("ADD_NETWORK").strip()
      if not network_id.isdigit():
        raise RuntimeError("invalid network id")
      self._request(f"SET_NETWORK {network_id} ssid {command.ssid.encode('utf-8', errors='surrogateescape').hex()}")
      self._request(f"SET_NETWORK {network_id} id_str \"{profile.uuid}\"")
      if command.security == SecurityType.WPA:
        self._request(f"SET_NETWORK {network_id} psk {self._psk_value(command.password)}")
        self._request(f"SET_NETWORK {network_id} key_mgmt WPA-PSK")
      else:
        self._request(f"SET_NETWORK {network_id} key_mgmt NONE")
      if command.hidden:
        self._request(f"SET_NETWORK {network_id} scan_ssid 1")
      self._request("DISABLE_NETWORK all")
      self._request(f"ENABLE_NETWORK {network_id}")
      self._request(f"SELECT_NETWORK {network_id}")
    except (OSError, RuntimeError):
      self._cancel_selection()
      return

    self._pending_profile = profile
    self._runtime_profiles[profile.uuid] = network_id

  def _activate(self, ssid: str):
    self._assert_owner()
    profiles = self._store.profiles_for_ssid(ssid)
    runtime_ids = [self._runtime_profiles[profile.uuid] for profile in profiles if profile.uuid in self._runtime_profiles]
    if not runtime_ids:
      return

    self._begin_selection(ssid)
    try:
      self._request("DISABLE_NETWORK all")
      for network_id in runtime_ids:
        self._request(f"ENABLE_NETWORK {network_id}")
      self._request("REASSOCIATE")
    except (OSError, RuntimeError):
      self._cancel_selection()

  def _begin_selection(self, ssid: str):
    self._assert_owner()
    self._dhcp.stop()
    self._dhcp.clear_ipv6()
    self._requested_ssid = ssid
    self._connecting_since = time.monotonic()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)

  def _cancel_selection(self):
    self._assert_owner()
    self._pending_profile = None
    self._requested_ssid = None
    self._connecting_since = 0.0
    try:
      self._request("ENABLE_NETWORK all")
    except (OSError, RuntimeError):
      pass
    self._dhcp.stop()
    self._dhcp.clear_ipv6()
    self._state = WifiState()
    self._callbacks.put(("disconnected", None))

  def _handle_wpa_event(self, event: str):
    self._assert_owner()
    if event.startswith("CTRL-EVENT-CONNECTED"):
      try:
        status = parse_status(self._request("STATUS"))
      except (OSError, RuntimeError):
        return
      if status.get("wpa_state") == "COMPLETED":
        self._adopt_status(status)
      return

    if "WRONG_KEY" in event or "reason=WRONG_KEY" in event:
      failed_id = parse_event_network_id(event)
      failed_ssid = parse_event_ssid(event)
      pending_id = self._runtime_profiles.get(self._pending_profile.uuid) if self._pending_profile is not None else None
      if self._requested_ssid is not None and (failed_ssid in (None, self._requested_ssid)) and (failed_id is None or failed_id == pending_id):
        ssid = self._requested_ssid
        self._cancel_selection()
        self._callbacks.put(("need_auth", ssid))

  def _adopt_status(self, status: dict[str, str]):
    self._assert_owner()
    if status.get("wpa_state") != "COMPLETED":
      return

    ssid = status.get("ssid")
    profile_uuid = status.get("id_str", "").strip('"')
    if not ssid or not profile_uuid:
      return
    if self._requested_ssid is not None and ssid != self._requested_ssid:
      return

    if self._pending_profile is not None and profile_uuid == self._pending_profile.uuid:
      try:
        stored = self._store.write(self._pending_profile)
        self._pending_profile = None
        wpa_supplicant.write_station_config([profile.as_wpa_network() for profile in self._store.profiles()])
        profile_uuid = stored.uuid
      except OSError:
        return

    profile = self._store.get(profile_uuid)
    if profile is None:
      return

    self._requested_ssid = None
    self._connecting_since = time.monotonic()
    if not profile.ipv6_enabled:
      self._dhcp.clear_ipv6()
    if not self._dhcp.running:
      self._dhcp.start()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING, profile_uuid=profile_uuid, metered=profile.metered)
    try:
      self._request("ENABLE_NETWORK all")
    except (OSError, RuntimeError):
      pass

  def _reconcile(self):
    self._assert_owner()
    try:
      status = parse_status(self._request("STATUS"))
    except (OSError, RuntimeError):
      return

    if status.get("wpa_state") == "COMPLETED":
      ssid = status.get("ssid")
      profile_uuid = status.get("id_str", "").strip('"')
      if self._state.profile_uuid != profile_uuid or self._state.ssid != ssid:
        self._adopt_status(status)

      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTING:
        if not self._dhcp.running:
          self._dhcp.start()
        if self._dhcp.ready():
          profile = self._store.get(profile_uuid)
          self._state = WifiState(
            ssid=ssid,
            status=ConnectStatus.CONNECTED,
            profile_uuid=profile_uuid,
            ipv4_address=self._dhcp.ipv4_address(),
            metered=profile.metered if profile is not None else MeteredType.UNKNOWN,
          )
          self._connecting_since = 0.0
          self._callbacks.put(("activated", None))
      return

    if self._state.status != ConnectStatus.DISCONNECTED and self._connecting_since and time.monotonic() - self._connecting_since >= CONNECT_TIMEOUT_SECONDS:
      self._cancel_selection()
