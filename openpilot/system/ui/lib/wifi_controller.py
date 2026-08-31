import queue
import subprocess
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, replace
from enum import IntEnum

from openpilot.common.swaglog import cloudlog
from openpilot.common.wifi import clear_active_profile, read_active_profile, write_active_profile
from openpilot.system.ui.lib.dhcp_client import DhcpClient
from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkProfile, NetworkStore
from openpilot.system.ui.lib.wifi_tethering_store import TetheringStore
from openpilot.system.ui.lib.wpa_ctrl import (SecurityType, WpaCtrl, WpaCtrlMonitor, dbm_to_percent,
                                               flags_to_security_type, is_valid_ssid, parse_event_network_id,
                                               parse_event_ssid, parse_scan_results, parse_status)
from openpilot.system.ui.lib import wifi_tethering, wpa_supplicant


SCAN_PERIOD_SECONDS = 5.0
RECONCILE_PERIOD_SECONDS = 0.5
CONNECT_TIMEOUT_SECONDS = 20.0
CONTROL_FAILURE_LIMIT = 5
TETHERING_FIREWALL_CHECK_PERIOD_SECONDS = 5.0
DEFAULT_TETHERING_PASSWORD = "swagswagcomma"


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


@dataclass(frozen=True)
class _SetMetered:
  metered: MeteredType


@dataclass(frozen=True)
class _Forget:
  ssid: str


@dataclass(frozen=True)
class _SetTetheringActive:
  active: bool


@dataclass(frozen=True)
class _SetTetheringPassword:
  password: str


@dataclass(frozen=True)
class _SetIpv4Forward:
  enabled: bool


class _Stop:
  pass


class WifiController:
  def __init__(self, store: NetworkStore | None = None, dhcp: DhcpClient | None = None, tethering_store: TetheringStore | None = None,
               tethering_ssid: str = "weedle", tethering_password: str = DEFAULT_TETHERING_PASSWORD, start: bool = True):
    self._store = store or NetworkStore()
    self._dhcp = dhcp or DhcpClient()
    self._tethering_store = tethering_store or TetheringStore()
    self._commands: queue.Queue[object] = queue.Queue()
    self._callbacks: queue.Queue[tuple[str, object | None]] = queue.Queue()
    self._state = WifiState()
    self._networks: tuple[Network, ...] = ()
    self._saved_ssids: frozenset[str] = frozenset()
    self._active = False
    self._ctrl: WpaCtrl | None = None
    self._monitor: WpaCtrlMonitor | None = None
    self._runtime_profiles: dict[str, str] = {}
    self._pending_profile: NetworkProfile | None = None
    self._temporary_network_id: str | None = None
    self._replacement_network_id: str | None = None
    self._requested_ssid: str | None = None
    self._connecting_since = 0.0
    self._last_scan = 0.0
    self._last_reconcile = 0.0
    self._control_failures = 0
    self._tethering = wifi_tethering.TetheringSession()
    self._tethering_ssid = tethering_ssid
    self._tethering_password = tethering_password
    self._tethering_password_rollback: str | None = None
    self._tethering_active = False
    self._last_tethering_firewall_check = 0.0
    self._ipv4_forward = False
    self._published_active_profile: tuple[str, int] | None = None
    self._ownership_touched = False
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
    return tuple(sorted(self._networks, key=lambda network: (
      network.ssid != self._state.ssid,
      network.ssid not in self._saved_ssids,
      -network.strength,
      network.ssid.lower(),
    )))

  @property
  def tethering_active(self) -> bool:
    return self._tethering_active

  @property
  def tethering_password(self) -> str:
    return self._tethering_password

  def is_connection_saved(self, ssid: str) -> bool:
    return ssid in self._saved_ssids

  def start(self):
    if self._thread is not None:
      return
    self._exit = False
    self._thread = threading.Thread(target=self._run, daemon=True)
    self._thread.start()

  def stop(self):
    if self._thread is None:
      return
    thread = self._thread
    self._commands.put(_Stop())
    thread.join()
    self._thread = None

  def set_active(self, active: bool):
    self._commands.put(_SetActive(active))

  def connect(self, ssid: str, password: str, hidden: bool = False, security: SecurityType = SecurityType.WPA):
    self._commands.put(_Connect(ssid, password, hidden, security))

  def activate(self, ssid: str):
    self._commands.put(_Activate(ssid))

  def set_metered(self, metered: MeteredType):
    self._commands.put(_SetMetered(metered))

  def forget(self, ssid: str):
    self._commands.put(_Forget(ssid))

  def set_tethering_active(self, active: bool):
    self._commands.put(_SetTetheringActive(active))

  def set_tethering_password(self, password: str):
    self._commands.put(_SetTetheringPassword(password))

  def set_ipv4_forward(self, enabled: bool):
    self._commands.put(_SetIpv4Forward(enabled))

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
      self._store.recover()
      self._tethering_store.recover()
      self._refresh_saved_ssids()
      stale_ap_running = wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF)
      self._ownership_touched = True
      if stale_ap_running and not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        raise RuntimeError("failed to stop stale tethering wpa_supplicant")
      if not wifi_tethering.TetheringSession.cleanup_stale():
        raise RuntimeError("failed to clean up stale tethering resources")
      if not stale_ap_running:
        self._ownership_touched = False
      self._initialize_tethering_profile()
      self._initialize_station()
      while not self._exit:
        self._drain_commands()
        if self._exit:
          break

        if self._tethering_active:
          time.sleep(0.05)
        elif self._monitor is not None:
          event = self._monitor.recv(timeout=0.05)
          if event is not None:
            self._handle_wpa_event(event)

        now = time.monotonic()
        if not self._tethering_active and self._active and now - self._last_scan >= SCAN_PERIOD_SECONDS:
          self._scan()
          self._last_scan = now
        if now - self._last_reconcile >= RECONCILE_PERIOD_SECONDS:
          if self._tethering_active:
            self._reconcile_tethering()
          else:
            self._reconcile()
          self._last_reconcile = now
    except Exception:
      cloudlog.exception("Wi-Fi controller failed")
      try:
        if (self._ownership_touched
            or self._tethering_active
            or wpa_supplicant.is_running(wpa_supplicant.WPA_SUPPLICANT_CONF)
            or wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF)):
          self._shutdown()
      except Exception:
        cloudlog.exception("Failed to return Wi-Fi ownership after controller failure")
    finally:
      if not self._ownership_touched:
        clear_active_profile()
      self._close_ctrl()
      self._owner_ident = None

  def _drain_commands(self):
    self._assert_owner()
    while True:
      try:
        command = self._commands.get_nowait()
      except queue.Empty:
        return

      if isinstance(command, _Stop):
        while not self._shutdown():
          time.sleep(RECONCILE_PERIOD_SECONDS)
        self._exit = True
        return
      if isinstance(command, _SetActive):
        self._active = command.active
        if command.active and not self._tethering_active:
          self._scan()
          self._last_scan = time.monotonic()
      elif isinstance(command, _Connect):
        if not self._tethering_active:
          self._connect(command)
      elif isinstance(command, _Activate):
        if not self._tethering_active:
          self._activate(command.ssid)
      elif isinstance(command, _SetMetered):
        if not self._tethering_active:
          self._set_metered(command.metered)
      elif isinstance(command, _Forget):
        if not self._tethering_active:
          self._forget(command.ssid)
      elif isinstance(command, _SetTetheringActive):
        self._set_tethering_active(command.active)
      elif isinstance(command, _SetTetheringPassword):
        self._set_tethering_password(command.password)
      elif isinstance(command, _SetIpv4Forward):
        self._set_ipv4_forward(command.enabled)

  def _shutdown(self) -> bool:
    self._assert_owner()
    self._close_ctrl()
    if self._tethering_active or wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF):
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        cloudlog.error("Failed to stop tethering wpa_supplicant during shutdown")
        return False
      if not self._tethering.stop():
        wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF)
        cloudlog.error("Failed to stop tethering services during shutdown")
        return False
      self._tethering_active = False
    else:
      station_running = wpa_supplicant.is_running(wpa_supplicant.WPA_SUPPLICANT_CONF)
      if station_running or self._dhcp.running:
        if not self._dhcp.stop():
          cloudlog.error("Failed to stop Wi-Fi DHCP during shutdown")
          return False
        if station_running and not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF):
          self._dhcp.start()
          cloudlog.error("Failed to stop station wpa_supplicant during shutdown")
          return False
        self._dhcp.clear_ipv6()

    clear_active_profile()
    self._state = WifiState()
    if not wpa_supplicant.restore_networkmanager():
      cloudlog.error("Failed to return wlan0 to NetworkManager")
      return False
    self._ownership_touched = False
    return True

  def _refresh_saved_ssids(self):
    self._assert_owner()
    self._saved_ssids = frozenset(profile.ssid for profile in self._store.profiles())

  def _initialize_tethering_profile(self):
    self._assert_owner()
    try:
      profile = self._tethering_store.ensure(self._tethering_ssid, self._tethering_password)
    except OSError:
      cloudlog.exception("Failed to initialize tethering profile")
      return
    if profile is not None:
      self._tethering_password = profile.password

  def _close_ctrl(self):
    self._assert_owner()
    if self._monitor is not None:
      self._monitor.close()
      self._monitor = None
    if self._ctrl is not None:
      self._ctrl.close()
      self._ctrl = None

  def _open_station_ctrl(self, adopt: bool = True) -> dict[str, str]:
    self._assert_owner()
    self._ctrl = WpaCtrl()
    self._ctrl.open()
    self._request("RECONFIGURE")
    self._monitor = WpaCtrlMonitor()
    self._monitor.open()
    self._sync_runtime_profiles()
    status = parse_status(self._request("STATUS"))
    if adopt:
      self._adopt_status(status)
    return status

  def _start_station(self) -> bool:
    self._assert_owner()
    station_was_running = wpa_supplicant.is_running(wpa_supplicant.WPA_SUPPLICANT_CONF)
    dhcp_was_running = self._dhcp.running
    retained_active_profile = read_active_profile() if station_was_running and dhcp_was_running else None
    networks = []
    for profile in self._store.profiles():
      network = profile.as_wpa_network()
      if retained_active_profile is not None and profile.uuid == retained_active_profile[0]:
        network = replace(network, disabled=False)
      networks.append(network)
    try:
      wpa_supplicant.write_station_config(networks)
    except OSError:
      cloudlog.exception("Failed to write station wpa_supplicant configuration")
      if station_was_running or dhcp_was_running:
        self._ownership_touched = True
        if not self._clear_l3():
          cloudlog.error("Failed to stop stale Wi-Fi DHCP after station configuration failure")
          return False
      if not wpa_supplicant.restore_networkmanager():
        self._ownership_touched = True
        cloudlog.error("Failed to return wlan0 to NetworkManager after station configuration failure")
      else:
        self._ownership_touched = False
      return False
    l3_cleared = False
    if not station_was_running and dhcp_was_running:
      self._ownership_touched = True
      if not self._clear_l3():
        cloudlog.error("Failed to stop stale Wi-Fi DHCP before starting station")
        return False
      l3_cleared = True
    self._ownership_touched = True
    acquisition = wpa_supplicant.begin_station()
    if acquisition is None:
      return False
    if not (station_was_running and dhcp_was_running) and not l3_cleared:
      if not self._clear_l3():
        if not acquisition.rollback():
          cloudlog.error("Failed to roll back station acquisition")
        return False
    try:
      status = self._open_station_ctrl(adopt=False)
    except (OSError, RuntimeError):
      self._close_ctrl()
      if not acquisition.rollback():
        cloudlog.error("Failed to roll back station acquisition")
      return False
    if station_was_running and dhcp_was_running:
      profile_uuid = status.get("id_str", "").strip('"')
      retained_profile_uuid = retained_active_profile[0] if retained_active_profile is not None else None
      if status.get("wpa_state") != "COMPLETED" or profile_uuid != retained_profile_uuid:
        if not self._clear_l3():
          self._close_ctrl()
          if not acquisition.rollback():
            cloudlog.error("Failed to roll back station acquisition")
          return False
    if not acquisition.commit():
      self._close_ctrl()
      cloudlog.error("Failed to commit station acquisition")
      return False
    self._adopt_status(status)
    return True

  def _initialize_station(self):
    self._assert_owner()
    if not self._start_station():
      raise RuntimeError("failed to start station wpa_supplicant")

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

  def _restore_network_enablement(self):
    self._assert_owner()
    enable_networks = []
    for profile in self._store.profiles():
      network_id = self._runtime_profiles.get(profile.uuid)
      if network_id is not None and (profile.autoconnect or profile.uuid == self._state.profile_uuid):
        enable_networks.append(network_id)
    raw = self._request("LIST_NETWORKS")
    for line in raw.splitlines()[1:]:
      fields = line.split("\t")
      if fields and fields[0].isdigit() and fields[0] not in enable_networks:
        self._request(f"DISABLE_NETWORK {fields[0]}")
    for network_id in enable_networks:
      self._request(f"ENABLE_NETWORK {network_id}")

  def _update_scan_results(self):
    self._assert_owner()
    try:
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

  def _scan(self):
    self._assert_owner()
    try:
      self._request("SCAN")
    except (OSError, RuntimeError):
      return
    self._update_scan_results()

  @staticmethod
  def _valid_psk(password: str) -> bool:
    try:
      if any(unicodedata.category(char) == "Cc" for char in password):
        return False
      size = len(password.encode("utf-8"))
    except UnicodeEncodeError:
      return False
    return 8 <= size <= 63 or len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password)

  @staticmethod
  def _psk_value(password: str) -> str:
    if len(password) == 64 and all(char in "0123456789abcdefABCDEF" for char in password):
      return password
    return '"' + password.replace("\\", "\\\\").replace('"', '\\"') + '"'

  def _connect(self, command: _Connect):
    self._assert_owner()
    if self._requested_ssid is not None:
      self._cancel_selection(notify=False)
    if not is_valid_ssid(command.ssid):
      self._callbacks.put(("need_auth", command.ssid))
      return
    if command.security == SecurityType.WPA and not self._valid_psk(command.password):
      self._callbacks.put(("need_auth", command.ssid))
      return

    existing = self._store.profiles_for_ssid(command.ssid)
    if existing:
      if len(existing) != 1 or not self._store.can_mutate(existing[0].uuid):
        self._callbacks.put(("profile_readonly", command.ssid))
        return
      old = existing[0]
      profile = NetworkProfile(
        uuid=old.uuid,
        ssid=old.ssid,
        security=command.security,
        psk=command.password if command.security == SecurityType.WPA else "",
        hidden=command.hidden or old.hidden,
        priority=old.priority,
        bssid=old.bssid,
        metered=old.metered,
        ipv6_enabled=old.ipv6_enabled,
        autoconnect=old.autoconnect,
      )
      self._replacement_network_id = self._runtime_profiles.get(old.uuid)
    else:
      profile = NetworkProfile(
        uuid=str(uuid.uuid4()),
        ssid=command.ssid,
        security=command.security,
        psk=command.password if command.security == SecurityType.WPA else "",
        hidden=command.hidden,
        ipv6_enabled=False,
      )
      self._replacement_network_id = None

    if not self._begin_selection(command.ssid):
      return
    try:
      network_id = self._request("ADD_NETWORK").strip()
      if not network_id.isdigit():
        raise RuntimeError("invalid network id")
      self._temporary_network_id = network_id
      self._request(f"SET_NETWORK {network_id} ssid {command.ssid.encode('utf-8', errors='surrogateescape').hex()}")
      self._request(f"SET_NETWORK {network_id} id_str \"{profile.uuid}\"")
      if command.security == SecurityType.WPA:
        self._request(f"SET_NETWORK {network_id} psk {self._psk_value(command.password)}")
        self._request(f"SET_NETWORK {network_id} key_mgmt WPA-PSK")
      else:
        self._request(f"SET_NETWORK {network_id} key_mgmt NONE")
      if profile.hidden:
        self._request(f"SET_NETWORK {network_id} scan_ssid 1")
      if profile.bssid:
        self._request(f"SET_NETWORK {network_id} bssid {profile.bssid}")
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
    if self._requested_ssid is not None:
      self._cancel_selection(notify=False)
    profiles = self._store.profiles_for_ssid(ssid)
    runtime_ids = [self._runtime_profiles[profile.uuid] for profile in profiles if profile.uuid in self._runtime_profiles]
    if len(runtime_ids) < len(profiles):
      try:
        self._sync_runtime_profiles()
      except (OSError, RuntimeError):
        self._callbacks.put(("disconnected", None))
        return
      runtime_ids = [self._runtime_profiles[profile.uuid] for profile in profiles if profile.uuid in self._runtime_profiles]
    if not runtime_ids or len(runtime_ids) < len(profiles):
      self._callbacks.put(("disconnected", None))
      return

    if not self._begin_selection(ssid):
      return
    try:
      self._request("DISABLE_NETWORK all")
      for network_id in runtime_ids:
        self._request(f"ENABLE_NETWORK {network_id}")
      self._request("REASSOCIATE")
    except (OSError, RuntimeError):
      self._cancel_selection()

  def _set_metered(self, metered: MeteredType):
    self._assert_owner()
    profile_uuid = self._state.profile_uuid
    if profile_uuid is None:
      return
    profile = self._store.set_metered(profile_uuid, metered)
    if profile is None:
      self._callbacks.put(("settings_failed", self._state.ssid))
      return
    self._state = WifiState(
      ssid=self._state.ssid,
      status=self._state.status,
      profile_uuid=profile.uuid,
      ipv4_address=self._state.ipv4_address,
      metered=profile.metered,
    )
    if self._state.status == ConnectStatus.CONNECTED:
      self._publish_active_profile(profile)

  def _forget(self, ssid: str):
    self._assert_owner()
    profiles = self._store.profiles_for_ssid(ssid)
    if not profiles and self._requested_ssid == ssid:
      try:
        self._cancel_selection(notify=False)
      except RuntimeError:
        self._callbacks.put(("forget_failed", ssid))
        return
      self._callbacks.put(("forgotten", ssid))
      return
    runtime_ids = [self._runtime_profiles[profile.uuid] for profile in profiles if profile.uuid in self._runtime_profiles]
    active_forget = self._state.ssid == ssid or self._requested_ssid == ssid
    try:
      for network_id in runtime_ids:
        self._request(f"DISABLE_NETWORK {network_id}")
    except (OSError, RuntimeError):
      try:
        self._restore_network_enablement()
      except (OSError, RuntimeError):
        pass
      self._callbacks.put(("forget_failed", ssid))
      return

    if active_forget and not self._clear_l3():
      try:
        self._restore_network_enablement()
      except (OSError, RuntimeError):
        pass
      self._callbacks.put(("forget_failed", ssid))
      return

    if not self._store.remove_ssid(ssid):
      try:
        self._restore_network_enablement()
      except (OSError, RuntimeError):
        pass
      self._callbacks.put(("forget_failed", ssid))
      return

    self._refresh_saved_ssids()
    if active_forget:
      self._state = WifiState()
      self._requested_ssid = None
      self._connecting_since = 0.0
      self._pending_profile = None
      self._temporary_network_id = None
      self._replacement_network_id = None

    for profile in profiles:
      self._runtime_profiles.pop(profile.uuid, None)
    for network_id in runtime_ids:
      try:
        self._request(f"REMOVE_NETWORK {network_id}")
      except (OSError, RuntimeError):
        pass

    try:
      wpa_supplicant.write_station_config([profile.as_wpa_network() for profile in self._store.profiles()])
    except OSError:
      cloudlog.exception("Failed to rewrite station wpa_supplicant configuration after forget")
    else:
      try:
        self._request("RECONFIGURE")
        self._sync_runtime_profiles()
        self._restore_network_enablement()
      except (OSError, RuntimeError):
        pass
    self._callbacks.put(("forgotten", ssid))

  def _set_tethering_active(self, active: bool):
    self._assert_owner()
    if active == self._tethering_active:
      return
    if active:
      self._enter_tethering()
    else:
      self._leave_tethering()

  def _enter_tethering(self):
    self._assert_owner()
    if not self._valid_psk(self._tethering_password):
      self._callbacks.put(("tethering_failed", None))
      return

    try:
      wpa_supplicant.write_ap_config(self._tethering_ssid, self._tethering_password)
    except OSError:
      self._callbacks.put(("tethering_failed", None))
      return
    if not self._clear_l3():
      self._callbacks.put(("tethering_failed", None))
      return
    self._close_ctrl()
    if not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF):
      try:
        self._open_station_ctrl()
      except (OSError, RuntimeError):
        pass
      self._callbacks.put(("tethering_failed", None))
      return

    if not wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF):
      self._restore_station_after_tethering_failure()
      self._callbacks.put(("tethering_failed", None))
      return
    if not self._tethering.start(self._ipv4_forward):
      if not self._tethering.stop():
        self._tethering_active = True
        self._state = WifiState()
        self._callbacks.put(("tethering_failed", None))
        return
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        self._tethering_active = True
        self._state = WifiState()
        self._callbacks.put(("tethering_failed", None))
        return
      self._restore_station_after_tethering_failure()
      self._callbacks.put(("tethering_failed", None))
      return

    self._runtime_profiles = {}
    self._pending_profile = None
    self._temporary_network_id = None
    self._replacement_network_id = None
    self._requested_ssid = None
    self._connecting_since = 0.0
    self._tethering_password_rollback = None
    self._tethering_active = True
    self._last_tethering_firewall_check = time.monotonic()
    self._state = WifiState(ssid=self._tethering_ssid, status=ConnectStatus.CONNECTED, ipv4_address=wifi_tethering.TETHERING_ADDRESS)
    self._callbacks.put(("activated", None))

  def _restore_station_after_tethering_failure(self):
    self._assert_owner()
    self._state = WifiState()
    if not self._start_station():
      cloudlog.error("Failed to restore station Wi-Fi after tethering transition")

  def _leave_tethering(self, failed: bool = False):
    self._assert_owner()
    if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
      self._callbacks.put(("tethering_failed", None))
      return
    if not self._tethering.stop():
      wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF)
      self._callbacks.put(("tethering_failed", None))
      return

    self._tethering_password_rollback = None
    self._tethering_active = False
    self._last_tethering_firewall_check = 0.0
    self._state = WifiState()
    if self._start_station():
      self._callbacks.put(("tethering_failed" if failed else "disconnected", None))
      return

    if wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF):
      if self._tethering.start(self._ipv4_forward):
        self._tethering_active = True
        self._last_tethering_firewall_check = time.monotonic()
        self._state = WifiState(ssid=self._tethering_ssid, status=ConnectStatus.CONNECTED, ipv4_address=wifi_tethering.TETHERING_ADDRESS)
      elif not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF) or not self._tethering.stop():
        self._tethering_active = True
    self._callbacks.put(("tethering_failed", None))

  def _reconcile_tethering(self):
    self._assert_owner()
    if self._tethering_password_rollback is not None:
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        return
      password = self._tethering_password_rollback
      if not self._restore_tethering_password(password):
        self._tethering_password_rollback = None
        self._leave_tethering(failed=True)
        return
      self._tethering_password_rollback = None
      self._callbacks.put(("networks_updated", None))

    if self._state.status != ConnectStatus.CONNECTED:
      self._leave_tethering(failed=True)
      return
    if not (wpa_supplicant.is_running(wpa_supplicant.WPA_AP_CONF)
            and wifi_tethering.dnsmasq_running()
            and wifi_tethering.interface_ready()):
      self._leave_tethering(failed=True)
      return

    now = time.monotonic()
    if now - self._last_tethering_firewall_check < TETHERING_FIREWALL_CHECK_PERIOD_SECONDS:
      return
    self._last_tethering_firewall_check = now
    if not wifi_tethering.firewall_ready():
      self._leave_tethering(failed=True)

  def _set_tethering_password(self, password: str):
    self._assert_owner()
    if self._tethering_password_rollback is not None:
      self._callbacks.put(("tethering_failed", None))
      return
    if not self._valid_psk(password):
      self._callbacks.put(("tethering_failed", None))
      return
    if password == self._tethering_password:
      self._callbacks.put(("networks_updated", None))
      return

    if not self._tethering_active:
      try:
        profile = self._tethering_store.set_password(self._tethering_ssid, password)
      except OSError:
        profile = None
      if profile is None:
        self._callbacks.put(("tethering_failed", None))
        return
      self._tethering_password = profile.password
      return

    old_password = self._tethering_password
    if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
      self._callbacks.put(("tethering_failed", None))
      return
    try:
      wpa_supplicant.write_ap_config(self._tethering_ssid, password)
    except OSError:
      if self._restore_tethering_password(old_password):
        self._callbacks.put(("tethering_failed", None))
      else:
        self._leave_tethering(failed=True)
      return
    if not wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF):
      if self._restore_tethering_password(old_password):
        self._callbacks.put(("tethering_failed", None))
      else:
        self._leave_tethering(failed=True)
      return
    if not wifi_tethering.wait_for_ap_ready():
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        self._tethering_password_rollback = old_password
        self._callbacks.put(("tethering_failed", None))
        return
      if self._restore_tethering_password(old_password):
        self._callbacks.put(("tethering_failed", None))
      else:
        self._leave_tethering(failed=True)
      return

    try:
      profile = self._tethering_store.set_password(self._tethering_ssid, password)
    except OSError:
      profile = None
    if profile is None:
      if not wpa_supplicant.stop(wpa_supplicant.WPA_AP_CONF):
        self._tethering_password_rollback = old_password
        self._callbacks.put(("tethering_failed", None))
        return
      if self._restore_tethering_password(old_password):
        self._callbacks.put(("tethering_failed", None))
      else:
        self._leave_tethering(failed=True)
      return
    self._tethering_password = profile.password

  def _restore_tethering_password(self, password: str) -> bool:
    self._assert_owner()
    try:
      wpa_supplicant.write_ap_config(self._tethering_ssid, password)
    except OSError:
      cloudlog.exception("Failed to restore tethering configuration after password update")
      return False
    if not wpa_supplicant.start(wpa_supplicant.WPA_AP_CONF) or not wifi_tethering.wait_for_ap_ready():
      cloudlog.error("Failed to restore tethering after password update")
      return False
    return True

  def _set_ipv4_forward(self, enabled: bool):
    self._assert_owner()
    if enabled == self._ipv4_forward:
      return
    if self._tethering_active:
      try:
        wifi_tethering.set_ipv4_forward(enabled)
      except (OSError, RuntimeError):
        self._callbacks.put(("tethering_failed", None))
        return
    self._ipv4_forward = enabled

  def _begin_selection(self, ssid: str) -> bool:
    self._assert_owner()
    if not self._clear_l3():
      self._callbacks.put(("settings_failed", ssid))
      return False
    self._requested_ssid = ssid
    self._connecting_since = time.monotonic()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)
    return True

  def _clear_l3(self) -> bool:
    self._assert_owner()
    if not self._dhcp.stop():
      return False
    clear_active_profile()
    self._published_active_profile = None
    self._dhcp.clear_ipv6()
    return True

  def _remove_temporary_network(self):
    self._assert_owner()
    if self._temporary_network_id is None:
      return
    try:
      self._request(f"REMOVE_NETWORK {self._temporary_network_id}")
    except (OSError, RuntimeError):
      pass
    self._temporary_network_id = None

  def _cancel_selection(self, notify: bool = True):
    self._assert_owner()
    pending_uuid = self._pending_profile.uuid if self._pending_profile is not None else None
    self._remove_temporary_network()
    if pending_uuid is not None:
      if self._replacement_network_id is None:
        self._runtime_profiles.pop(pending_uuid, None)
      else:
        self._runtime_profiles[pending_uuid] = self._replacement_network_id
    self._pending_profile = None
    self._replacement_network_id = None
    self._requested_ssid = None
    self._connecting_since = 0.0
    if not self._clear_l3():
      try:
        self._restore_network_enablement()
      except (OSError, RuntimeError):
        pass
      raise RuntimeError("failed to stop Wi-Fi DHCP") from None
    self._state = WifiState()
    try:
      self._restore_network_enablement()
    except (OSError, RuntimeError):
      pass
    if notify:
      self._callbacks.put(("disconnected", None))

  def _link_lost(self):
    self._assert_owner()
    previous = self._state
    if not self._clear_l3():
      raise RuntimeError("failed to stop Wi-Fi DHCP") from None
    self._connecting_since = time.monotonic()
    if self._requested_ssid is not None:
      self._state = WifiState(ssid=self._requested_ssid, status=ConnectStatus.CONNECTING)
    elif previous.ssid is not None:
      self._state = WifiState(
        ssid=previous.ssid,
        status=ConnectStatus.CONNECTING,
        profile_uuid=previous.profile_uuid,
        metered=previous.metered,
      )
    else:
      self._state = WifiState()

  def _handle_wpa_event(self, event: str):
    self._assert_owner()
    if event.startswith("CTRL-EVENT-SCAN-RESULTS"):
      self._update_scan_results()
      return

    if event.startswith("CTRL-EVENT-CONNECTED"):
      try:
        status = parse_status(self._request("STATUS"))
      except (OSError, RuntimeError):
        return
      if status.get("wpa_state") == "COMPLETED":
        self._adopt_status(status)
      return

    if event.startswith("CTRL-EVENT-DISCONNECTED"):
      self._link_lost()
      return

    if "WRONG_KEY" in event or "reason=WRONG_KEY" in event:
      failed_id = parse_event_network_id(event)
      failed_ssid = parse_event_ssid(event)
      matches_ssid = failed_ssid in (None, self._requested_ssid)
      if self._pending_profile is not None:
        pending_id = self._runtime_profiles.get(self._pending_profile.uuid)
        matches_network_id = failed_id is None or failed_id == pending_id
      else:
        candidate_ids = [
          self._runtime_profiles[profile.uuid]
          for profile in self._store.profiles_for_ssid(self._requested_ssid)
          if profile.uuid in self._runtime_profiles
        ] if self._requested_ssid is not None else []
        matches_network_id = len(candidate_ids) == 1 and (failed_id is None or failed_id == candidate_ids[0])
      if self._requested_ssid is not None and matches_ssid and matches_network_id:
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
        self._refresh_saved_ssids()
        new_network_id = self._temporary_network_id
        if self._replacement_network_id is not None and self._replacement_network_id != new_network_id:
          try:
            self._request(f"REMOVE_NETWORK {self._replacement_network_id}")
          except (OSError, RuntimeError):
            pass
        if new_network_id is not None:
          self._runtime_profiles[stored.uuid] = new_network_id
        self._pending_profile = None
        self._temporary_network_id = None
        self._replacement_network_id = None
        wpa_supplicant.write_station_config([profile.as_wpa_network() for profile in self._store.profiles()])
        profile_uuid = stored.uuid
      except (OSError, subprocess.SubprocessError):
        self._cancel_selection()
        try:
          self._sync_runtime_profiles()
          self._restore_network_enablement()
        except (OSError, RuntimeError):
          pass
        return

    profile = self._store.get(profile_uuid)
    if profile is None:
      return

    if self._state.profile_uuid is not None and self._state.profile_uuid != profile_uuid:
      if not self._clear_l3():
        raise RuntimeError("failed to stop Wi-Fi DHCP") from None

    if not profile.ipv6_enabled and not self._dhcp.clear_ipv6():
      return
    self._requested_ssid = None
    self._connecting_since = time.monotonic()
    if not self._dhcp.running:
      self._dhcp.start()
    self._state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING, profile_uuid=profile_uuid, metered=profile.metered)
    try:
      self._restore_network_enablement()
    except (OSError, RuntimeError):
      pass

  def _publish_active_profile(self, profile: NetworkProfile) -> bool:
    self._assert_owner()
    active_profile = (profile.uuid, int(profile.metered))
    if self._published_active_profile == active_profile:
      return True
    try:
      write_active_profile(*active_profile)
    except Exception:
      cloudlog.exception("Failed to publish active Wi-Fi profile")
      return False
    self._published_active_profile = active_profile
    return True

  def _recover_station_control(self):
    self._assert_owner()
    selection_pending = self._requested_ssid is not None
    self._close_ctrl()
    if not self._clear_l3():
      raise RuntimeError("failed to stop Wi-Fi DHCP") from None
    if not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF):
      raise RuntimeError("failed to stop unresponsive station wpa_supplicant") from None
    self._runtime_profiles = {}
    self._pending_profile = None
    self._temporary_network_id = None
    self._replacement_network_id = None
    self._requested_ssid = None
    self._connecting_since = 0.0
    self._state = WifiState()
    self._control_failures = 0
    if not self._start_station():
      raise RuntimeError("failed to recover station wpa_supplicant") from None
    if selection_pending:
      self._callbacks.put(("disconnected", None))

  def _reconcile(self):
    self._assert_owner()
    try:
      status = parse_status(self._request("STATUS"))
    except (OSError, RuntimeError):
      if wpa_supplicant.is_running(wpa_supplicant.WPA_SUPPLICANT_CONF):
        self._control_failures += 1
        if self._control_failures < CONTROL_FAILURE_LIMIT:
          return
        self._recover_station_control()
        return
      selection_pending = self._requested_ssid is not None
      self._control_failures = 0
      self._close_ctrl()
      if not self._clear_l3():
        raise RuntimeError("failed to stop Wi-Fi DHCP") from None
      self._runtime_profiles = {}
      self._pending_profile = None
      self._temporary_network_id = None
      self._replacement_network_id = None
      self._requested_ssid = None
      self._connecting_since = 0.0
      self._state = WifiState()
      if not self._start_station():
        raise RuntimeError("failed to recover station wpa_supplicant") from None
      if selection_pending:
        self._callbacks.put(("disconnected", None))
      return
    self._control_failures = 0

    if status.get("wpa_state") == "COMPLETED":
      ssid = status.get("ssid")
      profile_uuid = status.get("id_str", "").strip('"')
      if self._state.profile_uuid != profile_uuid or self._state.ssid != ssid:
        self._adopt_status(status)

      if (self._state.profile_uuid == profile_uuid
          and self._state.status == ConnectStatus.CONNECTED
          and (not self._dhcp.running or not self._dhcp.ready())):
        self._link_lost()

      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTED:
        ipv4_address = self._dhcp.ipv4_address()
        if ipv4_address != self._state.ipv4_address:
          self._state = WifiState(
            ssid=self._state.ssid,
            status=self._state.status,
            profile_uuid=self._state.profile_uuid,
            ipv4_address=ipv4_address,
            metered=self._state.metered,
          )
          self._callbacks.put(("networks_updated", None))
        profile = self._store.get(profile_uuid)
        if profile is not None:
          self._publish_active_profile(profile)

      if self._state.profile_uuid == profile_uuid and self._state.status == ConnectStatus.CONNECTING:
        if not self._dhcp.running:
          self._dhcp.start()
        if self._dhcp.ready():
          profile = self._store.get(profile_uuid)
          if profile is None:
            return
          self._state = WifiState(
            ssid=ssid,
            status=ConnectStatus.CONNECTED,
            profile_uuid=profile_uuid,
            ipv4_address=self._dhcp.ipv4_address(),
            metered=profile.metered,
          )
          self._publish_active_profile(profile)
          self._connecting_since = 0.0
          self._callbacks.put(("activated", None))
        elif self._connecting_since and time.monotonic() - self._connecting_since >= CONNECT_TIMEOUT_SECONDS:
          self._cancel_selection()
          try:
            network_id = self._runtime_profiles.get(profile_uuid)
            if network_id is not None:
              self._request(f"DISABLE_NETWORK {network_id}")
              self._request("REASSOCIATE")
          except (OSError, RuntimeError):
            pass

      if self._state.status == ConnectStatus.CONNECTING and self._connecting_since and time.monotonic() - self._connecting_since >= CONNECT_TIMEOUT_SECONDS:
        self._cancel_selection()
      return
    if self._state.status == ConnectStatus.CONNECTED:
      self._link_lost()
      return

    if self._state.status == ConnectStatus.CONNECTING and self._connecting_since and time.monotonic() - self._connecting_since >= CONNECT_TIMEOUT_SECONDS:
      self._cancel_selection()
