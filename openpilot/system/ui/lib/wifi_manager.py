import atexit
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.wifi_controller import WifiController
from openpilot.system.ui.lib.wifi_network_store import MeteredType as StoreMeteredType
from openpilot.system.ui.lib.wpa_ctrl import SecurityType as ControllerSecurityType
from openpilot.system.ui.lib.wpa_ctrl import normalize_ssid as normalize_ssid

try:
  from openpilot.common.params import Params
except (ImportError, OSError):
  Params = None


class SecurityType(IntEnum):
  OPEN = 0
  WPA = 1
  WPA2 = 2
  WPA3 = 3
  UNSUPPORTED = 4


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


def _security_type(security: ControllerSecurityType) -> SecurityType:
  if security == ControllerSecurityType.OPEN:
    return SecurityType.OPEN
  if security == ControllerSecurityType.WPA:
    return SecurityType.WPA
  return SecurityType.UNSUPPORTED


class WifiManager:
  def __init__(self):
    tethering_ssid = "weedle"
    if Params is not None:
      dongle_id = Params().get("DongleId")
      if dongle_id:
        tethering_ssid += "-" + dongle_id[:4]

    self._controller = WifiController(tethering_ssid=tethering_ssid)
    self._controller.set_active(True)
    self._need_auth: list[Callable[[str], None]] = []
    self._activated: list[Callable[[], None]] = []
    self._forgotten: list[Callable[[str | None], None]] = []
    self._networks_updated: list[Callable[[list[Network]], None]] = []
    self._disconnected: list[Callable[[], None]] = []
    self._pending_selection: str | None = None
    self._last_snapshot = self._snapshot()
    atexit.register(self.stop)

  def add_callbacks(self, need_auth: Callable[[str], None] | None = None,
                    activated: Callable[[], None] | None = None,
                    forgotten: Callable[[str | None], None] | None = None,
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
    if self._controller.tethering_active:
      return [Network(self.connected_ssid or "", 100, SecurityType.WPA, True)]
    return [Network(network.ssid, network.strength, _security_type(network.security_type), False) for network in self._controller.networks]

  @property
  def wifi_state(self) -> WifiState:
    state = self._controller.state
    return WifiState(state.ssid, ConnectStatus(int(state.status)))

  @property
  def ipv4_address(self) -> str:
    return self._controller.state.ipv4_address

  @property
  def current_network_metered(self) -> MeteredType:
    return MeteredType(int(self._controller.state.metered))

  @property
  def connecting_to_ssid(self) -> str | None:
    state = self.wifi_state
    return state.ssid if state.status == ConnectStatus.CONNECTING else None

  @property
  def connected_ssid(self) -> str | None:
    state = self.wifi_state
    return state.ssid if state.status == ConnectStatus.CONNECTED else None

  @property
  def tethering_password(self) -> str:
    return self._controller.tethering_password

  def is_tethering_active(self) -> bool:
    return self._controller.tethering_active

  def is_connection_saved(self, ssid: str) -> bool:
    return self._controller.is_connection_saved(ssid)

  def set_active(self, active: bool):
    self._controller.set_active(active)

  def connect_to_network(self, ssid: str, password: str, hidden: bool = False):
    security = ControllerSecurityType.WPA if password else ControllerSecurityType.OPEN
    self._pending_selection = ssid
    self._controller.connect(ssid, password, hidden, security)

  def activate_connection(self, ssid: str, block: bool = False):
    self._pending_selection = ssid
    self._controller.activate(ssid)

  def forget_connection(self, ssid: str, block: bool = False):
    self._controller.forget(ssid)

  def set_tethering_password(self, password: str):
    self._controller.set_tethering_password(password)

  def set_ipv4_forward(self, enabled: bool):
    self._controller.set_ipv4_forward(enabled)

  def set_tethering_active(self, active: bool):
    self._controller.set_tethering_active(active)

  def set_current_network_metered(self, metered: MeteredType):
    self._controller.set_metered(StoreMeteredType(int(metered)))

  def _snapshot(self):
    state = self._controller.state
    networks = tuple((network.ssid, network.strength, int(network.security_type)) for network in self._controller.networks)
    return (state, networks, self._controller.tethering_active, self._controller.tethering_password)

  def _emit_networks_updated(self):
    networks = self.networks
    for callback in self._networks_updated:
      callback(networks)

  def process_callbacks(self):
    emitted_network_update = False
    while (event := self._controller.get_callback()) is not None:
      name, value = event
      if name == "need_auth":
        if self._pending_selection != value:
          continue
        self._pending_selection = None
        for callback in self._need_auth:
          callback(str(value))
      elif name == "activated":
        if self._pending_selection is not None and self.connected_ssid != self._pending_selection:
          continue
        self._pending_selection = None
        for callback in self._activated:
          callback()
      elif name == "forgotten":
        for callback in self._forgotten:
          callback(value if isinstance(value, str) else None)
      elif name == "disconnected":
        self._pending_selection = None
        for callback in self._disconnected:
          callback()
      elif name == "networks_updated":
        self._emit_networks_updated()
        emitted_network_update = True
      elif name == "forget_failed":
        cloudlog.warning(f"Failed to forget Wi-Fi network {value!r}")
        for callback in self._forgotten:
          callback(value if isinstance(value, str) else None)
        self._emit_networks_updated()
        emitted_network_update = True
      elif name == "profile_readonly":
        if self._pending_selection != value:
          continue
        self._pending_selection = None
        cloudlog.warning(f"Wi-Fi profile is read-only: {value!r}")
        for callback in self._disconnected:
          callback()
      elif name == "settings_failed":
        cloudlog.warning(f"Failed to update Wi-Fi settings for {value!r}")
        if self._pending_selection == value and self.connecting_to_ssid != value:
          self._pending_selection = None
          for callback in self._disconnected:
            callback()
        self._emit_networks_updated()
        emitted_network_update = True
      elif name == "tethering_failed":
        cloudlog.warning("Tethering operation failed")
        self._emit_networks_updated()
        emitted_network_update = True

    snapshot = self._snapshot()
    if snapshot != self._last_snapshot and not emitted_network_update:
      self._emit_networks_updated()
    self._last_snapshot = snapshot

  def stop(self):
    self._controller.stop()

  def __del__(self):
    self.stop()