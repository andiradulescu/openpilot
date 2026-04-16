import atexit
import glob
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

from openpilot.common.swaglog import cloudlog
from openpilot.common.utils import atomic_write
from openpilot.system.ui.lib.dhcp_client import DhcpClient
from openpilot.system.ui.lib.gsm_manager import _GsmManager
from openpilot.system.ui.lib.wifi_network_store import MeteredType, NetworkStore, NM_CONNECTIONS_DIR
from openpilot.system.ui.lib.wpa_ctrl import (WpaCtrl, WpaCtrlMonitor, SecurityType,
                                               WPA_SUPPLICANT_CONF, WPA_AP_CONF,
                                               _wpa_supplicant_running, _pkill_wpa_supplicant,
                                               _sanitize_for_conf, _format_psk_value,
                                               _generate_wpa_conf, parse_event_ssid,
                                               parse_scan_results, flags_to_security_type,
                                               parse_status, dbm_to_percent, decode_ssid)

try:
  from openpilot.common.params import Params
except Exception:
  Params = None

TETHERING_IP_ADDRESS = "192.168.43.1"
TETHERING_SUBNET = "192.168.43.0/24"
TETHERING_NAT_COMMENT = "openpilot-tethering"
DEFAULT_TETHERING_PASSWORD = "swagswagcomma"
TETHERING_PASSWORD_FILE = "/data/tethering_password"
SCAN_PERIOD_SECONDS = 5
CONNECTING_STALE_TIMEOUT_SECONDS = 5
# Ignore WRONG_KEY events within this window of the previous dispatch.
# wpa_supplicant can queue multiple events from a single attempt (or a
# prior attempt the user has already retried past), and acting on each
# one clobbers the pending credentials of the current in-flight attempt.
WRONG_KEY_DEBOUNCE_SECONDS = 2.0


@dataclass(frozen=True)
class Network:
  ssid: str
  strength: int
  security_type: SecurityType
  is_tethering: bool


def sort_networks(networks: list[Network], current_ssid: str | None, saved_ssids: set[str]) -> list[Network]:
  """Sort networks: connected first, then saved, then by signal strength."""
  return sorted(networks, key=lambda n: (n.ssid != current_ssid, n.ssid not in saved_ssids, -n.strength, n.ssid.lower()))


class ConnectStatus(IntEnum):
  DISCONNECTED = 0
  CONNECTING = 1
  CONNECTED = 2


@dataclass(frozen=True)
class WifiState:
  ssid: str | None = None
  status: ConnectStatus = ConnectStatus.DISCONNECTED


@dataclass(frozen=True)
class PendingConnection:
  ssid: str
  password: str
  hidden: bool
  epoch: int


# ---------------------------------------------------------------------------
# WifiManager
def _tethering_nat_rule(op: str) -> list[str]:
  """Build the iptables MASQUERADE rule for the tethering subnet.

  Matches NetworkManager's shared-connection rule (see NM
  nm-firewall-utils.c:_share_iptables_set_masquerade_sync): source-subnet
  + negated destination, no `-o <iface>`, tagged with a comment so
  iptables -S surfaces it. Not binding to an uplink is what allows the
  session to survive a default-route change (ETH unplug, SIM drop, 3G↔4G).
  """
  return ["sudo", "iptables",
          "-t", "nat",
          op, "POSTROUTING",
          "-s", TETHERING_SUBNET, "!", "-d", TETHERING_SUBNET,
          "-j", "MASQUERADE",
          "-m", "comment", "--comment", TETHERING_NAT_COMMENT]


# ---------------------------------------------------------------------------

class WifiManager:
  def __init__(self):
    self._networks: list[Network] = []
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
    self._ipv4_forward = False
    self._tethering_active = False
    self._dnsmasq_proc: subprocess.Popen | None = None
    self._pending_connection: PendingConnection | None = None

    self._last_network_scan: float = 0.0
    self._last_connecting_at: float = 0.0
    self._last_connected_recheck: float = 0.0
    self._last_wrong_key_dispatch_at: float = 0.0
    self._callback_queue: list[Callable] = []
    self._callback_lock = threading.Lock()
    # Coalesced dirty flag for periodic networks_updated; the scan worker
    # sets this instead of enqueueing a lambda per scan, so when the panel
    # isn't draining callbacks (e.g. user on another tab) the queue can't
    # grow unboundedly.
    self._networks_updated_pending = False

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
    self._monitor_epoch = 0
    self._scan_thread = threading.Thread(target=self._network_scanner, daemon=True)
    self._state_thread = threading.Thread(target=self._monitor_state, daemon=True)
    self._initialize()
    atexit.register(self.stop)

  def _initialize(self):
    # Load tethering password from file
    try:
      with open(TETHERING_PASSWORD_FILE) as f:
        self._tethering_psk = f.read().strip()
    except FileNotFoundError:
      self._tethering_psk = DEFAULT_TETHERING_PASSWORD

    def worker():
      try:
        _generate_wpa_conf(self._store)
        self._ensure_wpa_supplicant()

        # Populate networks before wifi state so the connected network's
        # strength is available when the UI first renders (avoids the
        # "disconnected icon" flash for the connected SSID).
        self._update_networks(block=True)

        self._init_wifi_state()

        self._scan_thread.start()
        self._state_thread.start()

        cloudlog.debug("WifiManager initialized")
      except Exception:
        cloudlog.exception("WifiManager initialization failed")

    threading.Thread(target=worker, daemon=True).start()

  def _unmanage_wlan0(self):
    """Tell NetworkManager to stop managing wlan0."""
    result = subprocess.run(["sudo", "nmcli", "dev", "set", "wlan0", "managed", "no"], capture_output=True)
    cloudlog.info(f"nmcli dev set wlan0 managed no: rc={result.returncode}")

  def _our_wpa_supplicant_running(self) -> bool:
    """Return True iff a wpa_supplicant process running our config exists.

    Used to pick the fast path in _ensure_wpa_supplicant: if our daemon is
    alive we attach directly, without disturbing NM or waiting for a
    teardown we don't need.
    """
    return _wpa_supplicant_running(WPA_SUPPLICANT_CONF)

  def _try_attach_ctrl(self) -> bool:
    """Attach to an already-running wpa_supplicant via its ctrl socket.

    Works for both our own previously-spawned daemon and a system-managed
    one (e.g. a future systemd/OpenRC unit on tici). Pure attach — never
    spawns, never kills. Returns True if self._ctrl is now live.
    """
    try:
      ctrl = WpaCtrl()
      ctrl.open()
      self._ctrl = ctrl
      return True
    except (OSError, ConnectionRefusedError):
      return False

  def _ensure_wpa_supplicant(self):
    """Attach to a running wpa_supplicant, or spawn one if none is running.

    There must never be more than one wpa_supplicant on wlan0. We prefer
    attaching to a daemon we already own, and only spawn when no such
    daemon exists. We never attach to NM's daemon: NM drives its
    wpa_supplicant over DBus, and our ctrl-socket connection would be
    torn down asynchronously the moment NM releases wlan0.
    """
    # Wait for wlan0 to appear before touching NM. On cold boot the kernel
    # brings wlan0 up ~40s after openpilot starts, and `nmcli dev set wlan0
    # managed no` fails with "Device wlan0 does not exist" when the device
    # isn't registered yet — so NM silently keeps wlan0 managed and grabs
    # it the moment the kernel creates it.
    while not self._exit:
      if os.path.exists("/sys/class/net/wlan0"):
        break
      time.sleep(0.5)

    # AP-mode fast path: if tethering was active before the UI restart, the
    # hotspot's wpa_supplicant is still running with WPA_AP_CONF. Adopt it
    # directly — the STA cleanup path below would otherwise kill dnsmasq,
    # flush wlan0 (dropping TETHERING_IP_ADDRESS), and pkill the STA-config
    # daemon while our AP daemon still holds the ctrl socket, tearing the
    # live hotspot down mid-bringup. _init_wifi_state's mode=AP branch then
    # re-publishes state without disturbing the interface.
    if _wpa_supplicant_running(WPA_AP_CONF) and self._try_attach_ctrl():
      return

    # Fast path: our own STA daemon from a previous UI bringup is still alive.
    # Attach directly — no need to disturb NM or wait for a teardown.
    if self._our_wpa_supplicant_running() and self._try_attach_ctrl():
      try:
        self._ctrl.request("ENABLE_NETWORK all")
      except Exception:
        pass
      return

    # No daemon we own. Tell NM to release wlan0 so its wpa_supplicant
    # removes the ctrl socket, then spawn our own. On AGNOS, NM
    # auto-manages wlan0 on boot and autoconnects a stored profile, which
    # parks NM's wpa_supplicant on /var/run/wpa_supplicant/wlan0.
    self._unmanage_wlan0()

    # NM's teardown is asynchronous: nmcli returns immediately, then NM
    # tells wpa_supplicant over DBus to deinit wlan0, which removes
    # /var/run/wpa_supplicant/wlan0. Wait for that to finish — attaching
    # or spawning before it completes binds us to a socket NM is about to
    # delete, or collides with "ctrl_iface exists and seems to be in use".
    for _ in range(30):
      if self._exit:
        return
      if not os.path.exists("/var/run/wpa_supplicant/wlan0"):
        break
      time.sleep(0.1)
    else:
      # Timeout with the socket still present. NM hasn't released wlan0.
      # Don't bail — the spawn-and-verify path below will refuse to adopt
      # a foreign daemon via the pgrep gate on _try_attach_ctrl, so we
      # either cleanly take over or log an error and give up.
      cloudlog.warning("/var/run/wpa_supplicant/wlan0 still present after NM unmanage; spawn will refuse to attach to foreign daemon")

    # Clean up our own stale state. Target only wpa_supplicants running
    # *our* config so we don't touch a system-managed daemon that happens
    # to be on a different config or a different interface.
    _pkill_wpa_supplicant(WPA_SUPPLICANT_CONF)
    subprocess.run(["sudo", "killall", "-q", "dnsmasq"], check=False)
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=False)
    time.sleep(0.5)

    # Clean up NM metadata files
    for f in glob.glob(os.path.join(NM_CONNECTIONS_DIR, "*.nmmeta")):
      try:
        os.unlink(f)
      except OSError:
        subprocess.run(["sudo", "rm", "-f", f], check=False)

    subprocess.run(["sudo", "wpa_supplicant", "-B", "-i", "wlan0", "-c", WPA_SUPPLICANT_CONF, "-D", "nl80211"], check=False)

    # Wait for it to come up. Gate the attach on pgrep matching OUR config
    # so that if the wait-for-teardown loop above timed out and NM's daemon
    # is still on the socket, we refuse to attach to it (which would
    # silently let NM reconfigure or stop wpa_supplicant underneath us).
    for _ in range(30):
      if self._exit:
        return
      if self._our_wpa_supplicant_running() and self._try_attach_ctrl():
        try:
          self._ctrl.request("ENABLE_NETWORK all")
        except Exception:
          pass
        return
      time.sleep(1)
    cloudlog.error("wpa_supplicant did not start after 30 attempts")

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

      if status.get("mode") == "AP":
        # Process restart while hotspot was active. STATUS reports
        # wpa_state=COMPLETED in AP mode too, so the station path below
        # would call _handle_connected → _dhcp.start() → ip addr flush
        # wlan0, which drops TETHERING_IP_ADDRESS and kills the running
        # hotspot. dnsmasq/iptables/AP wpa_supplicant are still up from
        # the pre-restart bringup (dnsmasq was spawned with
        # start_new_session=True); just adopt the state.
        if self._user_epoch != epoch:
          return
        self._tethering_active = True
        self._wifi_state = WifiState(ssid=ssid or self._tethering_ssid, status=ConnectStatus.CONNECTED)
        self._ipv4_address = TETHERING_IP_ADDRESS
        self._enqueue_callbacks(self._activated)
        return

      if wpa_state == "COMPLETED":
        new_status = ConnectStatus.CONNECTED
      elif wpa_state in ("SCANNING", "AUTHENTICATING", "ASSOCIATING", "ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE"):
        # Adopt mid-connect state on restart. SCANNING/AUTHENTICATING used
        # to fall through to DISCONNECTED, which skipped the connect-in-
        # progress recovery path and let a wrong-password TEMP-DISABLED
        # event bypass its current_ssid check.
        new_status = ConnectStatus.CONNECTING
      else:
        new_status = ConnectStatus.DISCONNECTED
        ssid = None

      if self._user_epoch != epoch:
        return

      if new_status == ConnectStatus.CONNECTED and ssid is not None:
        # Adopt an already-connected daemon (UI restart, or attach to a
        # system-managed daemon that was already associated). We own DHCP,
        # so we must (re)start udhcpc — the previous UI's udhcpc died with
        # its parent, so without this the interface has no IPv4 lease.
        self._handle_connected(ssid)
      else:
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
    return sort_networks(self._networks, self._wifi_state.ssid, self._store.saved_ssids())

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
    return self._tethering_psk

  def _set_connecting(self, ssid: str | None):
    self._user_epoch += 1
    self._last_connecting_at = time.monotonic() if ssid is not None else 0.0
    self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.DISCONNECTED if ssid is None else ConnectStatus.CONNECTING)

  def _set_pending_connection(self, ssid: str, password: str, hidden: bool):
    self._pending_connection = PendingConnection(ssid=ssid, password=password, hidden=hidden, epoch=self._user_epoch)

  def _clear_pending_connection(self, ssid: str | None = None):
    if self._pending_connection is None:
      return
    if ssid is None or self._pending_connection.ssid == ssid:
      self._pending_connection = None

  def _persist_pending_connection(self, ssid: str | None):
    pending = self._pending_connection
    if pending is None:
      return

    if ssid != pending.ssid or pending.epoch != self._user_epoch:
      return

    # Clear _pending_connection only on successful persistence. If the
    # filesystem write fails, keep the credentials so a later retry can
    # save them, and swallow the exception so _handle_connected can still
    # fire DHCP start and the activated callbacks for this connect event.
    try:
      self._store.save_network(ssid, psk=pending.password, hidden=pending.hidden)
      _generate_wpa_conf(self._store)
    except Exception:
      cloudlog.exception("Failed to persist pending connection for %s", ssid)
      return
    self._pending_connection = None

  def _enqueue_callbacks(self, cbs: list[Callable], *args):
    with self._callback_lock:
      for cb in cbs:
        self._callback_queue.append(lambda _cb=cb: _cb(*args))

  def _mark_networks_updated(self):
    """Flag a pending networks_updated notification. Coalesces across scans
    so callback accumulation stays O(1) when the UI isn't draining."""
    with self._callback_lock:
      self._networks_updated_pending = True

  def process_callbacks(self):
    with self._callback_lock:
      to_run, self._callback_queue = self._callback_queue, []
      if self._networks_updated_pending:
        self._networks_updated_pending = False
        networks_cbs = list(self._networks_updated)
      else:
        networks_cbs = None
    for cb in to_run:
      cb()
    if networks_cbs:
      # Always fire with the latest snapshot, not a value captured at the
      # time we were flagged.
      snapshot = self.networks
      for cb in networks_cbs:
        cb(snapshot)

  # ---------------------------------------------------------------------------
  # Monitor thread: wpa_supplicant events
  # ---------------------------------------------------------------------------

  def _monitor_state(self):
    was_down = False
    while not self._exit:
      if self._ctrl is None:
        # wpa_supplicant not reachable yet (CI/dev, or _ensure_wpa_supplicant
        # exhausted its 30 retries at init). Retry attach silently so the
        # manager self-recovers if the daemon shows up later — without the
        # retry-spam of a full monitor-reconnect loop.
        if not self._try_attach_ctrl():
          time.sleep(2)
          continue
      monitor = None
      try:
        epoch = self._monitor_epoch
        monitor = WpaCtrlMonitor()
        monitor.open()
        if was_down:
          # Monitor reconnected after a prior failure — if wpa_supplicant
          # restarted (e.g. systemd brought it back), our main ctrl socket
          # is stale too. Refresh it without touching any service manager.
          self._try_attach_ctrl()
          was_down = False
        while not self._exit and self._monitor_epoch == epoch:
          event = monitor.recv(timeout=1.0)
          if event is None:
            continue
          self._handle_event(event)
      except Exception:
        was_down = True
        cloudlog.exception("wpa_supplicant monitor error, reconnecting...")
      finally:
        if monitor is not None:
          try:
            monitor.close()
          except Exception:
            pass
        time.sleep(2)

  def _handle_connected(self, ssid: str):
    """Transition to CONNECTED: persist credentials, start DHCP, notify UI.

    Idempotent: if we're already reporting CONNECTED to the same ssid, skip
    the DHCP restart and callback fan-out. Without this, the scanner's
    reconcile loop and the monitor thread's CTRL-EVENT-CONNECTED handler can
    both call in for the same transition, and each `_dhcp.start()` kills the
    previous udhcpc."""
    if (self._wifi_state.status == ConnectStatus.CONNECTED
        and self._wifi_state.ssid == ssid):
      return
    self._last_connecting_at = 0.0
    self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTED)
    self._persist_pending_connection(ssid)
    # Re-enable all saved networks so wpa_supplicant can auto-roam if the
    # current AP disappears. SELECT_NETWORK (in _add_and_select_network /
    # activate_connection) disables every other network as a side effect,
    # so without this call the runtime daemon has only one enabled network
    # and cannot fall back to another saved AP when the current one fades.
    if self._ctrl is not None:
      try:
        self._ctrl.request("ENABLE_NETWORK all")
      except Exception:
        cloudlog.exception("Failed to re-enable saved networks for auto-roam")
    self._dhcp.start()
    self._enqueue_callbacks(self._activated)
    self._poll_for_ip()

  def _handle_event(self, event: str):
    """Dispatch wpa_supplicant event to state machine."""
    if "CTRL-EVENT-SCAN-RESULTS" in event:
      self._update_networks(block=False)

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

      if ssid:
        self._handle_connected(ssid)

    elif "CTRL-EVENT-DISCONNECTED" in event:
      if self._tethering_active:
        return  # Ignore disconnects during tethering transitions

      epoch = self._user_epoch

      # Don't clear state if we're connecting to something (user action in progress)
      if self._wifi_state.status == ConnectStatus.CONNECTING:
        return

      if self._user_epoch != epoch:
        return

      self._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
      self._dhcp.stop()
      self._ipv4_address = ""
      self._current_network_metered = MeteredType.UNKNOWN
      self._enqueue_callbacks(self._disconnected)

    elif "TEMP-DISABLED" in event and "reason=WRONG_KEY" in event:
      event_ssid = parse_event_ssid(event)
      if event_ssid is not None:
        # Debounce: suppress stale events from a prior attempt for the
        # same SSID. If the user just retried with fresh credentials, an
        # in-flight WRONG_KEY from the earlier attempt can arrive and
        # clobber the new pending password; the real outcome of the new
        # attempt will surface as a later event.
        now = time.monotonic()
        if now - self._last_wrong_key_dispatch_at < WRONG_KEY_DEBOUNCE_SECONDS:
          return
        current_ssid = self._wifi_state.ssid
        # Auto-connect can land us in CONNECTING with ssid=None when STATUS
        # was briefly unavailable at set-connecting time. In that window
        # the supplicant's SSID in the WRONG_KEY event is the most
        # authoritative identifier of the target network, so accept it.
        connecting_unknown = (
          self._wifi_state.status == ConnectStatus.CONNECTING
          and current_ssid is None
        )
        if connecting_unknown or (current_ssid and event_ssid == current_ssid):
          self._last_wrong_key_dispatch_at = now
          self._clear_pending_connection(event_ssid)
          self._enqueue_callbacks(self._need_auth, event_ssid)
          self._set_connecting(None)

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
        self._last_connecting_at = time.monotonic()
        self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)

  # ---------------------------------------------------------------------------
  # Scanner thread
  # ---------------------------------------------------------------------------

  def _network_scanner(self):
    while not self._exit:
      self._reconcile_connecting_state()
      if not self._tethering_active:
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

  def _reconcile_connecting_state(self):
    current_state = self._wifi_state
    if self._ctrl is None or self._tethering_active:
      return

    # Detect missed CONNECTED event (e.g. monitor was reconnecting after tethering stop)
    if current_state.status == ConnectStatus.DISCONNECTED:
      try:
        status = parse_status(self._ctrl.request("STATUS"))
      except Exception:
        return
      if status.get("wpa_state") == "COMPLETED" and status.get("ssid"):
        self._handle_connected(status["ssid"])
      return

    # Detect missed DISCONNECTED event. If the monitor socket dropped and
    # reconnected, a CTRL-EVENT-DISCONNECTED may have been lost, leaving
    # self._wifi_state stuck at CONNECTED while wpa_supplicant is actually
    # disconnected. Poll STATUS at SCAN_PERIOD_SECONDS cadence (not every
    # scanner tick, to avoid STATUS spam) and synthesize a disconnect if
    # wpa_supplicant has moved on.
    if current_state.status == ConnectStatus.CONNECTED:
      now = time.monotonic()
      if now - self._last_connected_recheck < SCAN_PERIOD_SECONDS:
        return
      self._last_connected_recheck = now
      try:
        status = parse_status(self._ctrl.request("STATUS"))
      except Exception:
        return
      wpa_state = status.get("wpa_state", "")
      status_ssid = status.get("ssid")
      if wpa_state == "COMPLETED" and status_ssid == current_state.ssid:
        return
      if wpa_state == "COMPLETED" and status_ssid:
        # Roamed to a different SSID while the monitor socket was down.
        # Adopt the new network via the normal connected path instead of
        # synthesizing a disconnect — the latter would flush wlan0's IP
        # (dropping the live lease) and fire a spurious disconnected
        # callback before the next loop figured out we're still up.
        self._handle_connected(status_ssid)
        return
      # Actually disconnected under us.
      self._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
      self._dhcp.stop()
      self._ipv4_address = ""
      self._current_network_metered = MeteredType.UNKNOWN
      self._enqueue_callbacks(self._disconnected)
      return

    # Even if ssid is None (e.g. the auto-connect path couldn't read STATUS
    # when it set CONNECTING), we still need to reconcile — a subsequent
    # STATUS query below will tell us definitively whether we're up.
    if current_state.status != ConnectStatus.CONNECTING:
      return
    if time.monotonic() - self._last_connecting_at < CONNECTING_STALE_TIMEOUT_SECONDS:
      return

    try:
      status = parse_status(self._ctrl.request("STATUS"))
    except Exception:
      cloudlog.exception("Failed to reconcile wifi state from STATUS")
      return

    wpa_state = status.get("wpa_state", "")
    status_ssid = status.get("ssid")

    if wpa_state == "COMPLETED" and status_ssid:
      self._handle_connected(status_ssid)
    elif wpa_state == "SCANNING":
      # Still actively probing — hidden-SSID joins can legitimately stay in
      # SCANNING past the stale window. Don't synthesize a failure; defer
      # the next check by another full window so we avoid STATUS spam and
      # let wpa_supplicant either find the AP or transition to a terminal
      # state we'll recognize.
      self._last_connecting_at = time.monotonic()
    elif wpa_state in ("DISCONNECTED", "INACTIVE"):
      network = next((n for n in self._networks if n.ssid == current_state.ssid), None)
      if network is not None and network.security_type != SecurityType.OPEN:
        self._enqueue_callbacks(self._need_auth, current_state.ssid)
      self._clear_pending_connection(current_state.ssid)
      self._set_connecting(None)
      self._dhcp.stop()
      self._ipv4_address = ""
      self._current_network_metered = MeteredType.UNKNOWN
      self._enqueue_callbacks(self._disconnected)

  def _update_networks(self, block: bool = True):
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

        # Never replace with empty — stale data is better than no data
        if networks:
          self._networks = networks
        self._update_active_connection_info()
        self._mark_networks_updated()

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def _poll_for_ip(self):
    """Poll for IP address after DHCP starts, then update connection info."""
    epoch = self._user_epoch

    def worker():
      for _ in range(50):  # 10 seconds max
        if self._wifi_state.status != ConnectStatus.CONNECTED or self._user_epoch != epoch:
          return
        self._update_active_connection_info()
        if self._ipv4_address:
          return
        time.sleep(0.2)
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
    # Backend guard: reject station-connect attempts while tethering is
    # active. UI list taps are already filtered at the widget layer but
    # other entry points (hidden-network dialogs, automation) can still
    # reach here, and sending ADD_NETWORK/SELECT_NETWORK to the AP-mode
    # wpa_supplicant fails noisily and churns UI state.
    if self._tethering_active:
      cloudlog.warning(f"Ignoring connect to {ssid!r} while tethering is active")
      return
    self._set_connecting(ssid)
    self._set_pending_connection(ssid, password, hidden)

    def worker():
      if self._ctrl is None:
        cloudlog.warning("No wpa_supplicant connection")
        self._clear_pending_connection(ssid)
        self._init_wifi_state()
        return

      try:
        # Remove any existing network entry for this SSID
        self._remove_wpa_network(ssid)

        self._add_and_select_network(ssid, password, hidden)
      except Exception:
        cloudlog.exception(f"Failed to connect to {ssid}")
        self._clear_pending_connection(ssid)
        self._init_wifi_state()

    threading.Thread(target=worker, daemon=True).start()

  def forget_connection(self, ssid: str, block: bool = False):
    def worker():
      self._clear_pending_connection(ssid)
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
          self._ctrl.request("REASSOCIATE")
        except Exception:
          cloudlog.exception(f"Failed to reconfigure after forgetting {ssid}")

      self._enqueue_callbacks(self._forgotten, ssid)

    if block:
      worker()
    else:
      threading.Thread(target=worker, daemon=True).start()

  def activate_connection(self, ssid: str, block: bool = False):
    if self._tethering_active:
      cloudlog.warning(f"Ignoring activate {ssid!r} while tethering is active")
      return
    self._set_connecting(ssid)
    self._clear_pending_connection()

    def worker():
      if self._ctrl is None:
        cloudlog.warning(f"No wpa_supplicant connection for activate {ssid}")
        self._init_wifi_state()
        return

      try:
        ids = self._list_network_ids(ssid)
        if ids:
          self._ctrl.request(f"SELECT_NETWORK {ids[0]}")
        else:
          # Network not in wpa_supplicant's runtime list — add from store
          entry = self._store.get(ssid)
          if entry:
            self._add_and_select_network(ssid, entry.get("psk", ""), entry.get("hidden", False))
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

  def _add_and_select_network(self, ssid: str, psk: str = "", hidden: bool = False):
    """Add a network to wpa_supplicant and select it.

    Each SET_NETWORK / SELECT_NETWORK response is checked — a short PSK or
    bad key_mgmt returns "FAIL", and without this check SELECT_NETWORK
    would still run, producing a delayed/confusing WRONG_KEY instead of an
    immediate error. On any failure we REMOVE_NETWORK the orphan so we
    don't leak zombie entries across retries."""
    net_id = self._ctrl.request("ADD_NETWORK").strip()
    if not net_id.isdigit():
      raise RuntimeError(f"ADD_NETWORK failed: {net_id}")

    try:
      safe_ssid = _sanitize_for_conf(ssid)
      self._wpa_set_network(net_id, "ssid", f'"{safe_ssid}"')
      if psk:
        self._wpa_set_network(net_id, "psk", _format_psk_value(psk))
      else:
        self._wpa_set_network(net_id, "key_mgmt", "NONE")
      if hidden:
        self._wpa_set_network(net_id, "scan_ssid", "1")
      resp = self._ctrl.request(f"SELECT_NETWORK {net_id}").strip()
      if not resp.startswith("OK"):
        raise RuntimeError(f"SELECT_NETWORK {net_id} failed: {resp}")
    except Exception:
      try:
        self._ctrl.request(f"REMOVE_NETWORK {net_id}")
      except Exception:
        cloudlog.exception(f"Failed to clean up orphaned network {net_id}")
      raise

  def _wpa_set_network(self, net_id: str, key: str, value: str):
    """SET_NETWORK wrapper that raises on wpa_supplicant FAIL responses."""
    resp = self._ctrl.request(f"SET_NETWORK {net_id} {key} {value}").strip()
    if not resp.startswith("OK"):
      raise RuntimeError(f"SET_NETWORK {net_id} {key} failed: {resp}")

  def _list_network_ids(self, ssid: str) -> list[str]:
    """Return all wpa_supplicant network ids matching SSID.

    LIST_NETWORKS emits SSIDs in wpa_ssid_txt (printf_encode) form, so
    non-ASCII or escaped bytes must be decoded before comparing to the
    caller's already-decoded SSID — otherwise `forget_connection` and
    `activate_connection` silently miss entries for any SSID containing
    bytes outside the printable-ASCII range.
    """
    if self._ctrl is None:
      return []
    try:
      raw = self._ctrl.request("LIST_NETWORKS")
      return [parts[0] for line in raw.strip().split("\n")[1:]
              if len(parts := line.split("\t")) >= 2 and decode_ssid(parts[1]) == ssid]
    except Exception:
      cloudlog.exception("Failed to list networks")
      return []

  def _remove_wpa_network(self, ssid: str):
    """Remove all wpa_supplicant network entries matching SSID."""
    for net_id in self._list_network_ids(ssid):
      try:
        self._ctrl.request(f"REMOVE_NETWORK {net_id}")
      except Exception:
        cloudlog.exception(f"Failed to remove network {ssid}")

  def is_tethering_active(self) -> bool:
    return self._tethering_active

  def is_connection_saved(self, ssid: str) -> bool:
    return self._store.contains(ssid)

  def set_tethering_password(self, password: str):
    def worker():
      self._tethering_psk = password
      with atomic_write(TETHERING_PASSWORD_FILE, overwrite=True) as f:
        f.write(password)
      if self._tethering_active:
        # Restart tethering with new password. _stop_tethering clears
        # _tethering_active, and _start_tethering doesn't set it back — so
        # we re-assert the flag before the restart to keep UI/backend
        # state in sync (otherwise is_tethering_active() reports False
        # while the hotspot is still running). Mirror set_tethering_active's
        # rollback on bringup failure so a wedged AP doesn't leave the flag
        # stuck True (which would block scan/reconcile loops).
        self._stop_tethering()
        self._tethering_active = True
        try:
          self._start_tethering()
        except Exception:
          cloudlog.exception("Failed to restart tethering after password change")
          try:
            self._stop_tethering()
          except Exception:
            cloudlog.exception("Tethering rollback also failed")
            self._tethering_active = False
            self._wifi_state = WifiState()
            self._enqueue_callbacks(self._disconnected)
    threading.Thread(target=worker, daemon=True).start()

  def set_ipv4_forward(self, enabled: bool):
    self._ipv4_forward = enabled

  def set_tethering_active(self, active: bool):
    # On enable, assert the flag synchronously so scan/reconcile and
    # station-connect UI paths see "tethering is in progress" from the
    # first instant. On disable, leave the flag True until _stop_tethering
    # has actually switched _ctrl back to STA mode — otherwise a user
    # tapping a network immediately after hitting the toggle could race
    # the teardown and send ADD_NETWORK/SELECT_NETWORK to the AP daemon.
    if active:
      self._tethering_active = True
    def worker():
      if active:
        try:
          self._start_tethering()
          if not self._ipv4_forward:
            time.sleep(5)
            cloudlog.warning("net.ipv4.ip_forward = 0")
            subprocess.run(["sudo", "sysctl", "net.ipv4.ip_forward=0"], check=False)
        except Exception:
          cloudlog.exception("Failed to start tethering, rolling back")
          try:
            # _stop_tethering cleans up dnsmasq, iptables, AP wpa_supplicant,
            # restarts STA wpa_supplicant, and resets state. Safe to call on
            # a partial bringup.
            self._stop_tethering()
          except Exception:
            cloudlog.exception("Tethering rollback also failed")
            self._tethering_active = False
            self._wifi_state = WifiState()
            self._enqueue_callbacks(self._disconnected)
      else:
        try:
          self._stop_tethering()
        except Exception:
          cloudlog.exception("Failed to stop tethering")
          # Force-clear the flag even if teardown failed so the UI isn't
          # wedged reporting tethering active forever.
          self._tethering_active = False
    threading.Thread(target=worker, daemon=True).start()

  def _start_tethering(self):
    # TODO: tethering is currently a kill-and-respawn: kill our STA daemon,
    # spawn a second daemon with an AP-mode config. That's incompatible
    # with a system-managed wpa_supplicant (we can't kill it, and we can't
    # run two daemons on one interface). The clean model is to keep one
    # daemon and flip networks: ADD_NETWORK with mode=2/frequency=2437,
    # DISABLE_NETWORK all the STA networks, ENABLE_NETWORK the AP one.
    # _stop_tethering becomes the reverse. Needed before we can run under
    # a systemd-managed wpa_supplicant on tici.
    self._set_connecting(self._tethering_ssid)

    psk = self._tethering_psk

    # Close existing control socket
    if self._ctrl:
      self._ctrl.close()
      self._ctrl = None

    # Stop STA wpa_supplicant (only the one running our config — never touch a
    # system-managed daemon on another interface or config).
    self._monitor_epoch += 1
    _pkill_wpa_supplicant(WPA_SUPPLICANT_CONF)
    self._dhcp.stop()
    time.sleep(0.5)

    # Write AP config
    safe_tether_ssid = _sanitize_for_conf(self._tethering_ssid)
    lines = ["ctrl_interface=/var/run/wpa_supplicant", "ap_scan=2", "",
             "network={", f'  ssid="{safe_tether_ssid}"', "  mode=2",
             "  frequency=2437", "  key_mgmt=WPA-PSK", f'  psk={_format_psk_value(psk)}', "}", ""]
    ap_conf = "\n".join(lines)
    fd = os.open(WPA_AP_CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
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
    self._dnsmasq_proc = subprocess.Popen([
      "sudo", "dnsmasq",
      "--interface=wlan0",
      "--bind-interfaces",
      "--dhcp-range=192.168.43.2,192.168.43.254,24h",
      "--dhcp-leasefile=/tmp/dnsmasq.leases",
      "--no-daemon", "--log-queries",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
      start_new_session=True)

    # NAT: MASQUERADE traffic from the tethering subnet regardless of
    # which uplink has the default route. Source-subnet matching (no
    # `-o <iface>`) survives a mid-session uplink change — unplugging
    # ETH, pulling the SIM, 3G→4G, rmnet_data0 rename — without any
    # watchdog logic, because the rule describes *our* network, not
    # whichever interface happens to carry traffic out.
    # Flush any stale copies from previous sessions first (idempotent),
    # plus legacy `-o <iface>` rules from older openpilot versions that
    # bound MASQUERADE to a specific uplink.
    for _ in range(4):
      result = subprocess.run(_tethering_nat_rule("-D"), capture_output=True, check=False)
      if result.returncode != 0:
        break
    for iface in ("wwan0", "rmnet_data0", "eth0"):
      for _ in range(4):
        result = subprocess.run(["sudo", "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
                                capture_output=True, check=False)
        if result.returncode != 0:
          break
    subprocess.run(_tethering_nat_rule("-A"), check=False)
    if self._ipv4_forward:
      subprocess.run(["sudo", "sysctl", "net.ipv4.ip_forward=1"], check=False)

    # Reconnect control socket — doubles as a bringup check. A bare attach
    # isn't enough: a pre-existing STA daemon (system-managed, different
    # config path) can still own the ctrl socket even when our AP spawn
    # failed to take the interface. We also require STATUS to report
    # mode=AP, so a surviving STA daemon can't masquerade as our hotspot.
    try:
      ctrl = WpaCtrl()
      ctrl.open()
    except Exception as e:
      raise RuntimeError(f"AP wpa_supplicant bringup failed: {e}") from e
    try:
      status = parse_status(ctrl.request("STATUS"))
    except Exception as e:
      ctrl.close()
      raise RuntimeError(f"AP wpa_supplicant STATUS failed: {e}") from e
    if status.get("mode") != "AP":
      actual_mode = status.get("mode")
      ctrl.close()
      raise RuntimeError(f"AP wpa_supplicant bringup did not take over wlan0 (mode={actual_mode!r}); another daemon likely owns the interface")
    self._ctrl = ctrl

    self._wifi_state = WifiState(ssid=self._tethering_ssid, status=ConnectStatus.CONNECTED)
    self._ipv4_address = TETHERING_IP_ADDRESS
    self._enqueue_callbacks(self._activated)

  def _stop_tethering(self):
    # Kill dnsmasq
    subprocess.run(["sudo", "killall", "-q", "dnsmasq"], check=False)
    if self._dnsmasq_proc is not None:
      try:
        self._dnsmasq_proc.wait(timeout=3)
      except Exception:
        pass
      self._dnsmasq_proc = None

    # Remove NAT. Loop in case a prior start left duplicates.
    for _ in range(4):
      result = subprocess.run(_tethering_nat_rule("-D"), capture_output=True, check=False)
      if result.returncode != 0:
        break

    # Close control socket
    if self._ctrl:
      self._ctrl.close()
      self._ctrl = None

    # Stop AP wpa_supplicant (only the one running our AP config).
    self._monitor_epoch += 1
    _pkill_wpa_supplicant(WPA_AP_CONF)
    time.sleep(0.5)

    # Flush AP IP
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=False)

    # Restore STA. _ensure_wpa_supplicant attaches to our own daemon if
    # one survived _start_tethering, or unmanages NM and spawns a fresh
    # one. _generate_wpa_conf refreshes our config for the spawn path;
    # the attach path reuses the running daemon's existing config.
    _generate_wpa_conf(self._store)
    self._ensure_wpa_supplicant()

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
      if self._tethering_active:
        self._stop_tethering()
      if self._ctrl is not None:
        self._ctrl.close()
      self._dhcp.stop()
      self._gsm.close()
