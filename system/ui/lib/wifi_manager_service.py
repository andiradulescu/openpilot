import atexit
import json
import os
import socket
import socketserver
import threading
import time
from collections import deque
from collections.abc import Callable

from openpilot.common.swaglog import cloudlog
from openpilot.system.ui.lib.wifi_manager import ConnectStatus, MeteredType, Network, SecurityType, WifiManager as WifiManagerBackend, WifiState, sort_networks

WIFI_MANAGER_SOCKET = "/tmp/wifi_manager.sock"
WIFI_MANAGER_POLL_SECONDS = 0.5
WIFI_MANAGER_DAEMON_WAIT_SECONDS = 5.0
WIFI_MANAGER_EVENT_HISTORY = 256


def _serialize_network(network: Network) -> dict[str, int | str | bool]:
  return {
    "ssid": network.ssid,
    "strength": network.strength,
    "security_type": int(network.security_type),
    "is_tethering": network.is_tethering,
  }


def _deserialize_network(payload: dict) -> Network:
  return Network(
    ssid=str(payload["ssid"]),
    strength=int(payload["strength"]),
    security_type=SecurityType(int(payload["security_type"])),
    is_tethering=bool(payload["is_tethering"]),
  )


def _serialize_snapshot(manager: WifiManagerBackend) -> dict:
  return {
    "networks": [_serialize_network(n) for n in manager.networks],
    "saved_ssids": sorted(manager._store.saved_ssids()),
    "wifi_state": {
      "ssid": manager.wifi_state.ssid,
      "status": int(manager.wifi_state.status),
    },
    "ipv4_address": manager.ipv4_address,
    "current_network_metered": int(manager.current_network_metered),
    "tethering_active": manager.is_tethering_active(),
    "tethering_password": manager.tethering_password,
  }


def _deserialize_snapshot(snapshot: dict) -> dict:
  wifi_state = snapshot.get("wifi_state", {})
  return {
    "networks": [_deserialize_network(n) for n in snapshot.get("networks", [])],
    "saved_ssids": set(snapshot.get("saved_ssids", [])),
    "wifi_state": WifiState(
      ssid=wifi_state.get("ssid"),
      status=ConnectStatus(int(wifi_state.get("status", ConnectStatus.DISCONNECTED))),
    ),
    "ipv4_address": str(snapshot.get("ipv4_address", "")),
    "current_network_metered": MeteredType(int(snapshot.get("current_network_metered", MeteredType.UNKNOWN))),
    "tethering_active": bool(snapshot.get("tethering_active", False)),
    "tethering_password": str(snapshot.get("tethering_password", "")),
  }


class _EventBroker:
  def __init__(self):
    self._events: deque[dict] = deque(maxlen=WIFI_MANAGER_EVENT_HISTORY)
    self._seq = 0
    self._lock = threading.Lock()

  def push(self, event_type: str, **payload):
    with self._lock:
      self._seq += 1
      self._events.append({
        "seq": self._seq,
        "type": event_type,
        "payload": payload,
      })

  def since(self, seq: int) -> list[dict]:
    with self._lock:
      return [dict(event) for event in self._events if event["seq"] > seq]


class _WifiRPCServer(socketserver.ThreadingUnixStreamServer):
  def __init__(self, manager: WifiManagerBackend, broker: _EventBroker):
    if os.path.exists(WIFI_MANAGER_SOCKET):
      # Check if another daemon is already listening before removing
      try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
          probe.settimeout(1.0)
          probe.connect(WIFI_MANAGER_SOCKET)
          raise RuntimeError("wifi manager daemon already running")
      except (ConnectionRefusedError, FileNotFoundError, OSError):
        os.unlink(WIFI_MANAGER_SOCKET)
    self.manager = manager
    self.broker = broker
    self._request_lock = threading.Lock()
    super().__init__(WIFI_MANAGER_SOCKET, _WifiRPCHandler)

  def dispatch(self, request: dict) -> dict:
    command = request.get("command")
    with self._request_lock:
      if command == "get_state":
        since_seq = int(request.get("since_seq", 0))
        return {
          "ok": True,
          "snapshot": _serialize_snapshot(self.manager),
          "events": self.broker.since(since_seq),
        }
      if command == "connect_to_network":
        self.manager.connect_to_network(str(request["ssid"]), str(request.get("password", "")), bool(request.get("hidden", False)))
        return {"ok": True}
      if command == "forget_connection":
        self.manager.forget_connection(str(request["ssid"]))
        return {"ok": True}
      if command == "activate_connection":
        self.manager.activate_connection(str(request["ssid"]))
        return {"ok": True}
      if command == "set_tethering_password":
        self.manager.set_tethering_password(str(request["password"]))
        return {"ok": True}
      if command == "set_ipv4_forward":
        self.manager.set_ipv4_forward(bool(request["enabled"]))
        return {"ok": True}
      if command == "set_tethering_active":
        self.manager.set_tethering_active(bool(request["active"]))
        return {"ok": True}
      if command == "set_current_network_metered":
        self.manager.set_current_network_metered(MeteredType(int(request["metered"])))
        return {"ok": True}
      if command == "update_gsm_settings":
        self.manager.update_gsm_settings(bool(request["roaming"]), str(request.get("apn", "")), bool(request["metered"]))
        return {"ok": True}
    return {"ok": False, "error": f"unknown command: {command}"}


class _WifiRPCHandler(socketserver.StreamRequestHandler):
  def handle(self):
    raw = self.rfile.readline()
    if not raw:
      return
    try:
      request = json.loads(raw.decode())
      response = self.server.dispatch(request)
    except Exception as e:
      cloudlog.exception("wifi rpc handler failed")
      response = {"ok": False, "error": str(e)}
    self.wfile.write((json.dumps(response) + "\n").encode())
    self.wfile.flush()


def run_daemon():
  manager = WifiManagerBackend()
  broker = _EventBroker()
  stop_event = threading.Event()

  manager.add_callbacks(
    need_auth=lambda ssid: broker.push("need_auth", ssid=ssid),
    activated=lambda: broker.push("activated"),
    forgotten=lambda ssid: broker.push("forgotten", ssid=ssid),
    networks_updated=lambda networks: broker.push("networks_updated"),
    disconnected=lambda: broker.push("disconnected"),
  )

  def callback_pump():
    while not stop_event.is_set():
      manager.process_callbacks()
      time.sleep(0.05)

  pump_thread = threading.Thread(target=callback_pump, daemon=True)
  pump_thread.start()

  server = _WifiRPCServer(manager, broker)

  cloudlog.info("wifi_manager daemon started")
  try:
    server.serve_forever(poll_interval=0.5)
  finally:
    stop_event.set()
    server.server_close()
    manager.stop()
    if os.path.exists(WIFI_MANAGER_SOCKET):
      os.unlink(WIFI_MANAGER_SOCKET)


class WifiManagerClient:
  def __init__(self):
    self._exit = False
    self._callback_queue: list[Callable] = []
    self._callback_lock = threading.Lock()

    self._need_auth: list[Callable[[str], None]] = []
    self._activated: list[Callable[[], None]] = []
    self._forgotten: list[Callable[[str | None], None]] = []
    self._networks_updated: list[Callable[[list[Network]], None]] = []
    self._disconnected: list[Callable[[], None]] = []

    self._networks: list[Network] = []
    self._saved_ssids: set[str] = set()
    self._wifi_state = WifiState()
    self._ipv4_address = ""
    self._current_network_metered = MeteredType.UNKNOWN
    self._tethering_active = False
    self._tethering_pending = False
    self._tethering_pending_at: float = 0.0
    self._tethering_password = ""
    self._last_seq = 0

    self._wait_for_daemon()
    self._sync_state()

    self._poll_thread = threading.Thread(target=self._poll_state, daemon=True)
    self._poll_thread.start()
    atexit.register(self.stop)

  def _request(self, command: str, **payload) -> dict:
    message = {"command": command, **payload}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
      sock.settimeout(2.0)
      sock.connect(WIFI_MANAGER_SOCKET)
      sock.sendall((json.dumps(message) + "\n").encode())
      response = b""
      while not response.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
          break
        response += chunk
    if not response:
      raise RuntimeError("wifi manager daemon returned no response")
    decoded = json.loads(response.decode())
    if not decoded.get("ok", False):
      raise RuntimeError(decoded.get("error", "wifi manager daemon request failed"))
    return decoded

  def _can_connect(self) -> bool:
    if not os.path.exists(WIFI_MANAGER_SOCKET):
      return False
    try:
      self._request("get_state", since_seq=self._last_seq)
      return True
    except Exception:
      return False

  def _wait_for_daemon(self):
    """Wait for the manager-spawned wifi_manager daemon to be reachable."""
    deadline = time.monotonic() + WIFI_MANAGER_DAEMON_WAIT_SECONDS
    while time.monotonic() < deadline:
      if self._can_connect():
        return
      time.sleep(0.1)
    raise RuntimeError("wifi manager daemon not available")

  def _enqueue_callbacks(self, cbs: list[Callable], *args):
    with self._callback_lock:
      for cb in cbs:
        self._callback_queue.append(lambda _cb=cb: _cb(*args))

  def _apply_snapshot(self, snapshot: dict):
    state = _deserialize_snapshot(snapshot)
    previous_networks = self._networks
    previous_saved_ssids = self._saved_ssids
    previous_wifi_state = self._wifi_state

    self._networks = state["networks"]
    self._saved_ssids = state["saved_ssids"]
    self._wifi_state = state["wifi_state"]
    self._ipv4_address = state["ipv4_address"]
    self._current_network_metered = state["current_network_metered"]
    if self._tethering_pending:
      if state["tethering_active"] == self._tethering_active:
        self._tethering_pending = False
      elif time.monotonic() - self._tethering_pending_at > 10.0:
        self._tethering_pending = False
        self._tethering_active = state["tethering_active"]
    else:
      self._tethering_active = state["tethering_active"]
    self._tethering_password = state["tethering_password"]

    if previous_networks != self._networks or previous_saved_ssids != self._saved_ssids:
      self._enqueue_callbacks(self._networks_updated, self.networks)

    if previous_wifi_state != self._wifi_state:
      if self._wifi_state.status == ConnectStatus.CONNECTED and previous_wifi_state.status != ConnectStatus.CONNECTED:
        self._enqueue_callbacks(self._activated)
      elif self._wifi_state.status == ConnectStatus.DISCONNECTED and previous_wifi_state.status != ConnectStatus.DISCONNECTED:
        self._enqueue_callbacks(self._disconnected)

  def _apply_events(self, events: list[dict]):
    for event in events:
      self._last_seq = max(self._last_seq, int(event.get("seq", 0)))
      payload = event.get("payload", {})
      event_type = event.get("type")
      # need_auth and forgotten carry payload the snapshot can't express
      if event_type == "need_auth":
        ssid = payload.get("ssid")
        # Skip stale auth failures if snapshot already shows connected to this SSID
        if ssid is not None and not (self._wifi_state.status == ConnectStatus.CONNECTED and self._wifi_state.ssid == ssid):
          self._enqueue_callbacks(self._need_auth, ssid)
      elif event_type == "forgotten":
        self._enqueue_callbacks(self._forgotten, payload.get("ssid"))
      # activated, disconnected, networks_updated are handled by
      # _apply_snapshot state diff — skip here to avoid double-firing

  def _sync_state(self):
    response = self._request("get_state", since_seq=self._last_seq)
    self._apply_snapshot(response["snapshot"])
    self._apply_events(response.get("events", []))

  def _poll_state(self):
    while not self._exit:
      try:
        self._sync_state()
      except Exception:
        cloudlog.exception("wifi manager client poll failed")
        self._last_seq = 0
      time.sleep(WIFI_MANAGER_POLL_SECONDS)

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
    return sort_networks(self._networks, self._wifi_state.ssid, self._saved_ssids)

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
    return self._wifi_state.ssid if self._wifi_state.status == ConnectStatus.CONNECTING else None

  @property
  def connected_ssid(self) -> str | None:
    return self._wifi_state.ssid if self._wifi_state.status == ConnectStatus.CONNECTED else None

  @property
  def tethering_password(self) -> str:
    return self._tethering_password

  def process_callbacks(self):
    with self._callback_lock:
      to_run, self._callback_queue = self._callback_queue, []
    for cb in to_run:
      cb()

  def connect_to_network(self, ssid: str, password: str, hidden: bool = False):
    prev = self._wifi_state
    self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)
    try:
      self._request("connect_to_network", ssid=ssid, password=password, hidden=hidden)
    except Exception:
      self._wifi_state = prev
      raise

  def forget_connection(self, ssid: str):
    self._request("forget_connection", ssid=ssid)

  def activate_connection(self, ssid: str):
    prev = self._wifi_state
    self._wifi_state = WifiState(ssid=ssid, status=ConnectStatus.CONNECTING)
    try:
      self._request("activate_connection", ssid=ssid)
    except Exception:
      self._wifi_state = prev
      raise

  def is_tethering_active(self) -> bool:
    return self._tethering_active

  def is_connection_saved(self, ssid: str) -> bool:
    return ssid in self._saved_ssids

  def set_tethering_password(self, password: str):
    self._request("set_tethering_password", password=password)

  def set_ipv4_forward(self, enabled: bool):
    self._request("set_ipv4_forward", enabled=enabled)

  def set_tethering_active(self, active: bool):
    self._tethering_active = active
    self._tethering_pending = True
    self._tethering_pending_at = time.monotonic()
    self._request("set_tethering_active", active=active)

  def set_current_network_metered(self, metered: MeteredType):
    self._request("set_current_network_metered", metered=int(metered))

  def update_gsm_settings(self, roaming: bool, apn: str, metered: bool):
    self._request("update_gsm_settings", roaming=roaming, apn=apn, metered=metered)

  def stop(self):
    self._exit = True
    if hasattr(self, "_poll_thread") and self._poll_thread.is_alive():
      self._poll_thread.join(timeout=1.0)


def main():
  run_daemon()


if __name__ == "__main__":
  main()
