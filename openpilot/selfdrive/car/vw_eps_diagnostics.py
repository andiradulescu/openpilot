"""Read-only MQB EPS diagnostics. This module never constructs steering commands."""
import csv
import os
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

EPS_TX = 0x712
EPS_RX = 0x77C
DIAG_BUS = 1
DIDS = (0x180B, 0x1823)
PAYLOAD_LENGTHS = {0x180B: 5, 0x1823: 7}  # Includes 62 + DID, excludes ISO-TP PCI.
PERIOD_NS = 200_000_000  # At most five requests/second total.
TIMEOUT_NS = 500_000_000
PENDING_TIMEOUT_NS = 2_000_000_000
WRITER_TIMEOUT_NS = 2_000_000_000
ENABLE_FILE = Path("/data/hca_eps_diag_enabled")
PROBE_ENABLE_FILE = Path("/data/hca_eps_probe_enabled")
PROBE_ARM_FILE = Path("/tmp/hca_eps_probe_arm")
PROBE_ARM_VALUE = "320"
PROBE_SAFETY_PARAM = 4
PROBE_RECENT_DID_NS = 2_000_000_000
PROBE_RECENT_STATUS_NS = 500_000_000
TRACE_DIR = Path("/data/hca_eps_trace")
HEADER = ("wall_time_ns", "mono_time_ns", "event", "request_id", "did", "address", "bus", "value", "data")


def configure_probe_capability(cp, volkswagen_safety_model, diag_enable=ENABLE_FILE, probe_enable=PROBE_ENABLE_FILE, arm_file=PROBE_ARM_FILE):
  """Enable the Panda probe capability only after an explicit persistent opt-in; clear stale one-shot arms."""
  if not diag_enable.is_file() or not probe_enable.is_file():
    return False
  configs = [c for c in cp.safetyConfigs if c.safetyModel == volkswagen_safety_model]
  if not configs:
    return False
  try:
    arm_file.unlink(missing_ok=True)
  except OSError:
    return False
  for config in configs:
    config.safetyParam |= PROBE_SAFETY_PARAM
  return True


class TraceWriter:
  """Bounded, nonblocking producer; all filesystem work happens in the daemon thread."""
  def __init__(self, directory=TRACE_DIR, enable_file=ENABLE_FILE, max_bytes=64 * 1024 * 1024):
    self.directory, self.enable_file, self.max_bytes = directory, enable_file, max_bytes
    self.rows = queue.Queue(maxsize=4096)
    self.ready = False
    self.heartbeat_ns = 0
    self.error = ""
    self.path = None
    self.stop_event = threading.Event()
    self.thread = threading.Thread(target=self._run, name="vw_eps_trace", daemon=True)

  def start(self):
    self.thread.start()

  @property
  def healthy(self):
    return self.ready and not self.error and time.monotonic_ns() - self.heartbeat_ns < WRITER_TIMEOUT_NS

  def emit(self, mono_ns, event, request_id="", did="", address="", bus="", value="", data=""):
    if not self.healthy:
      return False
    try:
      self.rows.put_nowait((time.time_ns(), mono_ns, event, request_id, did, address, bus, value, data))
    except queue.Full:
      self.error = "trace_queue_full; recording incomplete"
      return False
    return True

  def _run(self):
    try:
      # Do not inherit card's realtime scheduling policy for disk I/O.
      if hasattr(os, "sched_setscheduler"):
        os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0))
      if not self.enable_file.is_file():
        return
      self.directory.mkdir(parents=True, exist_ok=True)
      self.path = self.directory / f"{time.time_ns()}-{os.getpid()}.csv"
      with self.path.open("x", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        f.flush()
        self.heartbeat_ns = time.monotonic_ns()
        self.ready = True
        while not self.stop_event.is_set() and not self.error:
          # Bound each drain; periodically flush even under a continuous producer.
          for _ in range(256):
            try:
              row = self.rows.get_nowait()
            except queue.Empty:
              break
            writer.writerow(row)
          f.flush()
          if f.tell() >= self.max_bytes:
            self.error = "trace_size_limit; recording incomplete"
            break
          self.heartbeat_ns = time.monotonic_ns()
          self.stop_event.wait(0.1)
        # Normal shutdown: preserve the tail. Error shutdown is explicitly incomplete.
        if not self.error:
          while not self.rows.empty():
            writer.writerow(self.rows.get_nowait())
          f.flush()
    except Exception as exc:
      self.error = f"trace_writer_failed: {type(exc).__name__}: {exc}"
    finally:
      self.ready = False
      if self.error:
        print(f"VW EPS diagnostics stopped: {self.error}", flush=True)

  def close(self):
    self.stop_event.set()
    if self.thread.ident is not None:
      self.thread.join(timeout=0.2)  # A blocked filesystem must not hold up card shutdown.


@dataclass
class PendingRead:
  request_id: int
  did: int
  requested_ns: int
  deadline_ns: int
  data: bytes


class EpsDiagnostics:
  def __init__(self, writer):
    self.writer = writer
    self.pending = None
    self.next_request_ns = 0
    self.index = 0
    self.sequence = 0
    self.unsupported = set()
    self.polling = True
    self.error = ""
    self.panda_blocked = {}
    self.last_did_success = {}
    self.last_eps_status_ns = 0
    self.last_eps_status = None
    self.probe_state = None

  def disable(self, reason):
    self.polling = False
    self.pending = None
    self.error = reason

  def _emit(self, *args, **kwargs):
    if not self.writer.emit(*args, **kwargs):
      self.disable("trace_unavailble")

  def _stop(self, now_ns, reason):
    self._emit(now_ns, "diagnostics_stopped", value=reason)
    self.disable(reason)

  def _expire(self, now_ns):
    if self.pending is not None and now_ns >= self.pending.deadline_ns:
      p = self.pending
      self._emit(now_ns, "timeout", p.request_id, f"{p.did:04X}", value=now_ns - p.requested_ns)
      # Never attribute a late NRC to a later DID. Restart is required after a timeout.
      self.disable("response_timeout")

  def requests(self, now_ns, can_valid):
    if not self.polling or not self.writer.healthy:
      return []
    self._expire(now_ns)
    if not can_valid:
      if self.pending is not None:
        self._stop(now_ns, "can_invalid")
      return []
    if not self.polling or self.pending is not None or now_ns < self.next_request_ns:
      return []
    for _ in DIDS:
      did = DIDS[self.index]
      self.index = (self.index + 1) % len(DIDS)
      if did not in self.unsupported:
        break
    else:
      self._stop(now_ns, "no_supported_dids")
      return []
    self.sequence += 1
    data = bytes((3, 0x22, did >> 8, did & 0xFF, 0, 0, 0, 0))
    self.pending = PendingRead(self.sequence, did, now_ns, now_ns + TIMEOUT_NS, data)
    self.next_request_ns = now_ns + PERIOD_NS
    self._emit(now_ns, "diag_request", self.sequence, f"{did:04X}", f"{EPS_TX:03X}", DIAG_BUS, data=data.hex())
    return [(EPS_TX, data, DIAG_BUS)] if self.polling and self.writer.healthy else []

  def observe_can(self, can_list):
    if not self.writer.healthy:
      return
    for mono_ns, frames in can_list:
      for addr, data, src in frames:
        # Decode each raw frame at its own batch timestamp, not the final CarState snapshot.
        if addr == 0x09F and src == 0 and len(data) == 8:
          self.last_eps_status_ns = mono_ns
          self.last_eps_status = data[4] & 0x0F
          self._emit(mono_ns, "eps_status", address="09F", bus=src, value=self.last_eps_status, data=data.hex())
        elif addr == 0x126 and src in (0, 128, 192) and len(data) == 8:
          event = {0: "hca_rx", 128: "hca_tx_echo", 192: "hca_tx_rejected"}[src]
          self._emit(mono_ns, event, address="126", bus=src, value=hca_torque(data), data=data.hex())
        elif addr == EPS_TX. and src == DIAG_BUS + 128:
          p = self.pending
          matched = p is not None and data == p.data and mono_ns >= p.requested_ns
          self._emit(mono_ns, "diag_tx_echo", p.request_id if matched else "", f"{p.did:04X}" if matched else "",
                     f"{addr:03X}", src, data=data.hex())
        elif addr == EPS_TX and src == DIAG_BUS + 192:
          self._emit(mono_ns, "diag_tx_rejected", address=f"{addr:03X}", bus=src, data=data.hex())
          self.disable("panda_rejected_diagnostic")
        elif addr == EPS_RX and src == DIAG_BUS:
          self._response(mono_ns, data)

  def _response(self, mono_ns, data):
    self._expire(mono_ns)
    p = self.pending
    if p is None or mono_ns < p.requested_ns:
      self._emit(mono_ns, "unsolicited_response", address=f"{EPS_RX:03X}", bus=DIAG_BUS, data=data.hex())
      return
    if not 2 <= len(data) <= 8 or not 1 <= data[0] <= 7 or data[0] >= len(data):
      self._emit(mono_ns, "malformed_response", p.request_id, f"{p.did:04X}", data=data.hex())
      self.disable("invalid_isotp_single_frame")
      return
    payload = data[1:1 + data[0]]
    if payload[:2] == b"\x7f\x22" and len(payload) == 3:
      nrc = payload[2]
      self._emit(mono_ns, "nrc", p.request_id, f"{p.did:04X}", value=f"{nrc:02X}", data=data.hex())
      if nrc == 0x78:
        p.deadline_ns = p.requested_ns + PENDING_TIMEOUT_NS  # Absolute, never indefinitely extended.
      else:
        self.unsupported.add(p.did)
        self.pending = None
      return
    if payload[:3] != bytes((0x62, p.did >> 8, p.did & 0xFF)) or len(payload) != PAYLOAD_LENGTHS[p.did]:
      self._emit(mono_ns, "unexpected_response", p.request_id, f"{p.did:04X}", data=data.hex())
      self.disable("unexpected_uds_payload")
      return
    self._emit(mono_ns, "did", p.request_id, f"{p.did:04X}", f"{EPS_RX:03X}", DIAG_BUS,
               value=mono_ns - p.requested_ns, data=payload[3:].hex())
    self.last_did_success[p.did] = mono_ns
    self.pending = None

  def probe_ready(self, now_ns):
    if not self.polling or not self.writer.healthy or self.error:
      return False
    if not self.last_eps_status_ns or now_ns - self.last_eps_status_ns > PROBE_RECENT_STATUS_NS:
      return False
    return all(did in self.last_did_success and now_ns - self.last_did_success[did] <= PROBE_RECENT_DID_NS for did in DIDS)

  def observe_probe(self, mono_ns, active, done, frames, armed):
    state = (bool(active), bool(done), int(frames), bool(armed))
    if state != self.probe_state:
      self._emit(mono_ns, "probe_state", value=f"active={int(active)};done={int(done)};frames={frames};armed={int(armed)}")
      self.probe_state = state

  def record_output(self, can_sends, mono_ns):
    if not self.writer.healthy:
      return
    for addr, data, src in can_sends:  # CANPacker returns tuples; CanData also supports unpacking.
      if addr == 0x126 and src == 0 and len(data) == 8:
        self._emit(mono_ns, "hca_requested", address="126", bus=src, value=hca_torque(data), data=data.hex())

  def observe_panda(self, mono_ns, states):
    if not self.writer.healthy:
      return
    for i, state in enumerate(states):
      count = int(state.safetyTxBlocked)
      previous = self.panda_blocked.get(i)
      if count != previous:
        self._emit(mono_ns, "safety_tx_blocked", bus=i, value=count)
      self.panda_blocked[i] = count
      if previous is not None and count > previous and self.pending is not None:
        self._stop(mono_ns, "panda_tx_blocked_during_read")


def hca_torque(data):
  magnitude = data[2] | ((data[3] & 1) << 8)
  return -magnitude if data[3] & 0x80 else magnitude
