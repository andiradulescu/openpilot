import ast
import csv
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from opendbc.can import CANPacker
from openpilot.selfdrive.car.vw_eps_diagnostics import (EpsDiagnostics, TraceWriter, TIMEOUT_NS, PENDING_TIMEOUT_NS,
                                                          configure_probe_capability)


class MemoryWriter:
  def __init__(self):
    self.healthy = True
    self.rows = []
    self.error = ""
    self.stop_event = threading.Event()

  def emit(self, mono_ns, event, request_id="", did="", address="", bus="", value="", data=""):
    self.rows.append((mono_ns, event, request_id, did, address, bus, value, data))
    return self.healthy


def response(did, value):
  payload = b"\x62" + did.to_bytes(2, "big") + value
  return bytes((len(payload),)) + payload + bytes(7 - len(payload))


class TestEpsDiagnostics(unittest.TestCase):
  def setUp(self):
    self.writer = MemoryWriter()
    self.diag = EpsDiagnostics(self.writer)
    self.packer = CANPacker("vw_mqb")

  def receive(self, ns, data, bus=1):
    self.diag.observe_can([(ns, [(0x77C, data, bus)])])

  def test_only_exact_reads_and_one_outstanding(self):
    self.assertEqual(self.diag.requests(0, True), [(0x712, bytes.fromhex("0322180b00000000"), 1)])
    self.assertEqual(self.diag.requests(200_000_000, True), [])
    self.receive(220_000_000, response(0x180B, b"\x01\x2c"))
    self.assertEqual(self.diag.requests(230_000_000, True), [(0x712, bytes.fromhex("0322182300000000"), 1)])

  def test_rate_bound_uses_time_not_loop_count(self):
    self.diag.requests(0, True)
    self.receive(10, response(0x180B, b"\x01\x2c"))
    self.assertEqual(self.diag.requests(199_999_999, True), [])
    self.assertEqual(len(self.diag.requests(200_000_000, True)), 1)

  def test_raw_residual_bytes_not_a_guessed_reason(self):
    self.diag.index = 1
    self.diag.requests(0, True)
    self.receive(10, response(0x1823, bytes.fromhex("00e3012c")))
    row = self.writer.rows[-1]
    self.assertEqual(row[1:4], ("did", 1, "1823"))
    self.assertEqual(row[-1], "00e3012c")
    self.assertEqual(row[-2], 10)

  def test_delayed_nrc_remains_with_outstanding_did(self):
    self.diag.requests(0, True)
    self.assertEqual(self.diag.requests(200_000_000, True), [])
    self.receive(250_000_000, bytes.fromhex("037f227e00000000"))
    self.assertEqual(self.writer.rows[-1][1:4], ("nrc", 1, "180B"))
    self.assertEqual(self.writer.rows[-1][-2], "7E")
    self.assertEqual(self.diag.requests(300_000_000, True)[0][1], bytes.fromhex("0322182300000000"))

  def test_timeout_stops_polling_and_late_nrc_is_unattributed(self):
    self.diag.requests(0, True)
    self.assertEqual(self.diag.requests(TIMEOUT_NS, True), [])
    self.assertFalse(self.diag.polling)
    self.receive(TIMEOUT_NS + 10, bytes.fromhex("037f223100000000"))
    self.assertEqual(self.writer.rows[-1][1], "unsolicited_response")
    self.assertEqual(self.writer.rows[-1][2:4], ("", ""))
    self.assertEqual(self.diag.requests(10_000_000_000, True), [])

  def test_late_response_expires_without_a_transmit_tick(self):
    self.diag.requests(100, True)
    self.receive(99, response(0x180B, b"\0\0"))
    self.assertIsNotNone(self.diag.pending)
    self.assertEqual(self.writer.rows[-1][1], "unsolicited_response")

  def test_pending_has_an_absolute_deadline(self):
    self.diag.requests(0, True)
    for ns in (100_000_000, 900_000_000, 1_900_000_000):
      self.receive(ns, bytes.fromhex("037f227800000000"))
      self.assertEqual(self.diag.pending.deadline_ns, PENDING_TIMEOUT_NS)
      self.assertEqual(self.diag.requests(ns, True), [])
    self.assertEqual(self.diag.requests(PENDING_TIMEOUT_NS, True), [])
    self.assertFalse(self.diag.polling)

  def test_bad_lengths_and_unexpected_payloads_stop_polling(self):
    for data in (b"", bytes.fromhex("0062180b012c0000"), bytes.fromhex("1062180b012c0000"),
                 bytes.fromhex("0862180b012c0000"), bytes.fromhex("0562180b"),
                 bytes.fromhex("0462180b01000000"), response(0x1823, b"\0\0\0\0"),
                 bytes.fromhex("027f220000000000")):
      with self.subTest(data=data.hex()):
        self.setUp()
        self.diag.requests(0, True)
        self.receive(1, data)
        self.assertFalse(self.diag.polling)
        self.assertFalse(any(r[1] == "did" for r in self.writer.rows))

  def test_wrong_bus_is_not_a_response(self):
    self.diag.requests(0, True)
    self.receive(1, response(0x180B, b"\0\0"), bus=0)
    self.assertIsNotNone(self.diag.pending)

  def test_response_older_than_request_is_unattributed(self):
    self.diag.requests(100, True)
    self.receive(99, response(0x180B, b"\0\0"))
    self.assertIsNotNone(self.diag.pending)
    self.assertEqual(self.writer.rows[-1][1], "unsolicited_response")

  def test_no_reads_without_writer_or_valid_can(self):
    self.assertEqual(self.diag.requests(0, False), [])
    self.writer.healthy = False
    self.assertEqual(self.diag.requests(0, True), [])
    self.writer.healthy = True
    self.diag.requests(0, True)
    self.assertEqual(self.diag.requests(1, False), [])
    self.assertFalse(self.diag.polling)

  def test_sink_failure_prevents_prepared_request_being_returned(self):
    self.writer.emit = lambda *args, **kwargs: False
    self.assertEqual(self.diag.requests(0, True), [])
    self.assertFalse(self.diag.polling)

  def test_packer_tuple_is_observed_without_mutation(self):
    msg = self.packer.make_can_msg("HCA_01", 0, {"HCA_01_LM_Offset": 150, "HCA_01_Sendestatus": 1})
    messages = [msg]
    self.diag.record_output(messages, 10)
    self.assertEqual(messages, [msg])
    self.assertEqual(self.writer.rows[-1][1], "hca_requested")
    self.assertEqual(self.writer.rows[-1][-2], 150)
    self.diag.observe_can([(20, [(msg[0], msg[1], 128)])])
    self.assertEqual(self.writer.rows[-1][1], "hca_tx_echo")
    self.assertEqual(self.writer.rows[-1][0], 20)

  def test_every_raw_status_transition_is_preserved(self):
    frames = [self.packer.make_can_msg("LH_EPS_03", 0, {"EPS_HCA_Status": s}) for s in (5, 4, 5)]
    self.diag.observe_can([(10, [frames[0]]), (20, frames[1:])])
    self.assertEqual([(r[0], r[-2]) for r in self.writer.rows], [(10, 5), (20, 4), (20, 5)])

  def test_request_echo_and_rejection_are_not_conflated(self):
    req = self.diag.requests(0, True)[0]
    self.diag.observe_can([(1, [(req[0], req[1], 129)])])
    self.assertEqual(self.writer.rows[-1][1:4], ("diag_tx_echo", 1, "180B"))
    self.diag.observe_can([(2, [(req[0], req[1], 193]])])
    self.assertEqual(self.writer.rows[-1][1], "diag_tx_rejected")
    self.assertFalse(self.diag.polling)

  def test_panda_counter_baseline_change_and_reset(self):
    state = SimpleNamespace(safetyTxBlocked=8)
    self.diag.observe_panda(0, [state])
    self.diag.requests(1, True)
    self.diag.observe_panda(2, [state])
    self.assertTrue(self.diag.polling)
    state.safetyTxBlocked = 0
    self.diag.observe_panda(3, [state])
    self.assertTrue(self.diag.polling)
    state.safetyTxBlocked = 1
    self.diag.observe_panda(4, [state])
    self.assertFalse(self.diag.polling)

  def test_nrc_does_not_trigger_session_change_or_retry_same_did(self):
    self.diag.requests(0, True)
    self.receive(1, bytes.fromhex("037f227e00000000"))
    req = self.diag.requests(200_000_000, True)
    self.assertEqual(req[0][1], bytes.fromhex("0322182300000000"))
    self.receive(200_000_001, bytes.fromhex("037f227e00000000"))
    self.assertEqual(self.diag.requests(400_000_000, True), [])
    self.assertFalse(self.diag.polling)


class TestTraceWriter(unittest.TestCase):
  def test_opt_in_absent_creates_no_file(self):
    with TemporaryDirectory() as tmp:
      w = TraceWriter(Path(tmp) / "trace", Path(tmp) / "enabled")
      w.start()
      w.thread.join(2)
      self.assertFalse(w.healthy)
      self.assertFalse((Path(tmp) / "trace").exists())

  def test_worker_writes_and_flushes_tail(self):
    with TemporaryDirectory() as tmp:
      enabled = Path(tmp) / "enabled"
      enabled.touch()
      w = TraceWriter(Path(tmp) / "trace", enabled)
      w.start()
      deadline = time.monotonic() + 2
      while not w.healthy and not w.error and time.monotonic() < deadline:
        time.sleep(0.01)
      self.assertTrue(w.healthy, w.error)
      self.assertTrue(w.emit(123, "did", did="180B", data="0000"))
      w.close()
      with w.path.open() as f:
        rows = list(csv.DictReader(f))
      self.assertEqual(rows[-1]["mono_time_ns"], "123")
      self.assertEqual(rows[-1]["data"], "0000")

  def test_open_failure_disables_writer(self):
    with TemporaryDirectory() as tmp:
      enabled = Path(tmp) / "enabled"
      enabled.touch()
      w = TraceWriter(Path(tmp) / "trace", enabled)
      with patch.object(Path, "open", side_effect=OSError("disk unavailable")):
        w._run()
      self.assertFalse(w.healthy)
      self.assertIn("disk unavailable", w.error)
      self.assertFalse(w.emit(1, "test"))

  def test_write_failure_after_open_disables_writer(self):
    with TemporaryDirectory() as tmp:
      enabled = Path(tmp) / "enabled"
      enabled.touch()
      w = TraceWriter(Path(tmp) / "trace", enabled)
      with patch("csv.writer") as mock:
        mock.return_value.writerow.side_effect = OSError("disk full")
        w._run()
      self.assertFalse(w.healthy)
      self.assertIn("disk full", w.error)

  def test_full_queue_and_stalled_writer_prevent_reads(self):
    w = TraceWriter()
    w.ready = True
    w.heartbeat_ns = time.monotonic_ns()
    for _ in range(w.rows.maxsize):
      w.rows.put_nowait(())
    self.assertFalse(w.emit(1, "test"))
    self.assertIn("queue_full", w.error)
    self.assertEqual(EpsDiagnostics(w).requests(1, True), [])
    w.error = ""
    w.heartbeat_ns = time.monotonic_ns() - 3_000_000_000
    self.assertFalse(w.healthy)
    self.assertEqual(EpsDiagnostics(w).requests(1, True), [])

  def test_size_limit_retains_file_and_stops_polling(self):
    with TemporaryDirectory() as tmp:
      enabled = Path(tmp) / "enabled"
      enabled.touch()
      w = TraceWriter(Path(tmp) / "trace", enabled, max_bytes=1)
      w.start()
      w.thread.join(2)
      self.assertIn("size_limit", w.error)
      self.assertTrue(w.path.is_file())
      self.assertEqual(EpsDiagnostics(w).requests(1, True), [])


class TestProbeCapability(unittest.TestCase):
  def test_requires_both_persistent_opt_ins_and_clears_stale_arm(self):
    with TemporaryDirectory() as tmp:
      tmp = Path(tmp)
      diag = tmp / "diag"
      probe = tmp / "probe"
      arm = tmp / "arm"
      arm.write_text("320")
      cfg = SimpleNamespace(safetyModel=7, safetyParam=0)
      cp = SimpleNamespace(safetyConfigs=[cfg])
      self.assertFalse(configure_probe_capability(cp, 7, diag, probe, arm))
      self.assertEqual(0, cfg.safetyParam)
      diag.touch(); probe.touch()
      self.assertTrue(configure_probe_capability(cp, 7, diag, probe, arm))
      self.assertEqual(4, cfg.safetyParam)
      self.assertFalse(arm.exists())

  def test_wrong_safety_model_is_not_enabled(self):
    with TemporaryDirectory() as tmp:
      tmp = Path(tmp)
      diag = tmp / "diag"; probe = tmp / "probe"; arm = tmp / "arm"
      diag.touch(); probe.touch()
      cfg = SimpleNamespace(safetyModel=8, safetyParam=0)
      cp = SimpleNamespace(safetyConfigs=[cfg])
      self.assertFalse(configure_probe_capability(cp, 7, diag, probe, arm))
      self.assertEqual(0, cfg.safetyParam)


class TestProbeReadiness(unittest.TestCase):
  def setUp(self):
    self.writer = MemoryWriter()
    self.diag = EpsDiagnostics(self.writer)

  def test_requires_recent_status_and_both_dids(self):
    now = 3_000_000_000
    self.assertFalse(self.diag.probe_ready(now))
    self.diag.last_eps_status_ns = now - 1
    self.assertFalse(self.diag.probe_ready(now))
    self.diag.last_did_success[0x180B] = now - 1
    self.assertFalse(self.diag.probe_ready(now))
    self.diag.last_did_success[0x1823] = now - 1
    self.assertTrue(self.diag.probe_ready(now))

  def test_stale_inputs_or_logger_error_disarm(self):
    now = 3_000_000_000
    self.diag.last_eps_status_ns = now - 1
    self.diag.last_did_success = {0x180B: now - 1, 0x1823: now - 1}
    self.assertTrue(self.diag.probe_ready(now))
    self.diag.last_eps_status_ns = now - 600_000_000
    self.assertFalse(self.diag.probe_ready(now))
    self.diag.last_eps_status_ns = now - 1
    self.writer.healthy = False
    self.assertFalse(self.diag.probe_ready(now))

  def test_probe_state_is_logged_only_on_change(self):
    self.diag.observe_probe(1, False, False, 0, False)
    self.diag.observe_probe(2, False, False, 0, False)
    self.diag.observe_probe(3, True, False, 1, True)
    rows = [r for r in self.writer.rows if r[1] == "probe_state"]
    self.assertEqual(2, len(rows))



class TestCardInstrumentationIsolation(unittest.TestCase):
  """Run the actual card control/exception-boundary methods without native messaging libraries."""
  def test_logging_exception_does_not_suppress_normal_sendcan(self):
    source = Path(__file__).parents[1] / "card.py"
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Car")
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in ("_eps_diagnostic_call", "controls_update")]
    cls.bases = []
    tree.body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), cls]
    ast.fix_missing_locations(tree)
    namespace = {"time": time, "REPLAY": False, "can_list_to_can_capnp": lambda messages, **kw: messages}
    exec(compile(tree, str(source), "exec"), namespace)
    c = namespace["Car"]()
    c.initialized_prev = True
    c.sm = SimpleNamespace(all_alive=lambda names: True)
    msg = CANPacker("vw_mqb").make_can_msg("HCA_01", 0, {"HCA_01_LM_Offset": 100})
    c.CI = SimpleNamespace(apply=lambda cc, ns: ("actuators", [msg]), CC=None)
    c.hca_probe_capable = False
    c.hca_probe_requested = False
    c.hca_probe_disarm_requested = False
    c.hca_probe_status_baseline = None
    sent = []
    c.pm = SimpleNamespace(send=lambda service, value: sent.append((service, value)))
    c.eps_diag = EpsDiagnostics(MemoryWriter())
    with patch.object(c.eps_diag, "record_output", side_effect=RuntimeError("trace failed")):
      c.controls_update(SimpleNamespace(canValid=True), SimpleNamespace())
    self.assertIsNone(c.eps_diag)
    self.assertEqual(sent, [("sendcan", [msg])])
    self.assertEqual(c.last_actuators_output, "actuators")

  def test_status_change_disarms_before_apply(self):
    source = Path(__file__).parents[1] / "card.py"
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Car")
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in ("_eps_diagnostic_call", "controls_update")]
    cls.bases = []
    tree.body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), cls]
    ast.fix_missing_locations(tree)
    namespace = {"time": time, "REPLAY": False, "can_list_to_can_capnp": lambda messages, **kw: messages}
    exec(compile(tree, str(source), "exec"), namespace)
    c = namespace["Car"]()
    c.initialized_prev = True
    c.sm = SimpleNamespace(all_alive=lambda names: True)
    c.hca_probe_capable = True
    c.hca_probe_requested = True
    c.hca_probe_disarm_requested = False
    c.hca_probe_status_baseline = 5
    probe = SimpleNamespace(active=True, done=False, frames=1)
    controller = SimpleNamespace(hca_probe_armed=True, hca_probe=probe)
    observed = []
    msg = CANPacker("vw_mqb").make_can_msg("HCA_01", 0, {"HCA_01_LM_Offset": 100})
    c.CI = SimpleNamespace(CC=controller, apply=lambda cc, ns: (observed.append(controller.hca_probe_armed) or "actuators", [msg]))
    c.eps_diag = SimpleNamespace(probe_ready=lambda now: True, last_eps_status=4,
                                 observe_probe=lambda *args: None, record_output=lambda *args: None, requests=lambda *args: [],
                                 disable=lambda reason: None, writer=SimpleNamespace(error="", stop_event=threading.Event()))
    c.pm = SimpleNamespace(send=lambda *args: None)
    c.controls_update(SimpleNamespace(canValid=True), SimpleNamespace())
    self.assertEqual([False], observed)
    self.assertTrue(c.hca_probe_disarm_requested)

  def test_diagnostics_health_loss_disarms_before_apply(self):
    source = Path(__file__).parents[1] / "card.py"
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Car")
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in ("_eps_diagnostic_call", "controls_update")]
    cls.bases = []
    tree.body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), cls]
    ast.fix_missing_locations(tree)
    namespace = {"time": time, "REPLAY": False, "can_list_to_can_capnp": lambda messages, **kw: messages}
    exec(compile(tree, str(source), "exec"), namespace)
    c = namespace["Car"]()
    c.initialized_prev = True
    c.sm = SimpleNamespace(all_alive=lambda names: True)
    c.hca_probe_capable = True
    c.hca_probe_requested = True
    c.hca_probe_disarm_requested = False
    c.hca_probe_status_baseline = 5
    probe = SimpleNamespace(active=False, done=False, frames=0)
    controller = SimpleNamespace(hca_probe_armed=True, hca_probe=probe)
    observed = []
    msg = CANPacker("vw_mqb").make_can_msg("HCA_01", 0, {"HCA_01_LM_Offset": 100})
    c.CI = SimpleNamespace(CC=controller, apply=lambda cc, ns: (observed.append(controller.hca_probe_armed) or "actuators", [msg]))
    c.eps_diag = SimpleNamespace(probe_ready=lambda now: False, last_eps_status=5,
                                 observe_probe=lambda *args: None, record_output=lambda *args: None, requests=lambda *args: [],
                                 disable=lambda reason: None, writer=SimpleNamespace(error="", stop_event=threading.Event()))
    c.pm = SimpleNamespace(send=lambda *args: None)
    c.controls_update(SimpleNamespace(canValid=True), SimpleNamespace())
    self.assertEqual([False], observed)
    self.assertTrue(c.hca_probe_disarm_requested)


if __name__ == "__main__":
  unittest.main()
