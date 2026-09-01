#!/usr/bin/env python3
import os
import time
import threading
from collections import deque

import openpilot.cereal.messaging as messaging

from openpilot.cereal import log
from opendbc.car.structs import car

from openpilot.common.params import Params
from openpilot.common.realtime import config_realtime_process, Priority, Ratekeeper
from openpilot.common.swaglog import cloudlog, ForwardingHandler

from opendbc.car import DT_CTRL, structs
from opendbc.car.can_definitions import CanData, CanRecvCallable, CanSendCallable
from opendbc.car.carlog import carlog
from opendbc.car.fw_versions import ObdCallback
from opendbc.car.car_helpers import get_car, interfaces
from opendbc.car.interfaces import CarInterfaceBase, RadarInterfaceBase
from openpilot.selfdrive.pandad import can_capnp_to_list, can_list_to_can_capnp
from openpilot.selfdrive.car.cruise import VCruiseHelper

REPLAY = "REPLAY" in os.environ

EventName = log.OnroadEvent.EventName

VW_HCA_TX = 0x126
VW_HCA_BUS = 0
VW_HCA_STOCK_MAX = 300
VW_HCA_TEST_MAX = 320
VW_HCA_TEST_RATE_UP = 4
VW_HCA_TEST_MIN_SPEED = 1.0
VW_HCA_TEST_MAX_SPEED = 10.0
VW_HCA_TEST_MAX_FRAMES = 10  # 200 ms at the 50 Hz HCA_01 send rate
VW_HCA_TEST_ARM_FILE = "/tmp/hca_limiter_test_arm"

VW_EPS_STATUS_RX = 0x09F
VW_EPS_STATUS_BUS = 0
VW_EPS_DIAG_TX = 0x712
VW_EPS_DIAG_RX = 0x77C
VW_EPS_DIAG_BUS = 1
VW_EPS_DIAG_DIDS = (0x180B, 0x1823)
VW_EPS_DIAG_PERIOD_FRAMES = 5  # 20 Hz total, 10 Hz per DID
VW_EPS_DIAG_LOG = "/data/hca_eps_trace.csv"

# forward
carlog.addHandler(ForwardingHandler(cloudlog))


def vw_hca_torque(dat: bytes) -> int:
  magnitude = dat[2] | ((dat[3] & 0x01) << 8)
  return -magnitude if dat[3] & 0x80 else magnitude


def vw_hca_with_torque(dat: bytes, torque: int) -> bytes:
  magnitude = abs(torque)
  ret = bytearray(dat)
  ret[2] = magnitude & 0xFF
  ret[3] = (ret[3] & 0x7E) | ((magnitude >> 8) & 0x01) | (0x80 if torque < 0 else 0)
  return bytes(ret)


def obd_callback(params: Params) -> ObdCallback:
  def set_obd_multiplexing(obd_multiplexing: bool):
    if params.get_bool("ObdMultiplexingEnabled") != obd_multiplexing:
      cloudlog.warning(f"Setting OBD multiplexing to {obd_multiplexing}")
      params.remove("ObdMultiplexingChanged")
      params.put_bool("ObdMultiplexingEnabled", obd_multiplexing, block=True)
      params.get_bool("ObdMultiplexingChanged", block=True)
      cloudlog.warning("OBD multiplexing set successfully")
  return set_obd_multiplexing


def can_comm_callbacks(logcan: messaging.SubSocket, sendcan: messaging.PubSocket) -> tuple[CanRecvCallable, CanSendCallable]:
  def can_recv(wait_for_one: bool = False) -> list[list[CanData]]:
    """
    wait_for_one: wait the normal logcan socket timeout for a CAN packet, may return empty list if nothing comes

    Returns: CAN packets comprised of CanData objects for easy access
    """
    ret = []
    for can in messaging.drain_sock(logcan, wait_for_one=wait_for_one):
      ret.append([CanData(msg.address, msg.dat, msg.src) for msg in can.can])
    return ret

  def can_send(msgs: list[CanData]) -> None:
    sendcan.send(can_list_to_can_capnp(msgs, msgtype='sendcan'))

  return can_recv, can_send


class Car:
  CI: CarInterfaceBase
  RI: RadarInterfaceBase
  CP: car.CarParams

  def __init__(self, CI=None, RI=None) -> None:
    self.can_sock = messaging.sub_sock('can', timeout=20)
    self.sm = messaging.SubMaster(['pandaStates', 'carControl', 'onroadEvents'])
    self.pm = messaging.PubMaster(['sendcan', 'carState', 'carParams', 'carOutput', 'radarTracks'])

    self.can_rcv_cum_timeout_counter = 0

    self.CC_prev = car.CarControl.new_message()
    self.CS_prev = car.CarState.new_message()
    self.initialized_prev = False

    self.last_actuators_output = structs.CarControl.Actuators()

    self.params = Params()

    self.can_callbacks = can_comm_callbacks(self.can_sock, self.pm.sock['sendcan'])

    is_release = self.params.get_bool("IsReleaseBranch")

    if CI is None:
      # wait for one pandaState and one CAN packet
      print("Waiting for CAN messages...")
      while True:
        can = messaging.recv_one_retry(self.can_sock)
        if len(can.can) > 0:
          break

      alpha_long_allowed = self.params.get_bool("AlphaLongitudinalEnabled")

      cached_params = None
      cached_params_raw = self.params.get("CarParamsCache")
      if cached_params_raw is not None:
        with car.CarParams.from_bytes(cached_params_raw) as _cached_params:
          cached_params = _cached_params

      self.CI = get_car(*self.can_callbacks, obd_callback(self.params), alpha_long_allowed, is_release, cached_params)
      self.RI = interfaces[self.CI.CP.carFingerprint].RadarInterface(self.CI.CP)
      self.CP = self.CI.CP

      # continue onto next fingerprinting step in pandad
      self.params.put_bool("FirmwareQueryDone", True, block=True)
    else:
      self.CI, self.CP = CI, CI.CP
      self.RI = RI

    self.CP.alternativeExperience = 0
    openpilot_enabled_toggle = self.params.get_bool("OpenpilotEnabledToggle")
    controller_available = self.CI.CC is not None and openpilot_enabled_toggle and not self.CP.dashcamOnly
    self.CP.passive = not controller_available or self.CP.dashcamOnly
    if self.CP.passive:
      safety_config = structs.CarParams.SafetyConfig()
      safety_config.safetyModel = structs.CarParams.SafetyModel.noOutput
      self.CP.safetyConfigs = [safety_config]

    if self.CP.secOcRequired:
      # Copy user key if available
      try:
        with open("/cache/params/SecOCKey") as f:
          user_key = f.readline().strip()
          if len(user_key) == 32:
            self.params.put("SecOCKey", user_key, block=True)
      except Exception:
        pass

      secoc_key = self.params.get("SecOCKey")
      if secoc_key is not None:
        saved_secoc_key = bytes.fromhex(secoc_key.strip())
        if len(saved_secoc_key) == 16:
          self.CP.secOcKeyAvailable = True
          self.CI.CS.secoc_key = saved_secoc_key
          if controller_available:
            self.CI.CC.secoc_key = saved_secoc_key
        else:
          cloudlog.warning("Saved SecOC key is invalid")

    # Write previous route's CarParams
    prev_cp = self.params.get("CarParamsPersistent")
    if prev_cp is not None:
      self.params.put("CarParamsPrevRoute", prev_cp, block=True)

    # Write CarParams for controls and radard
    cp_bytes = self.CP.to_bytes()
    self.params.put("CarParams", cp_bytes, block=True)
    self.params.put("CarParamsCache", cp_bytes)
    self.params.put("CarParamsPersistent", cp_bytes)

    self.v_cruise_helper = VCruiseHelper(self.CP)

    self.is_metric = self.params.get_bool("IsMetric")
    self.experimental_mode = self.params.get_bool("ExperimentalMode")

    # SafetyModel.volkswagen is MQB specifically; PQ/MLB/MEB use separate safety models.
    self.eps_diag_enabled = (not REPLAY and self.CP.brand == "volkswagen" and
                             any(c.safetyModel == structs.CarParams.SafetyModel.volkswagen for c in self.CP.safetyConfigs))
    self.eps_diag_index = 0
    self.eps_diag_last_did = 0
    self.eps_diag_samples = deque(maxlen=5000)

    self.hca_test_armed = False
    self.hca_test_lockout = False
    self.hca_test_active = False
    self.hca_test_frames = 0
    self.hca_last_sent = 0
    self.eps_hca_status = -1
    self.eps_hca_status_prev = -1
    self.trace_v_ego = 0.0
    self.trace_fault_temp = False
    self.trace_fault_perm = False

    # Never carry an arm across a card process restart.
    if self.eps_diag_enabled:
      try:
        os.unlink(VW_HCA_TEST_ARM_FILE)
      except FileNotFoundError:
        pass
      except OSError:
        cloudlog.exception(f"Failed to clear {VW_HCA_TEST_ARM_FILE}")

    # card is driven by can recv, expected at 100Hz
    self.rk = Ratekeeper(100, print_delay_threshold=None)

  def queue_eps_trace(self, mono_time: int, event: str, did: str = "", value: str | int = "", data: str = "") -> None:
    if not self.eps_diag_enabled:
      return
    self.eps_diag_samples.append((time.time_ns(), mono_time, event, did, value, self.eps_hca_status,
                                  int(self.hca_test_armed), self.trace_v_ego, int(self.trace_fault_temp),
                                  int(self.trace_fault_perm), data))

  def capture_eps_diag(self, can_list) -> None:
    if not self.eps_diag_enabled:
      return

    eps_status_mono = None
    eps_status_raw = None
    for mono_time, frames in can_list:
      for addr, dat, src in frames:
        if addr == VW_EPS_STATUS_RX and src == VW_EPS_STATUS_BUS and len(dat) == 8:
          eps_status_mono = mono_time
          eps_status_raw = dat.hex()

        if addr != VW_EPS_DIAG_RX or src != VW_EPS_DIAG_BUS or len(dat) != 8 or (dat[0] >> 4) != 0:
          continue

        if dat[1] == 0x62 and dat[2] == 0x18:
          did = (dat[2] << 8) | dat[3]
          if did in VW_EPS_DIAG_DIDS:
            self.queue_eps_trace(mono_time, "did", f"{did:04X}", data=dat.hex())
        elif dat[1] == 0x7F and dat[2] == 0x22:
          self.queue_eps_trace(mono_time, "nrc", f"{self.eps_diag_last_did:04X}", f"{dat[3]:02X}", dat.hex())

    if self.eps_hca_status != self.eps_hca_status_prev and eps_status_mono is not None:
      self.queue_eps_trace(eps_status_mono, "eps_status", value=self.eps_hca_status, data=eps_status_raw or "")
      self.eps_hca_status_prev = self.eps_hca_status

  def apply_hca_probe(self, can_sends: list[CanData], CS: car.CarState, CC: car.CarControl, now_nanos: int) -> list[CanData]:
    if not self.eps_diag_enabled:
      return can_sends

    ret = []
    for msg in can_sends:
      if msg.address == VW_HCA_TX and msg.src == VW_HCA_BUS and len(msg.dat) == 8:
        stock_torque = vw_hca_torque(msg.dat)
        steer_req = bool(msg.dat[3] & 0x40)
        controller_saturated = abs(stock_torque) == VW_HCA_STOCK_MAX and abs(float(CC.actuators.torque)) >= 0.999
        probe_allowed = (self.hca_test_armed and not self.hca_test_lockout and CC.enabled and CC.latActive and steer_req and
                         VW_HCA_TEST_MIN_SPEED <= CS.vEgo <= VW_HCA_TEST_MAX_SPEED and not CS.steeringPressed and
                         not CS.steerFaultTemporary and not CS.steerFaultPermanent and controller_saturated and
                         self.hca_test_frames < VW_HCA_TEST_MAX_FRAMES)

        send_torque = stock_torque
        same_direction = self.hca_last_sent == 0 or (self.hca_last_sent > 0) == (stock_torque > 0)
        if probe_allowed and same_direction:
          if stock_torque > 0:
            send_torque = min(VW_HCA_TEST_MAX, max(stock_torque, self.hca_last_sent + VW_HCA_TEST_RATE_UP))
          else:
            send_torque = max(-VW_HCA_TEST_MAX, min(stock_torque, self.hca_last_sent - VW_HCA_TEST_RATE_UP))

        was_active = self.hca_test_active
        self.hca_test_active = abs(send_torque) > VW_HCA_STOCK_MAX
        if self.hca_test_active:
          self.hca_test_frames += 1
          if not was_active:
            self.queue_eps_trace(now_nanos, "probe_start", value=send_torque)
        elif was_active:
          self.hca_test_frames = 0
          self.hca_test_lockout = True
          self.queue_eps_trace(now_nanos, "probe_end", value=stock_torque)

        if send_torque != stock_torque:
          msg = CanData(msg.address, vw_hca_with_torque(msg.dat, send_torque), msg.src)

        self.hca_last_sent = send_torque
        self.queue_eps_trace(now_nanos, "hca_tx", value=send_torque, data=msg.dat.hex())

      ret.append(msg)

    return ret

  def state_update(self) -> tuple[car.CarState, structs.RadarDataT | None]:
    """carState update loop, driven by can"""

    can_strs = messaging.drain_sock_raw(self.can_sock, wait_for_one=True)
    can_list = can_capnp_to_list(can_strs)

    # Update carState from CAN
    CS = self.CI.update(can_list)

    if self.eps_diag_enabled:
      self.trace_v_ego = float(CS.vEgo)
      self.trace_fault_temp = bool(CS.steerFaultTemporary)
      self.trace_fault_perm = bool(CS.steerFaultPermanent)
      eps_stock_values = self.CI.CS.eps_stock_values
      if hasattr(eps_stock_values, "get"):
        self.eps_hca_status = int(eps_stock_values.get("EPS_HCA_Status", -1))
      self.capture_eps_diag(can_list)

    # Update radar tracks from CAN
    RD: structs.RadarDataT | None = self.RI.update(can_list)

    self.sm.update(0)

    can_rcv_valid = len(can_strs) > 0

    # Check for CAN timeout
    if not can_rcv_valid:
      self.can_rcv_cum_timeout_counter += 1

    if can_rcv_valid and REPLAY:
      self.can_log_mono_time = messaging.log_from_bytes(can_strs[0]).logMonoTime

    self.v_cruise_helper.update_v_cruise(CS, self.sm['carControl'].enabled, self.is_metric)
    if self.sm['carControl'].enabled and not self.CC_prev.enabled:
      # Use CarState w/ buttons from the step selfdrived enables on
      self.v_cruise_helper.initialize_v_cruise(self.CS_prev, self.experimental_mode)

    # TODO: mirror the carState.cruiseState struct?
    CS.vCruise = float(self.v_cruise_helper.v_cruise_kph)
    CS.vCruiseCluster = float(self.v_cruise_helper.v_cruise_cluster_kph)

    return CS, RD

  def state_publish(self, CS: car.CarState, RD: structs.RadarDataT | None):
    """carState and carParams publish loop"""

    # carParams - logged every 50 seconds (> 1 per segment)
    if self.sm.frame % int(50. / DT_CTRL) == 0:
      cp_send = messaging.new_message('carParams')
      cp_send.valid = True
      cp_send.carParams = self.CP
      self.pm.send('carParams', cp_send)

    # publish new carOutput
    co_send = messaging.new_message('carOutput')
    co_send.valid = self.sm.all_checks(['carControl'])
    co_send.carOutput.actuatorsOutput = self.last_actuators_output
    self.pm.send('carOutput', co_send)

    # kick off controlsd step while we actuate the latest carControl packet
    cs_send = messaging.new_message('carState')
    cs_send.valid = CS.canValid
    cs_send.carState = CS
    cs_send.carState.canErrorCounter = self.can_rcv_cum_timeout_counter
    cs_send.carState.cumLagMs = -self.rk.remaining * 1000.
    self.pm.send('carState', cs_send)

    if RD is not None:
      tracks_msg = messaging.new_message('radarTracks')
      tracks_msg.valid = not any(RD.errors.to_dict().values())
      tracks_msg.radarTracks = RD
      self.pm.send('radarTracks', tracks_msg)

  def controls_update(self, CS: car.CarState, CC: car.CarControl):
    """control update loop, driven by carControl"""

    if not self.initialized_prev:
      # Initialize CarInterface, once controls are ready
      # TODO: this can make us miss at least a few cycles when doing an ECU knockout
      self.CI.init(self.CP, *self.can_callbacks)
      # signal pandad to switch to car safety mode
      self.params.put_bool("ControlsReady", True)

    if self.sm.all_alive(['carControl']):
      # send car controls over can
      now_nanos = self.can_log_mono_time if REPLAY else int(time.monotonic() * 1e9)
      self.last_actuators_output, can_sends = self.CI.apply(CC, now_nanos)
      can_sends = self.apply_hca_probe(can_sends, CS, CC, now_nanos)

      if self.eps_diag_enabled and self.sm.frame % VW_EPS_DIAG_PERIOD_FRAMES == 0:
        did = VW_EPS_DIAG_DIDS[self.eps_diag_index]
        self.eps_diag_index = (self.eps_diag_index + 1) % len(VW_EPS_DIAG_DIDS)
        self.eps_diag_last_did = did
        request = bytes([0x03, 0x22, did >> 8, did & 0xFF, 0, 0, 0, 0])
        can_sends.append(CanData(VW_EPS_DIAG_TX, request, VW_EPS_DIAG_BUS))

      self.pm.send('sendcan', can_list_to_can_capnp(can_sends, msgtype='sendcan', valid=CS.canValid))

      self.CC_prev = CC

  def step(self):
    CS, RD = self.state_update()

    self.state_publish(CS, RD)

    initialized = (not any(e.name == EventName.selfdriveInitializing for e in self.sm['onroadEvents']) and
                   self.sm.seen['onroadEvents'])
    if not self.CP.passive and initialized:
      self.controls_update(CS, self.sm['carControl'])

    self.initialized_prev = initialized
    self.CS_prev = CS

  def params_thread(self, evt):
    eps_log = None
    if self.eps_diag_enabled:
      try:
        eps_log = open(VW_EPS_DIAG_LOG, "a", buffering=1)
        if eps_log.tell() == 0:
          eps_log.write("wall_time_ns,mono_time_ns,event,did,value,eps_hca_status,armed,v_ego,steer_fault_temp,steer_fault_perm,data\n")
      except OSError:
        cloudlog.exception(f"Failed to open {VW_EPS_DIAG_LOG}")

    try:
      while not evt.is_set():
        self.is_metric = self.params.get_bool("IsMetric")
        self.experimental_mode = self.params.get_bool("ExperimentalMode") and self.CP.openpilotLongitudinalControl

        if self.eps_diag_enabled:
          previous_armed = self.hca_test_armed
          if self.hca_test_lockout:
            try:
              os.unlink(VW_HCA_TEST_ARM_FILE)
            except FileNotFoundError:
              pass
            except OSError:
              cloudlog.exception(f"Failed to remove {VW_HCA_TEST_ARM_FILE}")
            self.hca_test_armed = False
            self.hca_test_lockout = False
          else:
            try:
              with open(VW_HCA_TEST_ARM_FILE) as f:
                self.hca_test_armed = f.read().strip() == str(VW_HCA_TEST_MAX)
            except OSError:
              self.hca_test_armed = False

          if self.hca_test_armed != previous_armed:
            self.queue_eps_trace(time.monotonic_ns(), "arm", value=int(self.hca_test_armed))

        if eps_log is not None:
          while self.eps_diag_samples:
            wall_time, mono_time, event, did, value, eps_hca_status, armed, v_ego, fault_temp, fault_perm, data = self.eps_diag_samples.popleft()
            eps_log.write(f"{wall_time},{mono_time},{event},{did},{value},{eps_hca_status},{armed},{v_ego:.3f},{fault_temp},{fault_perm},{data}\n")
        else:
          self.eps_diag_samples.clear()

        time.sleep(0.1)
    finally:
      if eps_log is not None:
        eps_log.close()

  def card_thread(self):
    e = threading.Event()
    t = threading.Thread(target=self.params_thread, args=(e, ))
    try:
      t.start()
      while True:
        self.step()
        self.rk.monitor_time()
    finally:
      e.set()
      t.join()


def main():
  config_realtime_process(4, Priority.CTRL_HIGH)
  car = Car()
  car.card_thread()


if __name__ == "__main__":
  main()