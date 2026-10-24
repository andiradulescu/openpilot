#!/usr/bin/env python3
import math
import os
import secrets
import select
import struct
import time
import zlib

from openpilot.cereal import messaging
from openpilot.common.serial import Serial, SerialException
from openpilot.common.swaglog import cloudlog

MAGIC = b'XIMU'
VERSION = 1
SYNC_REQUEST, SYNC_RESPONSE, SAMPLE = 1, 2, 3
FRAME = struct.Struct('<4sBBHIQQ6hI')
SYNC_INTERVAL_NS = 1_000_000_000
SYNC_TIMEOUT_NS = 100_000_000
MAX_SYNC_RTT_NS = 10_000_000
MAX_SYNC_AGE_NS = 2_000_000_000
MAX_SAMPLE_AGE_NS = 50_000_000
DISCONNECT_NS = 200_000_000
ACCEL_SCALE = 9.81 * 2 / 32768
GYRO_SCALE = 0.00875 * math.pi / 180


def parse_mount(value: str) -> tuple[tuple[int, int], ...]:
  """Signed sensor axes for device [forward, right, down]; require a proper rotation."""
  axes = value.split(',')
  if len(axes) != 3 or any(axis not in ('x', 'y', 'z', '-x', '-y', '-z') for axis in axes):
    raise ValueError('USB_IMU_DEVICE_FROM_SENSOR must contain three signed axes, for example x,y,z')
  mount = tuple(('xyz'.index(axis[-1]), -1 if axis.startswith('-') else 1) for axis in axes)
  indices = [axis for axis, _ in mount]
  inversions = sum(indices[i] > indices[j] for i in range(3) for j in range(i + 1, 3))
  if len(set(indices)) != 3 or (-1) ** inversions * math.prod(sign for _, sign in mount) != 1:
    raise ValueError('USB_IMU_DEVICE_FROM_SENSOR must be a right-handed signed permutation')
  return mount


class FrameParser:
  def __init__(self):
    self.buffer = bytearray()

  def feed(self, data: bytes):
    self.buffer.extend(data)
    while True:
      start = self.buffer.find(MAGIC)
      if start == -1:
        del self.buffer[: -len(MAGIC) + 1]
        return
      del self.buffer[:start]
      if len(self.buffer) < FRAME.size:
        return
      frame = bytes(self.buffer[: FRAME.size])
      if zlib.crc32(frame[:-4]) != struct.unpack_from('<I', frame, FRAME.size - 4)[0]:
        del self.buffer[0]
        continue
      del self.buffer[: FRAME.size]
      yield FRAME.unpack(frame)


class UsbImu:
  def __init__(self, mount: tuple[tuple[int, int], ...]):
    self.mount = mount
    self.parser = FrameParser()
    self.session = 0
    self.sync_sent_ns = 0
    self.offset_ns: int | None = None
    self.sync_device_us = 0
    self.last_sequence: int | None = None
    self.last_device_us = 0
    self.last_timestamp_ns = 0
    self.last_sample_ns = 0
    self.sequence_gaps = 0

  def sync_request(self, now_ns: int) -> bytes:
    self.session = secrets.randbits(64) or 1
    self.sync_sent_ns = now_ns
    self.offset_ns = None
    self.last_sequence = None
    self.last_device_us = 0
    self.sequence_gaps = 0
    frame = FRAME.pack(MAGIC, VERSION, SYNC_REQUEST, 0, 0, self.session, 0, *([0] * 6), 0)
    return frame[:-4] + struct.pack('<I', zlib.crc32(frame[:-4]))

  def feed(self, data: bytes, now_ns: int):
    for _, version, kind, flags, sequence, session, device_us, *values_crc in self.parser.feed(data):
      values = values_crc[:6]
      if version != VERSION or session != self.session or not self.session:
        continue
      if kind == SYNC_RESPONSE:
        if self.offset_ns is not None or flags or sequence or any(values):
          continue
        if not 0 <= now_ns - self.sync_sent_ns <= MAX_SYNC_RTT_NS:
          continue
        # The device handled this request after it was sent. This lower-bound
        # offset keeps the mapped acquisition time conservative by at most RTT.
        self.offset_ns = self.sync_sent_ns - device_us * 1000
        self.sync_device_us = device_us
        continue
      if kind != SAMPLE or flags not in (1, 2, 3) or self.offset_ns is None:
        continue
      if now_ns - self.sync_sent_ns > MAX_SYNC_AGE_NS:
        raise ValueError('USB IMU clock synchronization expired')
      timestamp_ns = device_us * 1000 + self.offset_ns
      if device_us < self.sync_device_us or not 0 < timestamp_ns <= now_ns or now_ns - timestamp_ns > MAX_SAMPLE_AGE_NS:
        raise ValueError('USB IMU sample timestamp is stale or outside the synchronized clock')
      if self.last_sequence is not None:
        delta = (sequence - self.last_sequence) & 0xFFFFFFFF
        if not 0 < delta < 0x80000000 or device_us <= self.last_device_us:
          raise ValueError('USB IMU sequence or timestamp did not advance')
        self.sequence_gaps += delta - 1
      self.last_sequence, self.last_device_us = sequence, device_us
      # A new bounded synchronization can move the conservative offset back.
      # Drop overlapping observations instead of sending time backwards.
      if timestamp_ns <= self.last_timestamp_ns:
        continue
      self.last_timestamp_ns, self.last_sample_ns = timestamp_ns, now_ns
      for flag, service, field, raw, scale in (
        (1, 'accelerometer', 'acceleration', values[:3], ACCEL_SCALE),
        (2, 'gyroscope', 'gyroUncalibrated', values[3:], GYRO_SCALE),
      ):
        if flags & flag:
          device = [raw[axis] * sign * scale for axis, sign in self.mount]
          msg = messaging.new_message(service, valid=True, logMonoTime=now_ns)
          event = getattr(msg, service)
          event.source = 'lsm6ds3trc'
          event.timestamp = timestamp_ns
          # locationd maps [-v_z, -v_y, -v_x] into the camera/device frame.
          event.init(field).v = [-device[2], -device[1], -device[0]]
          yield msg


def run(port: str, mount: tuple[tuple[int, int], ...]) -> None:
  # Linux uses the same CDC protocol; select the stable /dev/serial/by-id path there.
  pm = messaging.PubMaster(['accelerometer', 'gyroscope'])
  while True:
    try:
      with Serial(port, baudrate=115200, timeout=0, exclusive=True) as serial:
        imu = UsbImu(mount)
        while True:
          now_ns = time.monotonic_ns()
          if not imu.session or now_ns - imu.sync_sent_ns >= SYNC_INTERVAL_NS:
            if imu.sequence_gaps:
              cloudlog.warning(f'USB IMU: {imu.sequence_gaps} unreported data-ready edges in the previous session')
            request = imu.sync_request(now_ns)
            # Serial.write waits indefinitely on EAGAIN. CDC requests are tiny;
            # reconnect on a short/nonblocking write rather than blocking stop.
            if os.write(serial.fd, request) != len(request):
              raise SerialException('incomplete USB IMU synchronization request')
          if imu.offset_ns is None and now_ns - imu.sync_sent_ns > SYNC_TIMEOUT_NS:
            raise SerialException('USB IMU synchronization timed out')
          if imu.offset_ns is not None and now_ns - (imu.last_sample_ns or imu.sync_sent_ns) > DISCONNECT_NS:
            raise SerialException('USB IMU samples stopped')
          if select.select([serial.fd], [], [], 0.005)[0]:
            data = serial.read(4096)
            if not data:
              raise SerialException('USB IMU disconnected')
            for msg in imu.feed(data, time.monotonic_ns()):
              pm.send(msg.which(), msg)
    except (OSError, ValueError) as e:
      cloudlog.warning(f'USB IMU reconnecting: {e}')
      time.sleep(1)


def main() -> None:
  port = os.environ['USB_IMU_PORT']
  if not port:
    raise ValueError('USB_IMU_PORT must name an explicit serial device')
  mount = parse_mount(os.environ['USB_IMU_DEVICE_FROM_SENSOR'])
  try:
    run(port, mount)
  except KeyboardInterrupt:
    pass


if __name__ == '__main__':
  main()
