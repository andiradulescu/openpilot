import errno
import os
import pathlib
import select
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tty
import unittest
import uuid
import zlib

from openpilot.cereal import messaging
from openpilot.system.sensord.usbimud import FRAME, FrameParser, UsbImu, parse_mount


def frame(kind, session, device_us=0, sequence=0, flags=0, values=(0, 0, 0, 0, 0, 0), version=1):
  body = struct.pack('<4sBBHIQQ6h', b'XIMU', version, kind, flags, sequence, session, device_us, *values)
  return body + zlib.crc32(body).to_bytes(4, 'little')


class TestUsbImu(unittest.TestCase):
  def setUp(self):
    self.imu = UsbImu(parse_mount('x,y,z'))
    request = self.imu.sync_request(10_000_000_000)
    fields = FRAME.unpack(request)
    self.session = fields[5]
    self.assertEqual(fields[:5], (b'XIMU', 1, 1, 0, 0))
    self.assertNotEqual(self.session, 0)
    self.assertEqual(fields[6:-1], (0,) * 7)
    self.assertEqual(zlib.crc32(request[:-4]), fields[-1])
    self.assertEqual(list(self.imu.feed(frame(2, self.session, 1_000_000), 10_002_000_000)), [])

  def sample(self, **kwargs):
    return frame(3, self.session, device_us=kwargs.pop('device_us', 1_009_615), sequence=kwargs.pop('sequence', 1), flags=kwargs.pop('flags', 3), **kwargs)

  def test_publishes_scaled_values_in_locationd_frame(self):
    messages = list(self.imu.feed(self.sample(values=(16384, -8192, 4096, 1000, -2000, 3000)), 10_012_000_000))
    self.assertEqual([message.which() for message in messages], ['accelerometer', 'gyroscope'])
    for message in messages:
      self.assertTrue(message.valid)
      self.assertEqual(message.logMonoTime, 10_012_000_000)
      event = getattr(message, message.which())
      self.assertEqual(str(event.source), 'lsm6ds3trc')
      self.assertEqual(event.timestamp, 10_009_615_000)
      self.assertLess(event.timestamp, message.logMonoTime)
    for actual, expected in zip(messages[0].accelerometer.acceleration.v, (-2.4525, 4.905, -9.81), strict=True):
      self.assertAlmostEqual(actual, expected, places=5)
    for actual, expected in zip(messages[1].gyroscope.gyroUncalibrated.v, (-0.458148929, 0.305432619, -0.152716310), strict=True):
      self.assertAlmostEqual(actual, expected, places=6)

  def test_mount_is_applied_before_locationd_transform(self):
    imu = UsbImu(parse_mount('y,-x,z'))
    session = FRAME.unpack(imu.sync_request(10_000_000_000))[5]
    list(imu.feed(frame(2, session, 1_000_000), 10_002_000_000))
    message = list(imu.feed(frame(3, session, 1_009_615, 1, 1, (16384, -8192, 4096, 0, 0, 0)), 10_012_000_000))[0]
    for actual, expected in zip(message.accelerometer.acceleration.v, (-2.4525, 9.81, 4.905), strict=True):
      self.assertAlmostEqual(actual, expected, places=5)

  def test_only_ready_sensor_is_published(self):
    accelerometer = list(self.imu.feed(self.sample(flags=1), 10_012_000_000))
    gyroscope = list(self.imu.feed(self.sample(flags=2, sequence=2, device_us=1_019_230), 10_022_000_000))
    self.assertEqual([message.which() for message in accelerometer + gyroscope], ['accelerometer', 'gyroscope'])

  def test_invalid_frames_do_not_publish(self):
    corrupt = bytearray(self.sample())
    corrupt[31] ^= 0x80
    for packet in (
      bytes(corrupt),
      self.sample(version=2),
      frame(3, self.session ^ 1, 1_009_615, 1, 3),
      frame(4, self.session, 1_009_615, 1, 3),
      self.sample(flags=0),
      self.sample(flags=4),
    ):
      with self.subTest(packet=packet.hex()):
        self.assertEqual(list(self.imu.feed(packet, 10_012_000_000)), [])

  def test_stale_or_nonadvancing_samples_fail_closed(self):
    for device_us, host_ns in ((1_009_615, 10_060_000_001), (1_020_000, 10_012_000_000), (999_999, 10_012_000_000)):
      with self.subTest(device_us=device_us), self.assertRaisesRegex(ValueError, 'timestamp'):
        list(self.imu.feed(self.sample(device_us=device_us), host_ns))

    list(self.imu.feed(self.sample(sequence=100), 10_012_000_000))
    with self.assertRaisesRegex(ValueError, 'did not advance'):
      list(self.imu.feed(self.sample(sequence=100, device_us=1_019_230), 10_022_000_000))

  def test_fresh_sync_blocks_old_session_until_response(self):
    session = FRAME.unpack(self.imu.sync_request(11_000_000_000))[5]
    self.assertNotEqual(session, self.session)
    self.assertEqual(list(self.imu.feed(self.sample(device_us=2_009_615), 11_012_000_000)), [])
    packet = frame(3, session, 2_009_615, 1, 3)
    self.assertEqual(list(self.imu.feed(packet, 11_012_000_000)), [])
    list(self.imu.feed(frame(2, session, 2_000_000), 11_002_000_000))
    self.assertEqual(len(list(self.imu.feed(packet, 11_012_000_000))), 2)

  def test_parser_discards_noise_and_bad_frames(self):
    parser = FrameParser()
    self.assertEqual(list(parser.feed(b'a' * 100000)), [])
    self.assertLess(len(parser.buffer), 4)


class TestMount(unittest.TestCase):
  def test_requires_explicit_right_handed_sensor_mount(self):
    self.assertEqual(parse_mount('x,y,z'), ((0, 1), (1, 1), (2, 1)))
    for value in ('', 'x,y', 'x,x,z', 'x,y,-z', 'x,z,y', 'x,y, z', '1,2,3'):
      with self.subTest(value=value), self.assertRaises(ValueError):
        parse_mount(value)


class PtyResponder:
  def __init__(self):
    self.master, self.slave = os.openpty()
    tty.setraw(self.slave)
    os.set_blocking(self.master, False)
    self.path = os.ttyname(self.slave)
    self.buffer = bytearray()
    self.sessions = []
    self.session = 0
    self.base_us = 5_000_000
    self.base_ns = 0
    self.sequence = 0
    self.running = threading.Event()
    self.running.set()
    self.lock = threading.Lock()
    self.session_ready = threading.Condition(self.lock)
    self.writer = threading.Lock()
    self.error = None
    self.thread = threading.Thread(target=self.run, daemon=True)
    self.thread.start()

  def close(self):
    self.running.clear()
    self.thread.join(1)
    for name in ('master', 'slave'):
      fd = getattr(self, name)
      if fd is not None:
        os.close(fd)
        setattr(self, name, None)

  def write(self, data):
    with self.writer:
      while data:
        _, writable, _ = select.select([], [self.master], [], 1)
        if not writable:
          raise TimeoutError('daemon stopped consuming the PTY')
        data = data[os.write(self.master, data) :]

  def run(self):
    try:
      while self.running.is_set():
        if not select.select([self.master], [], [], 0.005)[0]:
          continue
        try:
          self.buffer.extend(os.read(self.master, 4096))
        except OSError as e:
          if e.errno == errno.EIO and not self.running.is_set():
            return
          raise
        self.respond_to_requests()
    except Exception as e:
      self.error = e
      with self.session_ready:
        self.session_ready.notify_all()

  def respond_to_requests(self):
    while len(self.buffer) >= FRAME.size:
      start = self.buffer.find(b'XIMU')
      if start == -1:
        del self.buffer[:-3]
        return
      del self.buffer[:start]
      if len(self.buffer) < FRAME.size:
        return
      request = bytes(self.buffer[: FRAME.size])
      if zlib.crc32(request[:-4]) != struct.unpack_from('<I', request, FRAME.size - 4)[0]:
        del self.buffer[0]
        continue
      del self.buffer[: FRAME.size]
      magic, version, kind, flags, sequence, session, device_us, *values_crc = FRAME.unpack(request)
      if (magic, version, kind, flags, sequence, device_us, values_crc[:6]) != (b'XIMU', 1, 1, 0, 0, 0, [0] * 6) or not session:
        raise AssertionError(f'nonconforming sync request: {request.hex()}')
      with self.lock:
        if session in (existing for existing, _ in self.sessions):
          raise AssertionError('sync session must be fresh')
        self.base_us += 1_000_000
        self.base_ns = time.monotonic_ns()
        self.session = session
        self.sequence = 0
        response = frame(2, session, self.base_us)
      self.write(response)
      with self.session_ready:
        self.sessions.append((session, self.base_ns))
        self.session_ready.notify_all()

  def wait_for_session(self, count, timeout):
    deadline = time.monotonic() + timeout
    with self.session_ready:
      while len(self.sessions) <= count and self.error is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
          break
        self.session_ready.wait(remaining)
      if self.error is not None:
        raise self.error
      if len(self.sessions) <= count:
        raise TimeoutError('daemon did not emit a sync request')
      return self.sessions[count]

  def sample(self, session=None):
    with self.lock:
      session = self.session if session is None else session
      self.sequence += 1
      device_us = self.base_us + (time.monotonic_ns() - self.base_ns) // 1000
      return frame(3, session, device_us, self.sequence, 3, (16384, -8192, 4096, 1000, -2000, 3000))


class TestUsbImuDaemon(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory(prefix='usbimud-pty-')
    self.path = pathlib.Path(self.tmp.name)
    self.port = self.path / 'usb-imu'
    self.responder = PtyResponder()
    self.port.symlink_to(self.responder.path)
    self.prefix = 'usbimud-' + uuid.uuid4().hex
    self.original_prefix = os.environ.get('OPENPILOT_PREFIX')
    os.environ['OPENPILOT_PREFIX'] = self.prefix
    self.msgq_path = pathlib.Path('/tmp' if os.uname().sysname == 'Darwin' else '/dev/shm') / ('msgq_' + self.prefix)
    self.msgq_path.mkdir()
    self.log = (self.path / 'usbimud.log').open('w+')
    root = pathlib.Path.cwd()
    env = dict(
      os.environ,
      PYTHONPATH=os.pathsep.join((str(root), os.environ.get('PYTHONPATH', ''))),
      PWD=str(root),
      PYTHONDONTWRITEBYTECODE='1',
      USB_IMU_PORT=str(self.port),
      USB_IMU_DEVICE_FROM_SENSOR='x,y,z',
    )
    self.proc = subprocess.Popen([sys.executable, '-m', 'openpilot.system.sensord.usbimud'], cwd=root, env=env, stdout=self.log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 2
    while not all((self.msgq_path / name).exists() for name in ('accelerometer', 'gyroscope')):
      if self.proc.poll() is not None or time.monotonic() >= deadline:
        self.fail(f'usbimud did not create messaging endpoints: {self.daemon_log()}')
      time.sleep(0.001)
    self.sockets = {name: messaging.sub_sock(name, conflate=False) for name in ('accelerometer', 'gyroscope')}

  def tearDown(self):
    self.proc.terminate()
    try:
      self.proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
      self.proc.kill()
      self.proc.wait(timeout=3)
    self.responder.close()
    self.log.close()
    self.sockets.clear()
    for entry in self.msgq_path.iterdir():
      entry.unlink()
    self.msgq_path.rmdir()
    if self.original_prefix is None:
      os.environ.pop('OPENPILOT_PREFIX', None)
    else:
      os.environ['OPENPILOT_PREFIX'] = self.original_prefix
    self.tmp.cleanup()

  def daemon_log(self):
    self.log.flush()
    self.log.seek(0)
    return self.log.read()

  def receive(self, timeout=0.2):
    messages = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(messages) != len(self.sockets):
      for name, socket in self.sockets.items():
        message = messaging.recv_one_or_none(socket)
        if message is not None:
          messages[name] = message
      if len(messages) != len(self.sockets):
        time.sleep(0.001)
    return messages

  def synchronize(self, responder, start=0):
    for attempt in range(3):
      session, _ = responder.wait_for_session(start + attempt, 1.5)
      for _ in range(5):
        responder.write(responder.sample(session))
        messages = self.receive()
        if len(messages) == len(self.sockets):
          return session
        time.sleep(0.005)
    self.fail(f'usbimud did not publish after synchronization: {self.daemon_log()}')

  def assert_silent(self):
    time.sleep(0.04)
    self.assertTrue(all(not messaging.drain_sock(socket) for socket in self.sockets.values()))

  def test_periodic_sync_rejects_old_session_and_recovers_after_reconnect(self):
    first = self.synchronize(self.responder)
    deadline = time.monotonic() + 2.5
    while len(self.responder.sessions) < 2 and time.monotonic() < deadline:
      self.responder.write(self.responder.sample())
      for socket in self.sockets.values():
        messaging.drain_sock(socket)
      time.sleep(0.02)
    self.assertGreaterEqual(len(self.responder.sessions), 2, self.daemon_log())
    second, second_received_ns = self.responder.sessions[1]
    self.assertNotEqual(second, first)
    self.assertGreater(second_received_ns - self.responder.sessions[0][1], 900_000_000)

    for socket in self.sockets.values():
      messaging.drain_sock(socket)
    self.responder.write(self.responder.sample(first))
    self.assert_silent()
    self.responder.write(self.responder.sample())
    self.assertEqual(set(self.receive()), {'accelerometer', 'gyroscope'})

    self.responder.close()
    self.port.unlink()
    self.responder = PtyResponder()
    self.port.symlink_to(self.responder.path)
    third = self.synchronize(self.responder)
    self.assertNotIn(third, (first, second))
