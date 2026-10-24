import atexit
import cv2 as cv
import numpy as np
import os
import platform
import select
import shutil
import struct
import subprocess
import threading
import time
from pathlib import Path

from openpilot.system.camerad.cameras.nv12_info import get_nv12_info


NEXIGO_N60 = 'NexiGo N60 FHD Webcam'
W = 1280
H = 720
NATIVE_FRAME_SIZE = 16 + W * H * 3 // 2
BGR_FRAME_SIZE = W * H * 3


class Camera:
  def __init__(self, cam_type_state, stream_type, camera_id):
    self.cam_type_state = cam_type_state
    self.stream_type = stream_type
    self.cur_frame_id = 0
    self.latest_frame = None
    self.capture_error = None
    self.frame_lock = threading.Lock()
    self.close_lock = threading.Lock()
    self.cap = None
    self.capture_process = None
    self.macos_backend = None

    if platform.system() == 'Darwin':
      if camera_id != NEXIGO_N60:
        raise RuntimeError(f"macOS webcam must be {NEXIGO_N60}, got {camera_id}")
      self.macos_backend = os.getenv('WEBCAM_BACKEND', 'native')
      if self.macos_backend not in ('native', 'ffmpeg'):
        raise RuntimeError(f"Invalid WEBCAM_BACKEND: {self.macos_backend}")
      if self.macos_backend == 'native':
        self.open_macos_camera()
      else:
        self.open_ffmpeg_camera()
    else:
      self.open_linux_camera(camera_id)

    atexit.register(self.close)
    self.capture_thread = threading.Thread(target=self.capture_frames, name=cam_type_state, daemon=True)
    self.capture_thread.start()

  def open_linux_camera(self, camera_id):
    try:
      camera_id = int(camera_id)
    except ValueError: # allow strings, ex: /dev/video0
      pass
    print(f"Opening {self.cam_type_state} at {camera_id}")

    # OpenCV has no V4L2 timestamp access; use V4L2 here when hardware timestamps are needed.
    self.cap = cv.VideoCapture(camera_id)
    if not self.cap.isOpened():
      raise RuntimeError(f"Failed to open {self.cam_type_state} camera {camera_id}")

    self.cap.set(cv.CAP_PROP_FRAME_WIDTH, 1280.0)
    self.cap.set(cv.CAP_PROP_FRAME_HEIGHT, 720.0)
    self.cap.set(cv.CAP_PROP_FPS, 25.0)

    self.W = int(self.cap.get(cv.CAP_PROP_FRAME_WIDTH))
    self.H = int(self.cap.get(cv.CAP_PROP_FRAME_HEIGHT))
    if (self.W, self.H) != (W, H):
      self.cap.release()
      raise RuntimeError(f"{self.cam_type_state} requires {W}x{H}, got {self.W}x{self.H}")

  def open_macos_camera(self):
    helper = Path(__file__).with_name('macos')
    if not helper.is_file():
      raise RuntimeError('Build the macOS webcam helper with scons --minimal first')
    self.capture_process = subprocess.Popen([str(helper)], stdout=subprocess.PIPE)
    self.W = W
    self.H = H

  def open_ffmpeg_camera(self):
    ffmpeg = shutil.which('ffmpeg', path='/opt/homebrew/bin:/usr/local/bin:/usr/bin')
    if ffmpeg is None:
      raise RuntimeError('macOS webcam requires ffmpeg with AVFoundation support')
    try:
      devices = subprocess.run([ffmpeg, '-hide_banner', '-f', 'avfoundation', '-list_devices', 'true', '-i', ''],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5, check=False).stdout
    except subprocess.TimeoutExpired as e:
      raise RuntimeError('Timed out listing AVFoundation cameras') from e
    if 'AVFoundation video devices:' not in devices:
      raise RuntimeError('ffmpeg lacks AVFoundation support')
    if not any(line.rstrip().endswith(f'] {NEXIGO_N60}') for line in devices.splitlines()):
      raise RuntimeError(f'AVFoundation camera {NEXIGO_N60} is unavailable')

    print(f"Opening {self.cam_type_state} at {NEXIGO_N60} with ffmpeg")
    self.capture_process = subprocess.Popen(
      [ffmpeg, '-hide_banner', '-loglevel', 'error', '-nostdin', '-f', 'avfoundation', '-pixel_format', 'nv12', '-framerate', '25',
       '-video_size', f'{W}x{H}', '-i', f'{NEXIGO_N60}:none', '-f', 'rawvideo', '-pix_fmt', 'bgr24', 'pipe:1'],
      stdout=subprocess.PIPE,
    )
    self.W = W
    self.H = H

  @classmethod
  def bgr2nv12(self, bgr):
    height, width = bgr.shape[:2]
    i420 = cv.cvtColor(bgr, cv.COLOR_BGR2YUV_I420).ravel()
    y_size = height * width
    uv_size = y_size // 4
    stride, y_height, uv_height, size = get_nv12_info(width, height)
    padded_nv12 = np.zeros(size, dtype=np.uint8)
    planes = padded_nv12[:stride * (y_height + uv_height)].reshape(-1, stride)
    planes[:height, :width] = i420[:y_size].reshape(height, width)
    planes[y_height:y_height + height // 2, :width:2] = i420[y_size:y_size + uv_size].reshape(height // 2, width // 2)
    planes[y_height:y_height + height // 2, 1:width:2] = i420[y_size + uv_size:].reshape(height // 2, width // 2)
    return padded_nv12.tobytes()

  @staticmethod
  def rotate_nv12(packed):
    packed = np.frombuffer(packed, dtype=np.uint8)
    y = packed[:W * H].reshape(H, W)[::-1, ::-1]
    uv = packed[W * H:].reshape(H // 2, W // 2, 2)[::-1, ::-1, :].reshape(H // 2, W)
    stride, y_height, uv_height, size = get_nv12_info(W, H)
    padded = np.zeros(size, dtype=np.uint8)
    planes = padded[:stride * (y_height + uv_height)].reshape(-1, stride)
    planes[:H, :W] = y
    planes[y_height:y_height + H // 2, :W] = uv
    return padded.tobytes()

  def capture_frames(self):
    try:
      while True:
        if self.capture_process is not None:
          yuv, sof, eof = self.read_macos_frame()
        else:
          # OpenCV exposes only host capture-call bounds on Linux.
          sof = time.monotonic_ns()
          ret, frame = self.cap.read()
          eof = time.monotonic_ns()
          if not ret:
            raise RuntimeError(f"Failed to capture {self.cam_type_state} frame")
          yuv = self.bgr2nv12(cv.flip(frame, -1))
        with self.frame_lock:
          self.latest_frame = (self.cur_frame_id, yuv, sof, eof)
          self.cur_frame_id += 1
    except Exception as e:
      with self.frame_lock:
        self.capture_error = e
    finally:
      self.close()

  def read_macos_frame(self):
    if self.macos_backend == 'ffmpeg':
      sof = time.monotonic_ns()
      bgr = self.read_capture_bytes(BGR_FRAME_SIZE)
      eof = time.monotonic_ns()
      return self.bgr2nv12(cv.flip(np.frombuffer(bgr, dtype=np.uint8).reshape(H, W, 3), -1)), sof, eof

    frame = self.read_capture_bytes(NATIVE_FRAME_SIZE)
    sof, eof = struct.unpack_from('<QQ', frame)
    if not 0 < sof <= eof <= time.monotonic_ns():
      raise RuntimeError(f"Invalid {self.cam_type_state} capture timestamps: {sof}, {eof}")
    return self.rotate_nv12(memoryview(frame)[16:]), sof, eof

  def read_capture_bytes(self, size):
    process = self.capture_process
    assert process is not None and process.stdout is not None
    frame = bytearray()
    deadline = time.monotonic() + 5
    while len(frame) < size:
      ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
      if not ready:
        raise RuntimeError(f"Timed out capturing {self.cam_type_state} frame")
      chunk = os.read(process.stdout.fileno(), size - len(frame))
      if not chunk:
        raise RuntimeError(f"{self.cam_type_state} capture ended with {len(frame)} of {size} bytes")
      frame.extend(chunk)
    return frame

  def close(self):
    with self.close_lock:
      if self.cap is not None:
        self.cap.release()
        self.cap = None
      if self.capture_process is not None:
        process = self.capture_process
        self.capture_process = None
        if process.poll() is None:
          process.terminate()
          try:
            process.wait(timeout=1)
          except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout is not None:
          process.stdout.close()

  def get_latest_frame(self):
    with self.frame_lock:
      if self.capture_error is not None:
        raise RuntimeError(f"{self.cam_type_state} capture stopped") from self.capture_error
      return self.latest_frame
