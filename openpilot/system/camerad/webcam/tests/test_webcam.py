import gc
import os
import platform
import shutil
import unittest
from unittest.mock import patch

import numpy as np

from msgq.visionipc import VisionIpcClient, VisionIpcServer
from openpilot.cereal import messaging
from openpilot.cereal.visionipc import VisionStreamType
from openpilot.common.prefix import OpenpilotPrefix
from openpilot.system.camerad.cameras.nv12_info import get_nv12_info
from openpilot.system.camerad.webcam.camera import Camera, NEXIGO_N60
from openpilot.system.camerad.webcam.camerad import Camerad


W = 1280
H = 720
STREAM = VisionStreamType.VISION_STREAM_NARROW_ROAD
SERVICE = 'narrowRoadCameraState'


class TestWebcam(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.prefix = OpenpilotPrefix(create_dirs_on_enter=False, clean_dirs_on_exit=False)
    cls.prefix.__enter__()
    os.mkdir(cls.prefix.msgq_path)

    cls.stride, cls.y_height, cls.uv_height, cls.size = get_nv12_info(W, H)
    cls.camerad = Camerad.__new__(Camerad)
    cls.camerad.pm = messaging.PubMaster([SERVICE])
    cls.camerad.vipc_server = VisionIpcServer('camerad')
    cls.camerad.vipc_server.create_buffers_with_sizes(STREAM, 2, W, H, cls.size, cls.stride, cls.stride * cls.y_height)
    cls.camerad.vipc_server.start_listener()

    cls.state_sock = messaging.sub_sock(SERVICE)
    assert cls.camerad.pm.wait_for_readers_to_update(SERVICE, timeout=5)
    cls.vipc_client = VisionIpcClient('camerad', STREAM, False)
    assert cls.vipc_client.connect(True)

  @classmethod
  def tearDownClass(cls):
    cls.vipc_client = None
    cls.state_sock = None
    cls.camerad = None
    gc.collect()
    shutil.rmtree(cls.prefix.msgq_path)
    cls.prefix.__exit__(None, None, None)

  def test_bgr_to_padded_nv12(self):
    yuv = Camera.bgr2nv12(np.zeros((H, W, 3), dtype=np.uint8))
    plane_size = self.stride * (self.y_height + self.uv_height)
    planes = np.frombuffer(yuv[:plane_size], dtype=np.uint8).reshape(-1, self.stride)

    assert len(yuv) == self.size
    assert planes[0, 0] == 16
    assert np.all(planes[H:self.y_height] == 0)
    assert np.all(planes[self.y_height + H // 2:] == 0)
    assert np.all(np.frombuffer(yuv[plane_size:], dtype=np.uint8) == 0)

    red = np.full((H, W, 3), (0, 0, 255), dtype=np.uint8)
    red_yuv = np.frombuffer(Camera.bgr2nv12(red), dtype=np.uint8)
    assert np.all(red_yuv[:self.stride * H].reshape(H, self.stride)[:, :W] == 82)
    uv = red_yuv[self.stride * self.y_height:self.stride * (self.y_height + H // 2)].reshape(H // 2, self.stride)
    assert np.all(uv[:, :W:2] == 90)
    assert np.all(uv[:, 1:W:2] == 240)

  @unittest.skipUnless(platform.system() == 'Darwin', 'macOS only')
  def test_macos_backend_selector_rejects_invalid_values_before_capture(self):
    with patch.dict(os.environ, {'WEBCAM_BACKEND': 'invalid'}):
      with self.assertRaisesRegex(RuntimeError, 'Invalid WEBCAM_BACKEND'):
        Camera(SERVICE, STREAM, NEXIGO_N60)

  @unittest.skipUnless(platform.system() == 'Darwin', 'macOS only')
  def test_macos_backend_selector_rejects_non_nexigo_camera_before_capture(self):
    for camera_id in ('0', 'MacBook Air Camera'):
      with patch.dict(os.environ, {'WEBCAM_BACKEND': 'native'}):
        with self.assertRaisesRegex(RuntimeError, 'macOS webcam must be NexiGo N60 FHD Webcam'):
          Camera(SERVICE, STREAM, camera_id)

  def test_nv12_rotation_preserves_chroma_pairs(self):
    packed = np.zeros(W * H * 3 // 2, dtype=np.uint8)
    packed[0], packed[W * H - 1] = 20, 80
    packed[W * H:W * H + 2] = (90, 240)
    packed[-2:] = (110, 130)
    rotated = np.frombuffer(Camera.rotate_nv12(packed), dtype=np.uint8)
    planes = rotated[:self.stride * (self.y_height + self.uv_height)].reshape(-1, self.stride)
    assert planes[0, 0] == 80
    assert planes[H - 1, W - 1] == 20
    assert tuple(planes[self.y_height, :2]) == (110, 130)
    assert tuple(planes[self.y_height + H // 2 - 1, W - 2:W]) == (90, 240)
    assert np.all(planes[H:self.y_height] == 0)
    assert np.all(planes[self.y_height + H // 2:] == 0)

  def test_visionipc_frame_metadata_and_cadence(self):
    timestamps = ((1_000_000_000, 1_035_000_000), (1_050_000_000, 1_085_000_000))
    frames = []
    for i in range(2):
      frame = bytearray(self.size)
      frame[0] = i + 10
      frame[self.stride * self.y_height] = i + 11
      frames.append(bytes(frame))

    class FrameSource:
      cam_type_state = SERVICE
      stream_type = STREAM

      def __init__(self):
        self.frames = iter(((10, frames[0], *timestamps[0]), (10, frames[0], *timestamps[0]), (12, frames[1], *timestamps[1])))

      def get_latest_frame(self):
        return next(self.frames)

    self.camerad.cameras = [FrameSource()]
    with self.assertRaises(StopIteration):
      self.camerad.run()

    for i, ((sof, eof), frame) in enumerate(zip(timestamps, frames, strict=True)):
      vipc_frame = self.vipc_client.recv(timeout_ms=1000)
      assert vipc_frame is not None
      assert vipc_frame.frame_id == i
      assert self.vipc_client.timestamp_sof == sof
      assert self.vipc_client.timestamp_eof == eof
      assert self.vipc_client.timestamp_eof > self.vipc_client.timestamp_sof
      assert vipc_frame.data.tobytes() == frame

      state = messaging.recv_one(self.state_sock).narrowRoadCameraState
      assert state.frameId == i
      assert state.timestampSof == sof
      assert state.timestampEof == eof

    assert timestamps[1][0] - timestamps[0][0] == 50_000_000
