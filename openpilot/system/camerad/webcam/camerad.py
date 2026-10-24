#!/usr/bin/env python3
import os
import platform
from collections import namedtuple

from openpilot.cereal.visionipc import VisionStreamType
from msgq.visionipc import VisionIpcServer
from openpilot.cereal import messaging

from openpilot.system.camerad.webcam.camera import Camera, NEXIGO_N60
from openpilot.system.camerad.cameras.nv12_info import get_nv12_info
from openpilot.common.realtime import Ratekeeper

NARROW_ROAD_CAM = NEXIGO_N60 if platform.system() == 'Darwin' else os.getenv("NARROW_ROAD_CAM", os.getenv("ROAD_CAM", "0"))
WIDE_CAM = os.getenv("WIDE_CAM")
DRIVER_CAM = os.getenv("DRIVER_CAM")

CameraType = namedtuple("CameraType", ["msg_name", "stream_type", "cam_id"])

CAMERAS = [
  CameraType("narrowRoadCameraState", VisionStreamType.VISION_STREAM_NARROW_ROAD, NARROW_ROAD_CAM)
]
if WIDE_CAM:
  CAMERAS.append(CameraType("wideRoadCameraState", VisionStreamType.VISION_STREAM_WIDE_ROAD, WIDE_CAM))
if DRIVER_CAM:
  CAMERAS.append(CameraType("cabinCameraState", VisionStreamType.VISION_STREAM_CABIN, DRIVER_CAM))

class Camerad:
  def __init__(self):
    self.pm = messaging.PubMaster([c.msg_name for c in CAMERAS])
    self.vipc_server = VisionIpcServer("camerad")

    self.cameras = []
    for c in CAMERAS:
      cam_device = f"/dev/video{c.cam_id}" if platform.system() != "Darwin" else c.cam_id
      cam = Camera(c.msg_name, c.stream_type, cam_device)
      self.cameras.append(cam)
      stride, y_height, _, size = get_nv12_info(cam.W, cam.H)
      self.vipc_server.create_buffers_with_sizes(c.stream_type, 20, cam.W, cam.H, size, stride, stride * y_height)

    self.vipc_server.start_listener()

  def _send_yuv(self, yuv, frame_id, sof, eof, pub_type, yuv_type):
    self.vipc_server.send(yuv_type, yuv, frame_id, sof, eof)
    dat = messaging.new_message(pub_type, valid=True)
    msg = {
      "frameId": frame_id,
      "timestampSof": sof,
      "timestampEof": eof,
      "transform": [1.0, 0.0, 0.0,
                    0.0, 1.0, 0.0,
                    0.0, 0.0, 1.0]
    }
    setattr(dat, pub_type, msg)
    self.pm.send(pub_type, dat)

  def run(self):
    rk = Ratekeeper(20, None)
    last_capture_ids = dict.fromkeys(self.cameras, -1)
    frame_ids = dict.fromkeys(self.cameras, 0)
    while True:
      for cam in self.cameras:
        frame = cam.get_latest_frame()
        if frame is not None:
          capture_frame_id, yuv, sof, eof = frame
          if capture_frame_id != last_capture_ids[cam]:
            self._send_yuv(yuv, frame_ids[cam], sof, eof, cam.cam_type_state, cam.stream_type)
            last_capture_ids[cam] = capture_frame_id
            frame_ids[cam] += 1
      rk.keep_time()


def main():
  camerad = Camerad()
  try:
    camerad.run()
  finally:
    for cam in camerad.cameras:
      cam.close()


if __name__ == "__main__":
  main()
