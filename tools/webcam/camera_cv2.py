import av
import cv2 as cv

class Camera:
  def __init__(self, cam_type_state, stream_type, camera_id):
    try:
      camera_id = int(camera_id)
    except ValueError: # allow strings, ex: /dev/video0
      pass
    self.cam_type_state = cam_type_state
    self.stream_type = stream_type
    self.cur_frame_id = 0

    self.cap = cv.VideoCapture(camera_id)
    if not self.cap.isOpened():
      raise AssertionError(f"Can't open video stream for camera {camera_id}")

    # Force 1920x1080 at 30 FPS
    self.cap.set(cv.CAP_PROP_FRAME_WIDTH, 1920)
    self.cap.set(cv.CAP_PROP_FRAME_HEIGHT, 1080)
    self.cap.set(cv.CAP_PROP_FPS, 30)

    self.W = self.cap.get(cv.CAP_PROP_FRAME_WIDTH)
    self.H = self.cap.get(cv.CAP_PROP_FRAME_HEIGHT)
    self.fps = self.cap.get(cv.CAP_PROP_FPS)

    # Print OpenCV configuration
    print("OpenCV Configuration:")
    print(f"  Resolution: {int(self.W)}x{int(self.H)}")
    print(f"  Frame Rate: {self.fps:.1f} FPS")
    print(f"  Buffer Size: {int(self.cap.get(cv.CAP_PROP_BUFFERSIZE))}")
    fourcc = int(self.cap.get(cv.CAP_PROP_FOURCC))
    codec = "".join([chr((fourcc >> 8 * i) & 0xFF) for i in range(4)])
    print(f"  Codec: {codec}")

  @classmethod
  def bgr2nv12(self, bgr):
    frame = av.VideoFrame.from_ndarray(bgr, format='bgr24')
    return frame.reformat(format='nv12').to_ndarray()

  def read_frames(self):
    while True:
      ret, frame = self.cap.read()
      if not ret:
        break
      yuv = Camera.bgr2nv12(frame)
      yield yuv.data.tobytes()
    self.cap.release()
