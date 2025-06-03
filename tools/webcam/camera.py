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
        raise IOError(f"Unable to open camera {camera_id}")

    self.configure_camera_format("MJPG")
    actual_format = self.get_current_format()
    print("format: ", actual_format)

    self.fps = self.cap.get(cv.CAP_PROP_FPS)
    print(f"fps: {self.fps}")

    self.W = self.cap.get(cv.CAP_PROP_FRAME_WIDTH)
    self.H = self.cap.get(cv.CAP_PROP_FRAME_HEIGHT)
    print(f"width: {self.W}, height: {self.H}")

  def configure_camera_format(self, target_fourcc):
    print(f"target_fourcc: {target_fourcc}")
    # fourcc = cv.VideoWriter_fourcc(*target_fourcc)
    # self.cap.set(cv.CAP_PROP_FOURCC, fourcc)
    # self.cap.set(cv.CAP_PROP_FOURCC, fourcc)
    # self.cap.set(cv.CAP_PROP_FRAME_WIDTH, 1280)
    # self.cap.set(cv.CAP_PROP_FRAME_HEIGHT, 720)
    # self.cap.set(cv.CAP_PROP_FPS, 20)

  def get_current_format(self):
    fourcc_code = int(self.cap.get(cv.CAP_PROP_FOURCC))
    return ''.join([chr((fourcc_code >> 8 * i) & 0xFF) for i in range(4)])

  @classmethod
  def bgr2nv12(self, bgr):
    frame = av.VideoFrame.from_ndarray(bgr, format='bgr24')
    return frame.reformat(format='nv12').to_ndarray()

  def read_frames(self):
    try:
      while True:
        ret, frame = self.cap.read()
        if not ret:
          print ("cv can't receive frame")
          break
        # Rotate the frame 180 degrees (flip both axes)
        frame = cv.flip(frame, -1)
        yuv = Camera.bgr2nv12(frame)
        yield yuv.data.tobytes()
    except cv.error as error:
      print(f"cv error: {error}")
    self.cap.release()
