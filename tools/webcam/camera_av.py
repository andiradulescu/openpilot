import av
import platform

class Camera:
  def __init__(self, cam_type_state, stream_type, camera_id):
    try:
      camera_id = int(camera_id)
    except ValueError: # allow strings, ex: /dev/video0
      pass
    self.cam_type_state = cam_type_state
    self.stream_type = stream_type
    self.cur_frame_id = 0

    self.fps = "30"

    if platform.system() == "Darwin":
      self.container = av.open(str(camera_id), format='avfoundation',
                              container_options={"framerate": self.fps, "video_size": "1920x1080"})
    else:
      self.container = av.open(f"/dev/video{camera_id}")

    assert self.container.streams.video, f"Can't open video stream for camera {camera_id}"
    self.video_stream = self.container.streams.video[0]
    self.W = self.video_stream.codec_context.width
    self.H = self.video_stream.codec_context.height

    # Print PyAV configuration
    print("PyAV Configuration:")
    print(f"  Resolution: {self.W}x{self.H}")
    print(f"  Frame Rate: {self.fps} FPS")

  @classmethod
  def bgr2nv12(self, bgr):
    frame = av.VideoFrame.from_ndarray(bgr, format='bgr24')
    return frame.reformat(format='nv12').to_ndarray()

  def read_frames(self):
    # https://pyav.basswood-io.com/docs/stable/cookbook/basics.html#recording-a-facecam
    try:
      while True:
        try:
          for frame in self.container.decode(self.video_stream):
            img = frame.to_rgb().to_ndarray()[:,:, ::-1] # convert to bgr24
            yuv = Camera.bgr2nv12(img)
            yield yuv.data.tobytes()
        except av.BlockingIOError:
            pass
    finally:
      self.container.close()
