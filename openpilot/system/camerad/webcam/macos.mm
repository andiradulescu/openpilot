#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <IOKit/audio/IOAudioTypes.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr char kCameraName[] = "NexiGo N60 FHD Webcam";
constexpr int kWidth = 1280;
constexpr int kHeight = 720;
constexpr int kFps = 25;
constexpr size_t kFrameBytes = kWidth * kHeight * 3 / 2;

std::atomic<bool> running{true};
static_assert(std::atomic<bool>::is_always_lock_free);

uint64_t host_time_ns() {
  const CMTime host_time = CMClockGetTime(CMClockGetHostTimeClock());
  return CMTimeConvertScale(host_time, 1000000000, kCMTimeRoundingMethod_Default).value;
}

bool write_all(const void *buffer, size_t size) {
  const uint8_t *p = static_cast<const uint8_t *>(buffer);
  while (size > 0) {
    const ssize_t written = write(STDOUT_FILENO, p, size);
    if (written > 0) {
      p += written;
      size -= written;
    } else if (written < 0 && errno == EINTR) {
      continue;
    } else if (written < 0 && errno == EPIPE) {
      running.store(false, std::memory_order_relaxed);
      return false;
    } else {
      std::fprintf(stderr, "webcam: stdout write failed: %s\n", std::strerror(errno));
      running.store(false, std::memory_order_relaxed);
      return false;
    }
  }
  return true;
}

void stop(int) {
  running.store(false, std::memory_order_relaxed);
}

}  // namespace

@interface FrameWriter : NSObject<AVCaptureVideoDataOutputSampleBufferDelegate> {
@private
  std::vector<uint8_t> frame_;
}
@end

@implementation FrameWriter

- (instancetype)init {
  self = [super init];
  if (self) {
    frame_.resize(kFrameBytes);
  }
  return self;
}

- (void)captureOutput:(AVCaptureOutput *)output
 didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
        fromConnection:(AVCaptureConnection *)connection {
  (void)output;
  (void)connection;
  if (!running.load(std::memory_order_relaxed)) return;

  const uint64_t delivery_ns = host_time_ns();
  const CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
  if (!CMTIME_IS_VALID(pts) || !CMTIME_IS_NUMERIC(pts)) {
    std::fprintf(stderr, "webcam: capture frame has invalid presentation timestamp\n");
    running.store(false, std::memory_order_relaxed);
    return;
  }
  const CMTime pts_ns_time = CMTimeConvertScale(pts, 1000000000, kCMTimeRoundingMethod_Default);
  if (!CMTIME_IS_VALID(pts_ns_time) || pts_ns_time.value < 0) {
    std::fprintf(stderr, "webcam: capture frame has unusable presentation timestamp\n");
    running.store(false, std::memory_order_relaxed);
    return;
  }
  const uint64_t pts_ns = pts_ns_time.value;
  if (pts_ns > delivery_ns || delivery_ns - pts_ns > 1000000000ULL) {
    std::fprintf(stderr, "webcam: AVFoundation PTS is not a recent host-clock timestamp\n");
    running.store(false, std::memory_order_relaxed);
    return;
  }

  CVImageBufferRef image = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (image == nullptr || CVPixelBufferGetPixelFormatType(image) != kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
      CVPixelBufferGetWidth(image) != kWidth || CVPixelBufferGetHeight(image) != kHeight ||
      CVPixelBufferGetPlaneCount(image) != 2 || CVPixelBufferLockBaseAddress(image, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) {
    if (image != nullptr) {
      std::fprintf(stderr, "webcam: unexpected frame format=%#x size=%zux%zu planes=%zu\n",
                   static_cast<unsigned int>(CVPixelBufferGetPixelFormatType(image)),
                   CVPixelBufferGetWidth(image), CVPixelBufferGetHeight(image), CVPixelBufferGetPlaneCount(image));
    } else {
      std::fprintf(stderr, "webcam: capture frame has no image buffer\n");
    }
    running.store(false, std::memory_order_relaxed);
    return;
  }

  const size_t y_stride = CVPixelBufferGetBytesPerRowOfPlane(image, 0);
  const size_t uv_stride = CVPixelBufferGetBytesPerRowOfPlane(image, 1);
  const size_t y_height = CVPixelBufferGetHeightOfPlane(image, 0);
  const size_t uv_height = CVPixelBufferGetHeightOfPlane(image, 1);
  const uint8_t *y = static_cast<const uint8_t *>(CVPixelBufferGetBaseAddressOfPlane(image, 0));
  const uint8_t *uv = static_cast<const uint8_t *>(CVPixelBufferGetBaseAddressOfPlane(image, 1));
  if (y == nullptr || uv == nullptr || y_stride < kWidth || uv_stride < kWidth || y_height != kHeight || uv_height != kHeight / 2) {
    CVPixelBufferUnlockBaseAddress(image, kCVPixelBufferLock_ReadOnly);
    std::fprintf(stderr, "webcam: invalid NV12 plane layout\n");
    running.store(false, std::memory_order_relaxed);
    return;
  }

  for (int row = 0; row < kHeight; ++row) {
    std::memcpy(frame_.data() + row * kWidth, y + row * y_stride, kWidth);
  }
  for (int row = 0; row < kHeight / 2; ++row) {
    std::memcpy(frame_.data() + kWidth * kHeight + row * kWidth, uv + row * uv_stride, kWidth);
  }
  CVPixelBufferUnlockBaseAddress(image, kCVPixelBufferLock_ReadOnly);

  const uint64_t header[] = {CFSwapInt64HostToLittle(pts_ns), CFSwapInt64HostToLittle(delivery_ns)};
  if (!write_all(header, sizeof(header))) return;
  write_all(frame_.data(), frame_.size());
}

@end

AVCaptureDevice *find_camera() {
  if (@available(macOS 14.0, *)) {
    AVCaptureDeviceDiscoverySession *discovery = [AVCaptureDeviceDiscoverySession
      discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeExternal]
      mediaType:AVMediaTypeVideo
      position:AVCaptureDevicePositionUnspecified];
    AVCaptureDevice *selected = nil;
    for (AVCaptureDevice *device in discovery.devices) {
      if ([device.localizedName isEqualToString:[NSString stringWithUTF8String:kCameraName]] && device.transportType == kIOAudioDeviceTransportTypeUSB) {
        if (selected != nil) {
          std::fprintf(stderr, "webcam: multiple USB cameras named %s\n", kCameraName);
          return nil;
        }
        selected = device;
      }
    }
    return selected;
  }
  std::fprintf(stderr, "webcam: macOS 14 or newer is required for external-only camera discovery\n");
  return nil;
}

AVCaptureDeviceFormat *find_format(AVCaptureDevice *device) {
  for (AVCaptureDeviceFormat *format in device.formats) {
    const CMVideoDimensions dimensions = CMVideoFormatDescriptionGetDimensions(format.formatDescription);
    if (dimensions.width != kWidth || dimensions.height != kHeight) continue;
    for (AVFrameRateRange *range in format.videoSupportedFrameRateRanges) {
      if (range.minFrameRate <= kFps && kFps <= range.maxFrameRate) return format;
    }
  }
  return nil;
}

int main() {
  @autoreleasepool {
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    signal(SIGPIPE, SIG_DFL);

    AVCaptureDevice *device = find_camera();
    if (device == nil) {
      std::fprintf(stderr, "webcam: required USB camera %s is unavailable\n", kCameraName);
      return 1;
    }
    AVCaptureDeviceFormat *format = find_format(device);
    if (format == nil) {
      std::fprintf(stderr, "webcam: %s does not support %dx%d@%d\n", kCameraName, kWidth, kHeight, kFps);
      return 1;
    }

    NSError *error = nil;
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:device error:&error];
    AVCaptureVideoDataOutput *output = [[AVCaptureVideoDataOutput alloc] init];
    output.alwaysDiscardsLateVideoFrames = YES;
    FrameWriter *writer = [[FrameWriter alloc] init];
    dispatch_queue_t queue = dispatch_queue_create("webcam.nexigo", DISPATCH_QUEUE_SERIAL);

    AVCaptureSession *session = [[AVCaptureSession alloc] init];
    if (input == nil || ![session canAddInput:input] || ![session canAddOutput:output]) {
      std::fprintf(stderr, "webcam: cannot configure capture session: %s\n", error.localizedDescription.UTF8String ?: "unknown error");
      return 1;
    }
    [session beginConfiguration];
    [session addInput:input];
    if (![session canSetSessionPreset:AVCaptureSessionPreset1280x720]) {
      std::fprintf(stderr, "webcam: capture session cannot produce %dx%d\n", kWidth, kHeight);
      return 1;
    }
    session.sessionPreset = AVCaptureSessionPreset1280x720;
    [session addOutput:output];
    [session commitConfiguration];
    if (![device lockForConfiguration:&error]) {
      std::fprintf(stderr, "webcam: cannot configure %s: %s\n", kCameraName, error.localizedDescription.UTF8String);
      return 1;
    }
    device.activeFormat = format;
    device.activeVideoMinFrameDuration = CMTimeMake(1, kFps);
    device.activeVideoMaxFrameDuration = CMTimeMake(1, kFps);
    output.videoSettings = @{
      (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange),
      (id)kCVPixelBufferWidthKey: @(kWidth),
      (id)kCVPixelBufferHeightKey: @(kHeight),
    };
    std::fprintf(stderr, "webcam: selected %s uid=%s transport=USB\n", device.localizedName.UTF8String, device.uniqueID.UTF8String);
    // AVFoundation resets the active mode if this lock is released before the session starts.
    [session startRunning];
    const CMVideoDimensions dimensions = CMVideoFormatDescriptionGetDimensions(device.activeFormat.formatDescription);
    const CMTime min_duration = device.activeVideoMinFrameDuration;
    const CMTime max_duration = device.activeVideoMaxFrameDuration;
    std::fprintf(stderr, "webcam: started %dx%d min=%.6f max=%.6f\n", dimensions.width, dimensions.height,
                 CMTimeGetSeconds(min_duration), CMTimeGetSeconds(max_duration));
    [device unlockForConfiguration];
    if (dimensions.width != kWidth || dimensions.height != kHeight ||
        CMTimeCompare(min_duration, CMTimeMake(1, kFps)) != 0 ||
        CMTimeCompare(max_duration, CMTimeMake(1, kFps)) != 0) {
      std::fprintf(stderr, "webcam: camera did not start at %dx%d@%d\n", kWidth, kHeight, kFps);
      [session stopRunning];
      return 1;
    }
    [output setSampleBufferDelegate:writer queue:queue];

    while (running.load(std::memory_order_relaxed)) {
      CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, false);
    }
    [session stopRunning];
  }
  return 0;
}
