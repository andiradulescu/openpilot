# comma zero v2 on macOS

This worktree starts at the public v0.11.2 release commit
`6939d172e85e3b91f16d90cc8de72e8f938cc196`. It contains the local Apple Silicon
adaptations for one NexiGo N60, one red Panda over USB, and the XIAO nRF52840
Sense USB IMU. The earlier `comma-zero-v2` worktree is preserved separately.

## Build

The macOS capture backend uses a native AVFoundation helper built by SCons.
It requires macOS 14 or newer and the Xcode Command Line Tools.

From the repository root, with the pinned submodules and Git LFS files present:

```sh
uv sync --frozen --extra testing --extra tools --extra webcam
source .venv/bin/activate
export PYTHONPATH="$PWD"
scons -j8 --minimal
```

The macOS model build uses Metal and Clang for tinygrad's CPU helper kernels.
Use the same helper setting at runtime:

```sh
export USE_WEBCAM=1
export HCQ_RUNTIME_DEV=CPU:CLANG
```

## Camera

The last implemented camera setting in the old comma zero history is
1280×720 at 25 fps (`21d7e4e4d`, followed by `0f1a9d5c8`). The capture thread
requests that mode and continuously drains frames. The model loop publishes
the newest available frame at up to 20 Hz, with sequential publication IDs.
No duplicate images are published just to fill a missing capture interval.

Both macOS backends require the NexiGo name and never fall back to the internal
MacBook camera or a numeric index. `ROAD_CAM`/`NARROW_ROAD_CAM` cannot override
this selection. Choose the backend explicitly, or leave the native default:

```sh
export WEBCAM_BACKEND=native  # external-only AVFoundation discovery, direct NV12
# export WEBCAM_BACKEND=ffmpeg  # previous FFmpeg AVFoundation/BGR capture path
```

The native backend requires exactly one external USB device named
`NexiGo N60 FHD Webcam`. The FFmpeg backend lists AVFoundation devices and opens
the named NexiGo; it requires Homebrew FFmpeg with AVFoundation support
(`brew install ffmpeg`). Invalid backend names fail before opening a camera.
Grant camera access when macOS asks, then run:

```sh
python -m openpilot.system.camerad.webcam.camerad
```

Frames retain the old mount's 180-degree image rotation. NV12 buffers include
the stride and plane padding expected by the current model kernels. SOF/EOF
carry the AVFoundation presentation timestamp and callback delivery timestamp
on the host monotonic clock for the native backend; they are not verified
exposure-start/end times. FFmpeg uses host pipe-read bounds, so latency numbers
derived from these timestamps cannot be compared directly between backends.
The native helper requests 1280×720 at 25 fps and sends NV12 directly to Python.
The inherited 1477-pixel focal length has not been calibrated for this mounted
camera. Linux still uses OpenCV and host capture-call timestamps.

## macOS backend comparison

Repeated M5 runs on 2026-10-24, two 30-second measurements per backend/workload
in native/FFmpeg/FFmpeg/native order, favored native for the 20 Hz target:

| Measurement | Native | FFmpeg |
|---|---:|---:|
| Camera-only publication rate | 20.04 Hz | 8.91 Hz |
| Camera + consumer + macOS camera-service CPU | 23.2% | 22.3% |
| Camera process group physical footprint | 194 MiB | 300 MiB |
| CPU with both model consumers capped at 8 Hz, including services | 28.0% | 26.7% |
| Whole-GPU utilization with both model consumers at 8 Hz | 8.5% | 9.5% |

100% CPU means one fully occupied core. Native delivered about 2.25 times the
frames for slightly higher service-inclusive CPU. GPU readings include other
apps and are utilization, not watts; background GPU use varied between workload
groups. The FFmpeg path remains selectable, but its integrated ~9 Hz slowdown
is not yet explained. Neither backend is selected automatically based on load.

[Local report, method and raw-data locations](/Volumes/Stuff/openpilot-extra/comma-zero-v2-benchmark/report.md)
include the separate process and shared-service counters and reproduction scripts.

## USB IMU

The companion firmware/project is `nrf52840-sense-imu-companion`. Its XIMU v1
CDC stream carries CRC-protected, timestamped samples with periodic clock
synchronization. `usbimud` converts acceleration to m/s² and angular velocity
to rad/s, rejects stale sessions, and reconnects after a serial disconnect.
The manager enables it on road only when `USB_IMU_PORT` is set.

```sh
export USB_IMU_PORT=/dev/cu.usbmodem1201
export USB_IMU_DEVICE_FROM_SENSOR='-x,y,-z'
python -m openpilot.system.sensord.usbimud
```

The fixed mount has components up and USB pointing backward, opposite the
lens view. The PCB-derived mapping is device `[forward, right, down] = [-x, y, -z]`.
It follows the IMU and USB footprint rotations in the [official Seeed PCB](https://files.seeedstudio.com/wiki/XIAO-BLE/Seeed-Studio-XIAO-nRF52840V1.1-KiCad-Project-260105.zip)
and [ST package axes](https://files.seeedstudio.com/wiki/XIAO-BLE/ST_LSM6DS3TR_Datasheet.pdf).
A physical tilt check remains an independent confirmation. The daemon requires
this explicit proper rotation; the earlier `x,y,z` was only a bench fixture.
The port name can change after reconnection.

## USB Panda and bench operation

The native macOS pandad uses libusb for a single red Panda. The PC Python
launcher starts it without automatic firmware flashing or DFU recovery.
Firmware signature checks remain enabled. The connected Panda was explicitly
flashed, with approval, to the pinned
`DEV-a5919516-DEBUG` application (`a59195163c32a3a375ea6c86715dc08fd0984c1b`).
Its signature matches the built artifact, SHA-256
`6d1ab7b388087822aed81dcb924815fdd4bac6b05b3eb38c449f88abdfbdb1fc`.
The bootstub was preserved. Do not bypass the firmware check.

With the matching firmware and camera access established, a local bench
manager session can use the environment above and:

```sh
export OPENPILOT_PREFIX=comma-zero-v2-bench
export BLOCK=manage_athenad,uploader
export FAKESEND=1
python -m openpilot.system.manager.manager
```

`FAKESEND` disables the daemon's sendcan forwarding. The separate prefix keeps
bench parameters and logs apart. Without ignition/CAN the manager stays
off road; the direct camera and IMU commands allow separate sensor checks.

This road-camera-only setup has no cabin stream. Normal driver-monitoring
requirements remain in place, so this is a bench integration, not a validated
engageable system. A cabin camera also needs matching runtime intrinsics in
`dmonitoringmodeld.py`. Camera calibration, mount motion checks, and
longer-duration stability checks remain acceptance steps.

## Linux implementation locations

- USB Panda selection belongs in `pandad/panda.cc` and `panda_comms.h`, with
  libusb linkage in `pandad/SConscript`. Keep SPI for comma hardware. Linux
  USB selection is deliberately not enabled by this macOS change.
- Camera capture is in `webcam/camera.py`; replace the OpenCV capture boundary
  with V4L2 when adding sensor timestamps and mode verification on Linux.
- The IMU CDC protocol is portable. Select `/dev/serial/by-id/...` and validate
  serial permissions, clock synchronization, and reconnects on the Linux host.

## Checks

```sh
python tools/test_runner.py openpilot/system/camerad/webcam/tests/test_webcam.py openpilot/system/sensord/tests/test_usbimud.py
openpilot/selfdrive/pandad/tests/test_pandad_canprotocol
openpilot/selfdrive/pandad/tests/test_pandad_usb_transport
```

The Python tests cover NV12 pixels/padding and real VisionIPC/message metadata,
plus IMU units, rotation, CRC/session rejection, and real PTY reconnects. These
do not substitute for real-camera timing or Jungle CAN checks.

Local validation on 2026-10-24:

- `scons -j8 --minimal` completed, and the 1280×720 `ModelState.warmup()` ran
  on Metal with `HCQ_RUNTIME_DEV=CPU:CLANG`.
- The camera/IMU test command above passed all 14 tests; scoped Ruff and
  `git diff --check` passed. The native CAN protocol test and offline USB
  short-write regression test passed. A successful partial USB write now marks
  the transport disconnected and unhealthy.
- The existing companion manager tests passed 2/2. Its older PTY integration
  suite passed 19/20: its periodic-sync responder can delay a response beyond
  the production 10 ms RTT bound. The new in-tree PTY test responds immediately
  and checks periodic sync/reconnect without relaxing that bound.
- A read-only four-second IMU sample contained 409 records, approximately
  102.13 Hz. Physical sensor-to-device motion validation remains outstanding.
- Native external-only capture returned 718 frames in a 30-second probe,
  approximately 24.34 fps. The selected device was USB NexiGo UID
  `0x130000344360bb`; the started mode was 1280×720 with 40 ms min/max intervals.
  AVFoundation PTS-to-callback delay was about 70.7 ms at the median.
- During a repeat external-only NexiGo capture, Andi confirmed that the physical
  LED beside the MacBook camera lens stayed off.
- Repeating the previous FFmpeg path, including AVFoundation camera listing
  followed by named NexiGo capture, also left the MacBook lens LED off according
  to Andi. The earlier reported activation was not reproduced; its cause is
  unconfirmed.
- A 30-second combined run processed 584 real camera frames through the Metal
  model at 19.93 Hz, with no publication-ID gaps and finite model outputs.
  Median inference was 9.04 ms (maximum 30.82 ms); the IMU published at
  102.09 Hz with advancing timestamps. All camera/IMU/Panda messages were valid,
  and Panda stayed in `noOutput`, controls disallowed, with zero transmissions.
  All bench processes stopped afterward.
- Live Panda and IMU publication passed. The Jungle sent 300 marked CAN frames;
  native pandad received all 300 exactly once, 100 on each bus, with zero invalid
  messages. Panda remained in `noOutput` with controls disallowed and zero CAN
  transmissions. Jungle ignition was returned off. The installed older Jungle
  used its existing matching client; no Jungle firmware was changed.
- A red Panda application reset interrupted USB reception; the native daemon
  exited and the Python supervisor reconnected to valid Panda states without
  flashing.
- No vehicle/engagement validation has been performed.
