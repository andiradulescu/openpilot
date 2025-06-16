#!/usr/bin/env python3
"""
Benchmark script to compare pyav vs opencv camera implementations.
Tests memory usage, CPU usage, frame rate, and latency.
"""

import time
import psutil
import numpy as np
import gc
import argparse
import sys
import os

# Add the webcam directory to the path so we can import both implementations
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import camera_av
    AV_AVAILABLE = True
except ImportError:
    print("Warning: pyav implementation not available")
    AV_AVAILABLE = False

try:
    import camera_cv2
    CV2_AVAILABLE = True
except ImportError:
    print("Warning: opencv implementation not available")
    CV2_AVAILABLE = False

class PerformanceMetrics:
    def __init__(self):
        self.frame_times = []
        self.memory_usage = []
        self.cpu_usage = []
        self.frame_count = 0
        self.start_time = None
        self.end_time = None
        self.process = psutil.Process()
        self.last_cpu_time = None

    def start_monitoring(self):
        self.start_time = time.time()
        # Initialize CPU monitoring
        self.process.cpu_percent()
        self.last_cpu_time = time.time()

    def record_frame(self, frame_size: int):
        current_time = time.time()
        self.frame_times.append(current_time)
        self.frame_count += 1

        # Record memory usage
        self.memory_usage.append(self.process.memory_info().rss / 1024 / 1024)  # MB

        # Record CPU usage every 0.1 seconds to get meaningful measurements
        if current_time - self.last_cpu_time >= 0.1:
            cpu_pct = self.process.cpu_percent()
            if cpu_pct >= 0:  # cpu_percent can return negative on first calls
                self.cpu_usage.append(cpu_pct)
            self.last_cpu_time = current_time

    def finish_monitoring(self):
        self.end_time = time.time()

    def get_stats(self) -> dict:
        if len(self.frame_times) < 2:
            return {}

        total_time = self.end_time - self.start_time
        avg_fps = self.frame_count / total_time

        # Calculate frame intervals
        intervals = [self.frame_times[i] - self.frame_times[i-1]
                    for i in range(1, len(self.frame_times))]

        return {
            'total_frames': self.frame_count,
            'total_time': total_time,
            'avg_fps': avg_fps,
            'frame_interval_avg': np.mean(intervals) if intervals else 0,
            'frame_interval_std': np.std(intervals) if intervals else 0,
            'memory_avg_mb': np.mean(self.memory_usage) if self.memory_usage else 0,
            'memory_max_mb': np.max(self.memory_usage) if self.memory_usage else 0,
            'cpu_avg_percent': np.mean(self.cpu_usage) if self.cpu_usage else 0,
            'cpu_max_percent': np.max(self.cpu_usage) if self.cpu_usage else 0
        }

def benchmark_camera_implementation(camera_class, camera_id: int, duration: float = 30.0,
                                   cam_type: str = "webcam") -> dict:
    """Benchmark a camera implementation for the specified duration."""
    print(f"Benchmarking {camera_class.__module__} for {duration} seconds...")

    metrics = PerformanceMetrics()

    try:
        # Initialize camera
        camera = camera_class(cam_type, "road", camera_id)
        print(f"Camera initialized: {camera.W}x{camera.H}")

        metrics.start_monitoring()

        # Capture frames for the specified duration
        start_time = time.time()
        for frame_data in camera.read_frames():
            current_time = time.time()

            if current_time - start_time >= duration:
                break

            metrics.record_frame(len(frame_data))

            # Small delay to prevent overwhelming the system
            time.sleep(0.001)

        metrics.finish_monitoring()

        # Clean up
        if hasattr(camera, 'cap') and camera.cap:
            camera.cap.release()
        if hasattr(camera, 'container') and camera.container:
            camera.container.close()

    except Exception as e:
        print(f"Error during benchmark: {e}")
        return {}

    # Force garbage collection
    gc.collect()

    return metrics.get_stats()

def memory_usage_test(camera_class, camera_id: int, iterations: int = 100) -> dict:
    """Test memory usage over multiple camera init/destroy cycles."""
    print(f"Testing memory usage for {camera_class.__module__} over {iterations} iterations...")

    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB

    memory_samples = []

    for i in range(iterations):
        try:
            camera = camera_class("webcam", "road", camera_id)

            # Capture a few frames
            frame_gen = camera.read_frames()
            for _ in range(5):
                try:
                    next(frame_gen)
                except StopIteration:
                    break

            # Clean up
            if hasattr(camera, 'cap') and camera.cap:
                camera.cap.release()
            if hasattr(camera, 'container') and camera.container:
                camera.container.close()

            del camera
            gc.collect()

            current_memory = process.memory_info().rss / 1024 / 1024
            memory_samples.append(current_memory)

        except Exception as e:
            print(f"Error in iteration {i}: {e}")
            continue

    final_memory = process.memory_info().rss / 1024 / 1024

    return {
        'initial_memory_mb': initial_memory,
        'final_memory_mb': final_memory,
        'memory_growth_mb': final_memory - initial_memory,
        'memory_samples': memory_samples,
        'avg_memory_mb': np.mean(memory_samples) if memory_samples else 0,
        'max_memory_mb': np.max(memory_samples) if memory_samples else 0
    }

def format_benchmark_results(results: dict, implementation: str) -> str:
    """Format benchmark results for display."""
    if not results:
        return f"{implementation}: FAILED TO RUN"

    output = f"\n{implementation} Results:\n"
    output += "=" * 50 + "\n"
    output += f"Total Frames: {results.get('total_frames', 'N/A')}\n"
    output += f"Total Time: {results.get('total_time', 0):.2f}s\n"
    output += f"Average FPS: {results.get('avg_fps', 0):.2f}\n"
    output += f"Frame Interval: {results.get('frame_interval_avg', 0)*1000:.2f}ms (±{results.get('frame_interval_std', 0)*1000:.2f}ms)\n"
    output += f"Memory Usage: {results.get('memory_avg_mb', 0):.1f}MB avg, {results.get('memory_max_mb', 0):.1f}MB max\n"
    output += f"CPU Usage: {results.get('cpu_avg_percent', 0):.1f}% avg, {results.get('cpu_max_percent', 0):.1f}% max\n"

    return output

def main():
    parser = argparse.ArgumentParser(description="Benchmark camera implementations")
    parser.add_argument("--camera-id", type=int, default=0, help="Camera ID to use")
    parser.add_argument("--duration", type=float, default=30.0, help="Benchmark duration in seconds")
    parser.add_argument("--memory-test", action="store_true", help="Run memory leak test")
    parser.add_argument("--implementations", nargs="+", choices=["av", "cv2", "both"],
                       default=["both"], help="Which implementations to test")

    args = parser.parse_args()

    print("Camera Implementation Benchmark")
    print("=" * 50)
    print(f"Camera ID: {args.camera_id}")
    print(f"Duration: {args.duration}s")
    print(f"System: {psutil.cpu_count()} CPUs, {psutil.virtual_memory().total / 1024**3:.1f}GB RAM")

    results = {}

    # Test pyav implementation
    if ("av" in args.implementations or "both" in args.implementations) and AV_AVAILABLE:
        try:
            results['pyav'] = benchmark_camera_implementation(
                camera_av.Camera, args.camera_id, args.duration
            )
            print(format_benchmark_results(results['pyav'], "PyAV"))

            if args.memory_test:
                memory_results = memory_usage_test(camera_av.Camera, args.camera_id)
                print(f"PyAV Memory Test: {memory_results['memory_growth_mb']:.1f}MB growth over 100 cycles")

        except Exception as e:
            print(f"PyAV benchmark failed: {e}")
            results['pyav'] = {}

    # Test opencv implementation
    if ("cv2" in args.implementations or "both" in args.implementations) and CV2_AVAILABLE:
        try:
            results['opencv'] = benchmark_camera_implementation(
                camera_cv2.Camera, args.camera_id, args.duration
            )
            print(format_benchmark_results(results['opencv'], "OpenCV"))

            if args.memory_test:
                memory_results = memory_usage_test(camera_cv2.Camera, args.camera_id)
                print(f"OpenCV Memory Test: {memory_results['memory_growth_mb']:.1f}MB growth over 100 cycles")

        except Exception as e:
            print(f"OpenCV benchmark failed: {e}")
            results['opencv'] = {}

    # Compare results
    if 'pyav' in results and 'opencv' in results and results['pyav'] and results['opencv']:
        print("\nComparison Summary:")
        print("=" * 50)

        pyav_fps = results['pyav'].get('avg_fps', 0)
        opencv_fps = results['opencv'].get('avg_fps', 0)

        pyav_memory = results['pyav'].get('memory_avg_mb', 0)
        opencv_memory = results['opencv'].get('memory_avg_mb', 0)

        pyav_cpu = results['pyav'].get('cpu_avg_percent', 0)
        opencv_cpu = results['opencv'].get('cpu_avg_percent', 0)

        print(f"FPS: PyAV {pyav_fps:.2f} vs OpenCV {opencv_fps:.2f} ({'PyAV' if pyav_fps > opencv_fps else 'OpenCV'} wins by {abs(pyav_fps - opencv_fps):.2f})")

        print(f"Memory: PyAV {pyav_memory:.1f}MB vs OpenCV {opencv_memory:.1f}MB ({'PyAV' if pyav_memory < opencv_memory else 'OpenCV'} wins by {abs(pyav_memory - opencv_memory):.1f}MB)")

        print(f"CPU: PyAV {pyav_cpu:.1f}% vs OpenCV {opencv_cpu:.1f}% ({'PyAV' if pyav_cpu < opencv_cpu else 'OpenCV'} wins by {abs(pyav_cpu - opencv_cpu):.1f}%)")

if __name__ == "__main__":
    main()
