#!/usr/bin/env python3
import os
import subprocess
import sys

def compile_model(backend_flags, onnx_file, output_file, tinygrad_path):
  env = os.environ.copy()
  env["PYTHONPATH"] = f"{env.get('PYTHONPATH', '')}:{tinygrad_path}"

  print(f"Compiling model with flags: '{backend_flags}'")

  # Parse backend_flags and add to env
  for flag in backend_flags.split():
    try:
      key, value = flag.split('=')
      env[key] = value
    except ValueError:
      print(f"Warning: Could not parse flag: {flag}")

  cmd = ['python3', f'{tinygrad_path}/examples/openpilot/compile3.py', onnx_file, output_file]

  print(f"Executing: {' '.join(cmd)} with env {backend_flags}")
  ret = subprocess.call(cmd, env=env)

  return ret

if __name__ == "__main__":
  backend_flags = sys.argv[1].strip('"')
  onnx_file = sys.argv[2]
  output_file = sys.argv[3]
  tinygrad_path = sys.argv[4]

  ret = compile_model(backend_flags, onnx_file, output_file, tinygrad_path)

  if ret != 0 and "CPU=1" not in backend_flags:
    cpu_flags = "CPU=1 IMAGE=0 JIT=2"
    print(f"Compilation with '{backend_flags}' failed, falling back to '{cpu_flags}'")
    ret = compile_model(cpu_flags, onnx_file, output_file, tinygrad_path)

  sys.exit(ret)
