#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from typing import Dict


def parse_flags_to_env(flags: str) -> Dict[str, str]:
  env_overrides: Dict[str, str] = {}
  if not flags:
    return env_overrides
  for token in flags.split():
    if '=' in token:
      k, v = token.split('=', 1)
      if k:
        env_overrides[k] = v
  return env_overrides


def run_compile(tinygrad_dir: str, onnx_path: str, out_path: str, flags: str) -> int:
  env = os.environ.copy()
  # Ensure PYTHONPATH contains tinygrad
  env['PYTHONPATH'] = (env.get('PYTHONPATH', '') + (':' if env.get('PYTHONPATH') else '') + tinygrad_dir)
  # Apply flag environment variables (e.g., GPU=1, CPU=1, IMAGE=0, JIT=2)
  env.update(parse_flags_to_env(flags))

  compile_py = os.path.join(tinygrad_dir, 'examples', 'openpilot', 'compile3.py')
  cmd = [sys.executable, compile_py, onnx_path, out_path]
  try:
    proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
      sys.stderr.write(proc.stdout)
      sys.stderr.write(proc.stderr)
    return proc.returncode
  except FileNotFoundError as e:
    sys.stderr.write(f"[tg-fallback] Failed to execute compile: {e}\n")
    return 127


def main() -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument('--tinygrad-dir', required=True)
  ap.add_argument('--onnx', required=True)
  ap.add_argument('--out', required=True)
  ap.add_argument('--flags', default='')
  ap.add_argument('--cpu-flags', default='CPU=1 IMAGE=0 JIT=2')
  args = ap.parse_args()

  # Primary attempt
  rc = run_compile(args.tinygrad_dir, args.onnx, args.out, args.flags)
  if rc == 0:
    return 0

  sys.stderr.write(f"[tg-fallback] Primary compile failed with flags '{args.flags}'. Falling back to CPU…\n")
  rc2 = run_compile(args.tinygrad_dir, args.onnx, args.out, args.cpu_flags)
  if rc2 == 0:
    sys.stderr.write("[tg-fallback] CPU fallback succeeded.\n")
    return 0

  sys.stderr.write(f"[tg-fallback] CPU fallback also failed (rc={rc2}).\n")
  return rc2


if __name__ == '__main__':
  sys.exit(main())