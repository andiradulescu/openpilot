#!/usr/bin/env python3
import os
import sys
import subprocess


def run(tg_dir: str, onnx: str, outp: str, env: dict) -> int:
  env = env.copy()
  env['PYTHONPATH'] = (env.get('PYTHONPATH', '') + (':' if env.get('PYTHONPATH') else '') + tg_dir)
  cmd = [sys.executable, os.path.join(tg_dir, 'examples', 'openpilot', 'compile3.py'), onnx, outp]
  p = subprocess.run(cmd, env=env)
  return p.returncode


def main() -> int:
  if len(sys.argv) != 4:
    print(f"usage: {sys.argv[0]} TINYGRAD_DIR ONNX_PATH OUT_PATH", file=sys.stderr)
    return 2
  tg_dir, onnx, outp = sys.argv[1:4]

  # try with current backend env (e.g., GPU=1, METAL=1, etc.)
  rc = run(tg_dir, onnx, outp, os.environ)
  if rc == 0:
    return 0

  # fallback to CPU
  fb = os.environ.copy()
  for k in [
    'QCOM', 'METAL', 'GPU', 'LLVM', 'BEAM', 'AMD', 'AMD_IFACE', 'AMD_LLVM', 'NOLOCALS', 'IMAGE', 'JIT'
  ]:
    fb.pop(k, None)
  fb['CPU'] = '1'
  fb['IMAGE'] = '0'
  fb['JIT'] = '2'
  rc2 = run(tg_dir, onnx, outp, fb)
  return rc2


if __name__ == '__main__':
  sys.exit(main())