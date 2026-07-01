#!/usr/bin/env python3
"""Move netplan-emitted NetworkManager keyfiles into persistent storage."""
import os
import re
import subprocess
import tempfile

from openpilot.common.swaglog import cloudlog
from openpilot.common.utils import sudo_read

RUN_DIR = "/run/NetworkManager/system-connections"
DEST_DIR = "/data/etc/NetworkManager/system-connections"
NETPLAN_DIR = "/data/etc/netplan"

NETPLAN_KEYFILE_RE = re.compile(
  r"^netplan-NM-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:-.*)?\.nmconnection$"
)


def sudo_install(content: str, dest: str) -> None:
  with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
    f.write(content)
    tmp = f.name
  try:
    subprocess.run(["sudo", "install", "-d", "-m", "755", os.path.dirname(dest)], check=True)
    subprocess.run(["sudo", "install", "-o", "root", "-g", "root", "-m", "600", tmp, dest], check=True)
  finally:
    os.unlink(tmp)


def persist_connections() -> None:
  try:
    fnames = os.listdir(RUN_DIR)
  except OSError:
    return

  for fname in fnames:
    m = NETPLAN_KEYFILE_RE.match(fname)
    if m is None:
      continue

    src = os.path.join(RUN_DIR, fname)
    raw = sudo_read(src)
    if not raw:
      continue

    dest = os.path.join(DEST_DIR, fname)
    try:
      if sudo_read(dest) != raw:
        sudo_install(raw, dest)
      subprocess.run(["sudo", "rm", "-f", src], check=True)
      try:
        yamls = os.listdir(NETPLAN_DIR)
      except OSError:
        yamls = []
      for yaml in yamls:
        if m.group(1) in yaml and yaml.endswith(".yaml"):
          subprocess.run(["sudo", "rm", "-f", os.path.join(NETPLAN_DIR, yaml)], check=True)
    except Exception:
      cloudlog.exception("nm_persist: failed for %s", fname)


if __name__ == "__main__":
  persist_connections()
