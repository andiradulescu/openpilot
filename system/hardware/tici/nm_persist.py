"""Migrate netplan-emitted NM keyfiles from /run into /data/etc so they survive
netplan and NetworkManager removal in a future AGNOS release.

For each netplan-NM-<uuid>*.nmconnection in /run/NetworkManager/system-connections/:
  1. Copy to /data/etc/NetworkManager/system-connections/ (NM's canonical
     keyfile store, scanned via the /etc/NetworkManager/system-connections
     symlink).
  2. Delete the /run copy.
  3. Delete the source /data/etc/netplan/*<uuid>*.yaml so netplan does not
     regenerate the /run copy on the next boot.

NM dedups connection profiles by UUID, so briefly seeing the file in both
/run and /etc during migration is harmless. Idempotent and self-disabling:
once the netplan YAMLs are gone, netplan has nothing to regenerate and
subsequent calls find no work.
"""
import configparser
import os
import re
import subprocess
import tempfile

from openpilot.common.swaglog import cloudlog
from openpilot.common.utils import sudo_read

RUN_DIR = "/run/NetworkManager/system-connections"
DEST_DIR = "/data/etc/NetworkManager/system-connections"
NETPLAN_DIR = "/data/etc/netplan"

_NETPLAN_KEYFILE_RE = re.compile(
  r"^netplan-NM-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:-.*)?\.nmconnection$"
)


def _sudo_install(content: str, dest: str) -> None:
  with tempfile.NamedTemporaryFile(mode="w", dir="/tmp", delete=False) as f:
    f.write(content)
    tmp = f.name
  try:
    subprocess.run(["sudo", "install", "-d", "-m", "755", os.path.dirname(dest)], check=True)
    subprocess.run(["sudo", "install", "-o", "root", "-g", "root", "-m", "600", tmp, dest], check=True)
  finally:
    try:
      os.unlink(tmp)
    except FileNotFoundError:
      pass


def _sudo_rm(path: str) -> None:
  subprocess.run(["sudo", "rm", "-f", path], check=True)


def persist_connections(run_dir: str = RUN_DIR, dest_dir: str = DEST_DIR, netplan_dir: str = NETPLAN_DIR) -> None:
  try:
    fnames = os.listdir(run_dir)
  except OSError:
    return

  for fname in fnames:
    m = _NETPLAN_KEYFILE_RE.match(fname)
    if m is None:
      continue
    file_uuid = m.group(1)

    src = os.path.join(run_dir, fname)
    raw = sudo_read(src)
    if not raw:
      continue

    cp = configparser.ConfigParser(interpolation=None)
    try:
      cp.read_string(raw)
    except configparser.Error:
      continue

    dest = os.path.join(dest_dir, fname)
    try:
      if sudo_read(dest) != raw:
        _sudo_install(raw, dest)
      _sudo_rm(src)
      try:
        yamls = os.listdir(netplan_dir)
      except OSError:
        yamls = []
      for yaml in yamls:
        if file_uuid in yaml and yaml.endswith(".yaml"):
          _sudo_rm(os.path.join(netplan_dir, yaml))
    except Exception:
      cloudlog.exception("nm_persist: failed for %s", fname)
