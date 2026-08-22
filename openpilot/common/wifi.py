import os
import subprocess
import tempfile
import uuid


WPA_CTRL_DIR = "/run/openpilot-wpa"
WPA_CTRL_PATH = f"{WPA_CTRL_DIR}/wlan0"
WIFI_RUNTIME_DIR = "/run/openpilot-wifi"
ACTIVE_PROFILE_PATH = f"{WIFI_RUNTIME_DIR}/active_profile"


def parse_active_profile(value: str) -> tuple[str, int] | None:
  fields = value.split()
  if len(fields) != 2:
    return None
  try:
    profile_uuid = str(uuid.UUID(fields[0]))
    metered = int(fields[1])
  except (ValueError, TypeError):
    return None
  return (profile_uuid, metered) if metered in (0, 1, 2) else None


def read_active_profile() -> tuple[str, int] | None:
  try:
    with open(ACTIVE_PROFILE_PATH) as f:
      return parse_active_profile(f.read())
  except OSError:
    return None


def write_active_profile(profile_uuid: str, metered: int) -> None:
  value = f"{profile_uuid} {metered}\n"
  if parse_active_profile(value) is None:
    raise ValueError("invalid active Wi-Fi profile")

  subprocess.run(["sudo", "install", "-d", "-m", "755", WIFI_RUNTIME_DIR], check=True)
  with tempfile.NamedTemporaryFile("w", delete=False) as f:
    f.write(value)
    path = f.name
  try:
    subprocess.run(["sudo", "install", "-m", "644", path, ACTIVE_PROFILE_PATH], check=True)
  finally:
    os.unlink(path)


def clear_active_profile() -> None:
  subprocess.run(["sudo", "rm", "-f", ACTIVE_PROFILE_PATH], check=False)
