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
