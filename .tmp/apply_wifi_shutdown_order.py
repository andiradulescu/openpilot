#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys

EXPECTED_HEAD = "dc66cb9039741f7512d171078c30eee60f3235b3"


def run(*args: str, env: dict[str, str] | None = None) -> None:
  subprocess.run(args, check=True, env=env)


def output(*args: str) -> str:
  return subprocess.check_output(args, text=True).strip()


def replace_once(text: str, old: str, new: str) -> str:
  if text.count(old) != 1:
    raise RuntimeError("patch anchor mismatch")
  return text.replace(old, new, 1)


if output("git", "rev-parse", "HEAD") != EXPECTED_HEAD:
  raise RuntimeError("target branch moved")
run("git", "config", "user.name", "Andrei Radulescu")
run("git", "config", "user.email", "andi.radulescu@gmail.com")

controller = Path("openpilot/system/ui/lib/wifi_controller.py")
text = controller.read_text()
text = replace_once(text, '''    else:
      if not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF):
        cloudlog.error("Failed to stop station wpa_supplicant during shutdown")
        return
      if not self._dhcp.stop():
        cloudlog.error("Failed to stop Wi-Fi DHCP during shutdown")
        return
      self._dhcp.clear_ipv6()
''', '''    else:
      if not self._dhcp.stop():
        cloudlog.error("Failed to stop Wi-Fi DHCP during shutdown")
        return
      if not wpa_supplicant.stop(wpa_supplicant.WPA_SUPPLICANT_CONF):
        self._dhcp.start()
        cloudlog.error("Failed to stop station wpa_supplicant during shutdown")
        return
      self._dhcp.clear_ipv6()
''')
controller.write_text(text)

tests = Path("openpilot/system/ui/lib/tests/test_wifi_controller.py")
text = tests.read_text()
text = replace_once(text, '''    restore_networkmanager.assert_not_called()

  def test_station_attach_failure_rolls_back_acquisition(self):
''', '''    restore_networkmanager.assert_not_called()
    wpa_supplicant_stop.assert_not_called()

  def test_shutdown_restores_dhcp_when_station_owner_cannot_stop(self):
    controller, _, dhcp = make_controller()
    controller._close_ctrl = MagicMock()
    dhcp.stop.return_value = True
    with (
      patch.object(wifi_controller.wpa_supplicant, "is_running", return_value=False),
      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=False),
      patch.object(wifi_controller.wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
    ):
      controller._shutdown()

    dhcp.start.assert_called_once_with()
    restore_networkmanager.assert_not_called()

  def test_station_attach_failure_rolls_back_acquisition(self):
''')
text = replace_once(text, '''      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=True),
      patch.object(wifi_controller.wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
''', '''      patch.object(wifi_controller.wpa_supplicant, "stop", return_value=True) as wpa_supplicant_stop,
      patch.object(wifi_controller.wpa_supplicant, "restore_networkmanager") as restore_networkmanager,
''')
tests.write_text(text)

run(sys.executable, "-m", "py_compile", str(controller), str(tests))
run("git", "diff", "--check")
run("git", "add", str(controller), str(tests))
run("git", "commit", "-m", "wifi: preserve station owner on shutdown failure")

run(sys.executable, "-m", "pip", "install", "-q", "pytest", "ruff")
stub_dir = Path("/tmp/openpilot-test-stubs")
stub_dir.mkdir(exist_ok=True)
(stub_dir / "sitecustomize.py").write_text('''import sys\nimport types\n\nclass _CloudLog:\n  def __getattr__(self, _):\n    return lambda *args, **kwargs: None\n\nmodule = types.ModuleType("openpilot.common.swaglog")\nmodule.cloudlog = _CloudLog()\nsys.modules["openpilot.common.swaglog"] = module\n''')
env = os.environ.copy()
env["PYTHONPATH"] = str(stub_dir) + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
run(sys.executable, "-m", "pytest", "-q", str(tests), env=env)
run("ruff", "check", str(controller), str(tests))
run("git", "diff", "--check", "HEAD~1..HEAD")
run("git", "push", "origin", "HEAD:wifi-no-networkmanager-refactor")
