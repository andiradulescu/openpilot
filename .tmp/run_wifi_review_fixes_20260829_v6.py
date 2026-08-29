#!/usr/bin/env python3
from pathlib import Path
import subprocess

source = subprocess.check_output([
  "git", "show", "origin/wifi-review-fixes-20260829:.tmp/apply_wifi_review_fixes_20260829.py",
], text=True)

# Keep the healthy-tethering fixture consistent with the cleanup-pending state added by commit 4.
old = '''text = controller_tests.read_text()
anchor = "  def test_healthy_tethering_is_left_running(self):\\n"
addition = '''
new = '''text = controller_tests.read_text()
old_healthy = \"\"\"  def test_healthy_tethering_is_left_running(self):
    controller, _, _ = make_controller()
    controller._tethering_active = True
    controller._leave_tethering = MagicMock()
\"\"\"
new_healthy = \"\"\"  def test_healthy_tethering_is_left_running(self):
    controller, _, _ = make_controller()
    controller._tethering_active = True
    controller._state = wifi_controller.WifiState(ssid="weedle", status=ConnectStatus.CONNECTED, ipv4_address=wifi_controller.wifi_tethering.TETHERING_ADDRESS)
    controller._leave_tethering = MagicMock()
\"\"\"
text = replace_once(text, old_healthy, new_healthy)
anchor = "  def test_healthy_tethering_is_left_running(self):\\n"
addition = '''
if source.count(old) != 1:
  raise RuntimeError("validation fixture patch mismatch")
source = source.replace(old, new, 1)

# Ruff B904: both errors are re-raised intentionally from the STATUS request failure path.
old = 'f\'{match.group(1)}if not self._clear_l3():\\n{match.group(1)}  raise RuntimeError("failed to stop Wi-Fi DHCP")\\n\''
new = 'f\'{match.group(1)}if not self._clear_l3():\\n{match.group(1)}  raise RuntimeError("failed to stop Wi-Fi DHCP") from None\\n\''
if source.count(old) != 1:
  raise RuntimeError("DHCP raise patch mismatch")
source = source.replace(old, new, 1)

anchor = '''# Commit 1: don't switch network ownership while DHCP or tethering resources are still live.
text = controller_path.read_text()
'''
replacement = '''# Commit 1: don't switch network ownership while DHCP or tethering resources are still live.
text = controller_path.read_text()
text = replace_once(text, '        raise RuntimeError("failed to recover station wpa_supplicant")\\n',
                    '        raise RuntimeError("failed to recover station wpa_supplicant") from None\\n')
'''
if source.count(anchor) != 1:
  raise RuntimeError("station recovery raise patch mismatch")
source = source.replace(anchor, replacement, 1)

Path("/tmp/apply_wifi_review_fixes_v6.py").write_text(source)
subprocess.run(["python3", "/tmp/apply_wifi_review_fixes_v6.py"], check=True)
