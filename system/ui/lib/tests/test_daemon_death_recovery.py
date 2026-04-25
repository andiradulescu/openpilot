"""Regression tests for wpa_supplicant daemon-death recovery.

The monitor thread's select+recv doesn't raise when the daemon is SIGKILL'd,
so request-issuing threads (scanner, reconcile) must null self._ctrl on OSError
and bump _monitor_epoch to kick the monitor's outer loop into the respawn path.
"""
import time

from openpilot.system.ui.lib.wifi_manager import (
  CONNECTING_STALE_TIMEOUT_SECONDS,
  ConnectStatus,
  SCAN_PERIOD_SECONDS,
  WifiState,
)


def test_request_scan_invalidates_on_oserror(wm):
  wm._ctrl.request.side_effect = OSError(107, "Transport endpoint is not connected")
  epoch_before = wm._monitor_epoch

  wm._request_scan()

  assert wm._ctrl is None
  assert wm._monitor_epoch > epoch_before


def test_request_scan_keeps_ctrl_on_non_oserror(wm):
  old_ctrl = wm._ctrl
  wm._ctrl.request.side_effect = ValueError("bogus reply")

  wm._request_scan()

  assert wm._ctrl is old_ctrl


def test_reconcile_disconnected_invalidates_on_oserror(wm):
  wm._wifi_state = WifiState(ssid=None, status=ConnectStatus.DISCONNECTED)
  wm._ctrl.request.side_effect = OSError(107, "Transport endpoint is not connected")
  epoch_before = wm._monitor_epoch

  wm._reconcile_connecting_state()

  assert wm._ctrl is None
  assert wm._monitor_epoch > epoch_before


def test_reconcile_connected_invalidates_on_oserror(wm):
  wm._wifi_state = WifiState(ssid="TestNet", status=ConnectStatus.CONNECTED)
  wm._last_connected_recheck = time.monotonic() - SCAN_PERIOD_SECONDS - 1
  wm._ctrl.request.side_effect = OSError(107, "Transport endpoint is not connected")
  epoch_before = wm._monitor_epoch

  wm._reconcile_connecting_state()

  assert wm._ctrl is None
  assert wm._monitor_epoch > epoch_before


def test_reconcile_connecting_invalidates_on_oserror(wm):
  wm._wifi_state = WifiState(ssid="TestNet", status=ConnectStatus.CONNECTING)
  wm._last_connecting_at = time.monotonic() - CONNECTING_STALE_TIMEOUT_SECONDS - 1
  wm._ctrl.request.side_effect = OSError(107, "Transport endpoint is not connected")
  epoch_before = wm._monitor_epoch

  wm._reconcile_connecting_state()

  assert wm._ctrl is None
  assert wm._monitor_epoch > epoch_before
