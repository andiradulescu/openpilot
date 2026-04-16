"""udhcpc lifecycle for a single interface, with a one-shot default-route metric fixup."""
import subprocess
import threading
import time

from openpilot.common.swaglog import cloudlog


class DhcpClient:
  """Manage udhcpc for DHCP on wlan0."""

  # Higher than NM's wired default (metric 100), so a plugged-in eth0 keeps
  # priority as the default route while it's up. Matches NM's own metric
  # for wifi routes.
  DEFAULT_ROUTE_METRIC = 600

  def __init__(self, iface: str = "wlan0"):
    self._iface = iface
    self._proc: subprocess.Popen | None = None
    self._metric_thread: threading.Thread | None = None
    self._metric_stop = threading.Event()

  def start(self):
    self.stop()
    self._metric_stop.clear()
    try:
      self._proc = subprocess.Popen(
        ["sudo", "udhcpc", "-i", self._iface, "-f", "-t", "5", "-T", "3"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
      )
    except Exception:
      cloudlog.exception("Failed to start udhcpc")
      return
    self._metric_thread = threading.Thread(target=self._fix_default_route_metric, daemon=True)
    self._metric_thread.start()

  def _fix_default_route_metric(self):
    """Replace udhcpc's metric-0 wlan0 default route with a metric-600 one.

    busybox udhcpc has no way to set a route metric at bind time and its
    default dispatcher script installs the default route at metric 0.
    Without this fixup, wlan0 (metric 0) beats eth0 (NM's metric 100) and
    every DHCP bind silently hijacks the default gateway to wifi even with
    the cable plugged in. Poll briefly for the route to appear, then
    replace it. Same-router renewals leave the route alone, so a one-shot
    bump survives the lease.
    """
    deadline = time.monotonic() + 10.0
    while not self._metric_stop.is_set() and time.monotonic() < deadline:
      try:
        out = subprocess.check_output(
          ["ip", "-4", "route", "show", "default", "dev", self._iface],
          text=True, timeout=2,
        ).strip()
      except Exception:
        cloudlog.exception("Failed to query wlan0 default route")
        return

      for line in out.splitlines():
        parts = line.split()
        if "via" not in parts:
          continue
        try:
          gw = parts[parts.index("via") + 1]
        except IndexError:
          continue
        # Already at the target metric? Done.
        if "metric" in parts:
          try:
            if int(parts[parts.index("metric") + 1]) == self.DEFAULT_ROUTE_METRIC:
              return
          except (IndexError, ValueError):
            pass
        subprocess.run(
          ["sudo", "ip", "-4", "route", "flush", "exact", "0.0.0.0/0", "dev", self._iface],
          check=False,
        )
        subprocess.run(
          ["sudo", "ip", "-4", "route", "add", "default", "via", gw,
           "dev", self._iface, "metric", str(self.DEFAULT_ROUTE_METRIC)],
          check=False,
        )
        return

      self._metric_stop.wait(0.2)

  def stop(self):
    self._metric_stop.set()
    if self._metric_thread is not None:
      self._metric_thread.join(timeout=2)
      self._metric_thread = None
    if self._proc is not None:
      try:
        self._proc.terminate()
        self._proc.wait(timeout=3)
      except Exception:
        try:
          self._proc.kill()
          self._proc.wait()
        except Exception:
          pass
      self._proc = None
      subprocess.run(["sudo", "ip", "addr", "flush", "dev", self._iface], capture_output=True, check=False)
