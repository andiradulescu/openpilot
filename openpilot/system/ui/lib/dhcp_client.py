"""udhcpc lifecycle for a single interface, with default-route metric fixup."""
import subprocess
import threading

from openpilot.common.swaglog import cloudlog


class DhcpClient:
  """Manage udhcpc for DHCP on wlan0."""

  # Above NM's eth0 default (metric 100) so ETH keeps priority; matches NM's wifi metric.
  DEFAULT_ROUTE_METRIC = 600
  # Matches udhcpc's -T retry timeout below.
  DISCOVER_TIMEOUT_SECONDS = 3
  DISCOVER_ATTEMPTS = 5
  # Retry quickly while the lease route is missing or has the wrong metric.
  ROUTE_RETRY_INTERVAL_SECONDS = 0.2
  # Recheck on the udhcpc retry cadence so bound/renew route changes are corrected.
  ROUTE_MONITOR_INTERVAL_SECONDS = DISCOVER_TIMEOUT_SECONDS

  def __init__(self, iface: str = "wlan0"):
    self._iface = iface
    self._proc: subprocess.Popen | None = None
    self._adopted = False
    self._client_thread: threading.Thread | None = None
    self._client_stop = threading.Event()
    self._metric_thread: threading.Thread | None = None
    self._metric_stop = threading.Event()

  def _start_metric_thread(self):
    if self._metric_thread is not None and self._metric_thread.is_alive():
      return
    self._metric_stop.clear()
    self._metric_thread = threading.Thread(target=self._fix_default_route_metric, daemon=True)
    self._metric_thread.start()

  def _start_client_thread(self):
    self._client_stop.clear()
    self._client_thread = threading.Thread(target=self._monitor_client, daemon=True)
    self._client_thread.start()

  def _client_running(self) -> bool:
    if self._proc is not None and self._proc.poll() is None:
      return True
    result = subprocess.run(["pgrep", "-f", f"^udhcpc -i {self._iface}( |$)"], capture_output=True, check=False)
    return result.returncode == 0

  def _flush_address(self):
    subprocess.run(["sudo", "ip", "-4", "addr", "flush", "dev", self._iface], capture_output=True, check=False)

  def _flush_lease(self):
    subprocess.run(["sudo", "ip", "-4", "route", "flush", "dev", self._iface], capture_output=True, check=False)
    self._flush_address()

  def clear_ipv6_state(self):
    for command in (
      ["sudo", "ip", "-6", "addr", "flush", "dev", self._iface, "scope", "global"],
      ["sudo", "ip", "-6", "route", "flush", "dev", self._iface],
    ):
      try:
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode != 0:
          cloudlog.warning(f"Failed to clear {self._iface} IPv6 state (rc={result.returncode})")
      except OSError:
        cloudlog.exception(f"Failed to clear {self._iface} IPv6 state")

  def _spawn(self) -> bool:
    try:
      self._proc = subprocess.Popen(
        ["sudo", "udhcpc", "-i", self._iface, "-f",
         "-t", str(self.DISCOVER_ATTEMPTS), "-T", str(self.DISCOVER_TIMEOUT_SECONDS)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
      )
    except Exception:
      self._proc = None
      cloudlog.exception("Failed to start udhcpc")
      return False
    return True

  def _monitor_client(self):
    while not self._client_stop.wait(self.DISCOVER_TIMEOUT_SECONDS):
      if not self._client_running():
        self._flush_lease()
        if self._spawn():
          self._start_metric_thread()

  def adopt(self) -> bool:
    if not self._client_running():
      return False
    self._adopted = True
    self._start_client_thread()
    self._start_metric_thread()
    return True

  def start(self):
    self.stop()
    # A client from a previous controller can survive independently. A fresh
    # connection needs a new lease, so replace any client we did not adopt.
    subprocess.run(["sudo", "pkill", "-f", f"udhcpc.*-i {self._iface}"], check=False)
    self._flush_lease()
    started = self._spawn()
    self._start_client_thread()
    if started:
      self._start_metric_thread()

  def _fix_default_route_metric(self):
    """Replace udhcpc's metric-0 default route with metric 600.
    busybox udhcpc can't set a bind-time metric; without this, wlan0 silently beats
    eth0 on every DHCP bind. Poll quickly until the route is ready, then continue
    monitoring for renewals that replace it. stop() terminates the worker."""
    while not self._metric_stop.is_set():
      try:
        out = subprocess.check_output(
          ["ip", "-4", "route", "show", "default", "dev", self._iface],
          text=True, timeout=2,
        ).strip()
      except Exception:
        # Transient: udhcpc may not have installed the route yet, or the iface is briefly down.
        # Fall through to the throttled wait and retry; stop() unblocks the loop.
        cloudlog.exception("Failed to query wlan0 default route")
        out = ""

      saw_route = False
      needs_retry = False
      for line in out.splitlines():
        parts = line.split()
        if "via" not in parts:
          continue
        try:
          gw = parts[parts.index("via") + 1]
        except IndexError:
          needs_retry = True
          continue
        route_metric = 0
        if "metric" in parts:
          try:
            route_metric = int(parts[parts.index("metric") + 1])
          except (IndexError, ValueError):
            needs_retry = True
            continue
        saw_route = True
        if route_metric == self.DEFAULT_ROUTE_METRIC:
          continue
        result = subprocess.run(
          ["sudo", "ip", "-4", "route", "replace", "default", "via", gw,
           "dev", self._iface, "metric", str(self.DEFAULT_ROUTE_METRIC)],
          check=False,
        )
        if result.returncode == 0:
          subprocess.run(
            ["sudo", "ip", "-4", "route", "del", "default", "via", gw,
             "dev", self._iface, "metric", str(route_metric)],
            check=False,
          )
        needs_retry = True
        break

      route_ready = saw_route and not needs_retry
      interval = self.ROUTE_MONITOR_INTERVAL_SECONDS if route_ready else self.ROUTE_RETRY_INTERVAL_SECONDS
      self._metric_stop.wait(interval)

  def stop(self):
    self._client_stop.set()
    if self._client_thread is not None:
      self._client_thread.join(timeout=self.DISCOVER_TIMEOUT_SECONDS)
      self._client_thread = None
    self._metric_stop.set()
    if self._metric_thread is not None:
      self._metric_thread.join(timeout=2)
      self._metric_thread = None
    had_client = self._proc is not None or self._adopted
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
    self._adopted = False
    if had_client:
      # Same orphan risk as start(): a previous sudo udhcpc -f can survive our
      # tracked Popen (e.g. terminate timed out, sudo wrapper died but child
      # didn't). Without this, the orphan re-adds the address right after the
      # flush below and resurrects the route after we've moved on.
      subprocess.run(["sudo", "pkill", "-f", f"udhcpc.*-i {self._iface}"], check=False)
      self._flush_lease()
