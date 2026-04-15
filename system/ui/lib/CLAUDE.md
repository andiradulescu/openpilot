# system/ui/lib/ — wifi_manager

Standalone wifi/tethering stack that **coexists with NetworkManager**. NM is still running on AGNOS and still auto-manages `wlan0` on boot; the code must assume NM is present and fight for the interface on every bringup. Branch name "nonetworkmanager" is aspirational.

This file is non-obvious gotchas only. Don't restate what the code says; read the code for that.

## Boot timing (AGNOS)

- Kernel creates `wlan0` **~40s after openpilot starts**. Any `nmcli dev set wlan0 managed no` before that silently fails with "Device wlan0 does not exist", and NM grabs `wlan0` the instant the kernel brings it up. Always wait on `/sys/class/net/wlan0` before touching NM.
- `wpa_supplicant.service` is a systemd unit that starts at t≈8s in DBus-only mode (`-u -s -O DIR=/run/wpa_supplicant`). It has no interface until NM tells it to bind one via DBus. We don't own this daemon and must never kill it.

## Never attach to NM's wpa_supplicant

- NM drives the systemd daemon over DBus; it can reconfigure or deinit at any moment, stomping anything we push. Our fast path uses `pgrep -f wpa_supplicant.*{WPA_SUPPLICANT_CONF}` (`_our_wpa_supplicant_running`) to verify the running daemon is one *we* spawned before calling `_try_attach_ctrl`.
- The post-spawn retry loop in `_ensure_wpa_supplicant` also gates on pgrep so an NM-held socket can't be mistaken for our own after a teardown timeout.
- `pkill`/`pgrep` always target **our** config path with regex-escaped `WPA_SUPPLICANT_CONF` or `WPA_AP_CONF` (see `_pkill_wpa_supplicant`). Never `killall wpa_supplicant` — that would kill the shared systemd daemon.

## NM teardown is asynchronous (~800ms)

- `nmcli dev set wlan0 managed no` returns immediately; NM then tells wpa_supplicant over DBus to deinit `wlan0`, which removes `/var/run/wpa_supplicant/wlan0`. During that window the ctrl socket still exists but is about to be deleted.
- Attaching inside that window = bound to a dying socket = `FileNotFoundError` / `Transport endpoint is not connected` spam on every subsequent request.
- `_ensure_wpa_supplicant` polls for the socket to disappear (up to ~3s) after `_unmanage_wlan0` before proceeding. If the poll times out, the post-spawn pgrep gate is the fallback: it refuses to attach to a foreign daemon even if the socket is still there.

## Default route metric 600 (critical for dual-uplink)

- busybox `udhcpc` → `/etc/udhcpc/default.script` installs the wlan0 default route with **metric 0**, which beats NM's eth0 (metric 100) and silently hijacks all traffic to wifi **even with the ETH cable plugged in**. `system/hardware/tici/hardware.py:get_network_type` returns whichever `dev` is first in `ip route show default`, so the UI badge also flips.
- `DhcpClient._fix_default_route_metric` polls after spawn and replaces the wlan0 route with metric 600 (NM's wifi default). Same-router DHCP renewals leave the route alone because default.script's `$router == $crouter` guard skips the re-install, so a one-shot bump survives the lease.
- `ip route replace` does **not** work here — metric is part of the route key, so `replace default ... metric 600` would *add* a second route instead of replacing the metric-0 one. Must `flush exact 0.0.0.0/0` + `add`.

## NAT rule: source-subnet MASQUERADE, not `-o iface`

Mirrors NM's `nm-firewall-utils.c:_share_iptables_set_masquerade_sync`:

```
iptables -t nat -I POSTROUTING \
  -s 192.168.43.0/24 ! -d 192.168.43.0/24 \
  -j MASQUERADE -m comment --comment openpilot-tethering
```

- Matching on **source subnet** (not `-o <iface>`) is what makes tethering survive uplink changes — ETH unplug, SIM pull, 3G↔4G, `rmnet_data0` rename. No watchdog needed: the kernel picks the new outgoing iface per packet, the rule still fires.
- `_start_tethering` also flushes legacy `-o <iface>` rules from older openpilot versions for upgrade safety.
- Do **not** reintroduce `_tethering_upstream_iface` state — it's dead code and leaks stale NAT rules when the upstream changes mid-session.

## AP-mode adoption on process restart

- If STATUS reports `mode=AP` when `_init_wifi_state` runs, we're adopting a hotspot that was already up before the UI restart (dnsmasq, iptables, AP wpa_supplicant all survived via `start_new_session=True` on the dnsmasq Popen).
- **Must not** fall through to the STA path: `_handle_connected` → `_dhcp.start()` → `ip addr flush wlan0` drops `TETHERING_IP_ADDRESS` and kills the running hotspot. Take the dedicated adoption branch that just sets `_tethering_active=True` and publishes state.

## SSID encoding: decode everywhere on ingress

- wpa_supplicant emits SSIDs via `wpa_ssid_txt` (printf_encode) in **every** control path: STATUS, SCAN_RESULTS, LIST_NETWORKS, CTRL-EVENT-SSID-TEMP-DISABLED, CTRL-EVENT-CONNECTED. Bytes outside printable ASCII come through as `\xNN` escape sequences.
- Every ingress must pass through `decode_ssid()`. A raw string compare to a user-supplied SSID silently misses any network whose name contains non-ASCII bytes, and `forget_connection`/`activate_connection` leak runtime network IDs because `_list_network_ids` won't match (each leak lets a duplicate build up on reconnect).
- Empty/all-null SSIDs (hidden APs) normalize to `""` so the empty-SSID filter drops them.

## Credential persistence ordering

- `_persist_pending_connection` must call `store.save_network` + `_generate_wpa_conf` **before** clearing `self._pending_connection`, and swallow exceptions from both. A disk-full or permission error on `/data` must not lose the credentials the user just typed, and must not propagate up through `_handle_connected` and block `_dhcp.start()` / activated callbacks for the current connect event.

## Raw 64-hex PSKs are unquoted

- wpa_supplicant's `psk` field: quoted = passphrase (≤63 chars), **unquoted = 64-hex pre-computed PSK**. A 64-hex quoted value is rejected as a too-long passphrase. `_add_and_select_network` detects the 64-hex pattern and passes it unquoted.

## State machine rules

- **`_handle_connected` is idempotent on (ssid, status=CONNECTED)**. Monitor thread's `CTRL-EVENT-CONNECTED` handler and scanner's `_reconcile_connecting_state` can both dispatch the same transition; without the early-return, each `_dhcp.start()` would kill the previous udhcpc mid-lease.
- **`_reconcile_connecting_state` must also re-validate stale `CONNECTED` state** (gated at `SCAN_PERIOD_SECONDS` cadence to avoid STATUS spam). If the monitor socket drops and reconnects, a `CTRL-EVENT-DISCONNECTED` can be lost; without this check the state machine stays permanently stuck reporting an old network as connected.
- **`wpa_state=SCANNING` is not a terminal failure**. Hidden SSIDs can legitimately stay in SCANNING past the stale window. Refresh the window, don't synthesize wrong-password; the subsequent `DISCONNECTED`/`INACTIVE` transition is the real terminal state.
- **WRONG_KEY with unknown connecting ssid**: the auto-connect path can set `CONNECTING` with `ssid=None` when STATUS was briefly unavailable. The subsequent `TEMP-DISABLED reason=WRONG_KEY` event's SSID is authoritative mid-connect; accept it instead of requiring `current_ssid` to already match.

## Tethering flag timing

- `set_tethering_active(True)` asserts `_tethering_active = True` **synchronously** (blocks station-connect UI during AP bringup).
- `set_tethering_active(False)` does **not** clear the flag up-front. `_stop_tethering` clears it at the end, after `_ensure_wpa_supplicant` has actually switched `_ctrl` back to STA mode. Otherwise a user tapping a network immediately after hitting "stop tethering" races the teardown and sends `ADD_NETWORK`/`SELECT_NETWORK` to the AP daemon.

## WpaCtrl concurrency

- `WpaCtrl.request()` serializes send+recv so replies pair with commands. Monitor and scanner threads both issue requests; without serialization, replies would interleave.
- `WpaCtrl.close()` must serialize against in-flight `request()` callers to avoid racing the socket close against a reply read.
- The monitor thread self-heals: it retries `ctrl.open()` on every iteration, so a daemon restart doesn't permanently wedge event delivery.

## Test fixture gotcha (`wm` in `conftest.py`)

- The fixture creates a `WifiManager` via `__new__` + direct field injection and sets `_exit = True`. Tests that exercise `_ensure_wpa_supplicant` rely on `_exit=True` to short-circuit the wait-for-wlan0 loop at the top.
- Flipping `_exit` to `False` without also mocking `_scan_thread` / `_state_thread` / `_gsm` causes `__del__` → `stop()` → `.join()` on non-existent threads during GC, surfacing as a `PytestUnraisableExceptionWarning` on whatever unrelated test happens to trigger GC next. `_patch_bringup_sideeffects` handles this correctly; new helpers should too.
- Spawn-path tests use a **False-then-True** `side_effect` on `_our_wpa_supplicant_running` because the same method gates both the fast path (must see False to fall through) and the post-spawn retry (must see True to allow attach). See `_patch_bringup_sideeffects`.
