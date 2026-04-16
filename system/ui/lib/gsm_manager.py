"""GSM/cellular settings manager via NetworkManager DBus."""
from openpilot.common.swaglog import cloudlog


# NM NMMetered values
# https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMMetered
NM_METERED_UNKNOWN = 0
NM_METERED_NO = 2


class _GsmManager:
  """Manages cellular/GSM via NetworkManager DBus (unchanged from NM era)."""

  NM = "org.freedesktop.NetworkManager"
  NM_PATH = '/org/freedesktop/NetworkManager'
  NM_SETTINGS_PATH = '/org/freedesktop/NetworkManager/Settings'
  NM_SETTINGS_IFACE = NM + '.Settings'
  NM_CONNECTION_IFACE = NM + '.Settings.Connection'
  NM_DEVICE_IFACE = NM + '.Device'
  NM_DEVICE_TYPE_MODEM = 8

  def __init__(self):
    self._router = None

  def _ensure_router(self):
    if self._router is not None:
      return True
    try:
      from jeepney.io.threading import DBusRouter, open_dbus_connection
      self._router = DBusRouter(open_dbus_connection(bus="SYSTEM"))
      return True
    except Exception:
      cloudlog.exception("Failed to connect to system D-Bus for GSM")
      return False

  def update_gsm_settings(self, roaming: bool, apn: str, metered: bool):
    if not self._ensure_router():
      return
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.low_level import MessageType

      lte_path = self._get_lte_connection_path()
      if not lte_path:
        cloudlog.warning("No LTE connection found")
        return

      conn_addr = DBusAddress(lte_path, bus_name=self.NM, interface=self.NM_CONNECTION_IFACE)
      reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'GetSettings'))
      if reply.header.message_type == MessageType.error:
        cloudlog.warning(f'Failed to get connection settings: {reply}')
        return
      settings = dict(reply.body[0])

      if 'gsm' not in settings:
        settings['gsm'] = {}
      if 'connection' not in settings:
        settings['connection'] = {}

      changes = False
      auto_config = apn == ""

      if settings['gsm'].get('auto-config', ('b', False))[1] != auto_config:
        settings['gsm']['auto-config'] = ('b', auto_config)
        changes = True

      if settings['gsm'].get('apn', ('s', ''))[1] != apn:
        settings['gsm']['apn'] = ('s', apn)
        changes = True

      if settings['gsm'].get('home-only', ('b', False))[1] == roaming:
        settings['gsm']['home-only'] = ('b', not roaming)
        changes = True

      # Unknown lets NetworkManager decide based on connection type
      metered_int = NM_METERED_UNKNOWN if metered else NM_METERED_NO
      if settings['connection'].get('metered', ('i', 0))[1] != metered_int:
        settings['connection']['metered'] = ('i', metered_int)
        changes = True

      if changes:
        reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'UpdateUnsaved', 'a{sa{sv}}', (settings,)))
        if reply.header.message_type == MessageType.error:
          cloudlog.warning(f"Failed to update GSM settings: {reply}")
          return
        self._activate_modem_connection(lte_path)
    except Exception as e:
      cloudlog.exception(f"Error updating GSM settings: {e}")

  def _get_lte_connection_path(self) -> str | None:
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.low_level import MessageType

      settings_addr = DBusAddress(self.NM_SETTINGS_PATH, bus_name=self.NM, interface=self.NM_SETTINGS_IFACE)
      known = self._router.send_and_get_reply(new_method_call(settings_addr, 'ListConnections')).body[0]

      for conn_path in known:
        conn_addr = DBusAddress(conn_path, bus_name=self.NM, interface=self.NM_CONNECTION_IFACE)
        reply = self._router.send_and_get_reply(new_method_call(conn_addr, 'GetSettings'))
        if reply.header.message_type == MessageType.error:
          continue
        settings = dict(reply.body[0])
        if settings.get('connection', {}).get('id', ('s', ''))[1] == 'lte':
          return str(conn_path)
    except Exception as e:
      cloudlog.exception(f"Error finding LTE connection: {e}")
    return None

  def _activate_modem_connection(self, connection_path: str):
    try:
      from jeepney import DBusAddress, new_method_call
      from jeepney.wrappers import Properties

      nm = DBusAddress(self.NM_PATH, bus_name=self.NM, interface=self.NM)
      device_paths = self._router.send_and_get_reply(new_method_call(nm, 'GetDevices')).body[0]
      for device_path in device_paths:
        dev_addr = DBusAddress(device_path, bus_name=self.NM, interface=self.NM_DEVICE_IFACE)
        dev_type = self._router.send_and_get_reply(Properties(dev_addr).get('DeviceType')).body[0][1]
        if dev_type == self.NM_DEVICE_TYPE_MODEM:
          self._router.send_and_get_reply(new_method_call(nm, 'ActivateConnection', 'ooo',
                                                          (connection_path, str(device_path), "/")))
          return
    except Exception as e:
      cloudlog.exception(f"Error activating modem connection: {e}")

  def close(self):
    if self._router is not None:
      try:
        self._router.close()
        self._router.conn.close()
      except Exception:
        pass
      self._router = None
