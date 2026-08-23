from unittest import TestCase
from unittest.mock import patch

from openpilot.common.hardware.base import HardwareBase
from openpilot.common.hardware.comma import hardware
from openpilot.common.hardware.comma.hardware import HardwareComma


PROFILE_UUID = "11111111-1111-4111-8111-111111111111"
OTHER_UUID = "22222222-2222-4222-8222-222222222222"


class TestHardwareWifi(TestCase):
  def test_metered_uses_matching_active_profile_uuid(self):
    with (
      patch.object(hardware, "wpa_supplicant_cmd", return_value={"id_str": PROFILE_UUID}),
      patch.object(hardware, "read_active_profile", return_value=(PROFILE_UUID, 1)),
    ):
      assert HardwareComma().get_network_metered(hardware.NetworkType.wifi)

  def test_unmetered_uses_matching_active_profile_uuid(self):
    with (
      patch.object(hardware, "wpa_supplicant_cmd", return_value={"id_str": PROFILE_UUID}),
      patch.object(hardware, "read_active_profile", return_value=(PROFILE_UUID, 2)),
    ):
      assert not HardwareComma().get_network_metered(hardware.NetworkType.wifi)

  def test_stale_active_profile_does_not_apply_to_different_connection(self):
    with (
      patch.object(hardware, "wpa_supplicant_cmd", return_value={"id_str": PROFILE_UUID}),
      patch.object(hardware, "read_active_profile", return_value=(OTHER_UUID, 1)),
      patch.object(HardwareBase, "get_network_metered", return_value=False) as fallback,
    ):
      assert not HardwareComma().get_network_metered(hardware.NetworkType.wifi)

    fallback.assert_called_once_with(hardware.NetworkType.wifi)

  def test_unknown_metered_value_uses_base_policy(self):
    with (
      patch.object(hardware, "wpa_supplicant_cmd", return_value={"id_str": PROFILE_UUID}),
      patch.object(hardware, "read_active_profile", return_value=(PROFILE_UUID, 0)),
      patch.object(HardwareBase, "get_network_metered", return_value=True) as fallback,
    ):
      assert HardwareComma().get_network_metered(hardware.NetworkType.wifi)

    fallback.assert_called_once_with(hardware.NetworkType.wifi)
