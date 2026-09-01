from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from openpilot.system.ui.lib import wifi_tethering


class TestTethering(TestCase):
  def test_dnsmasq_does_not_require_persistent_leasefile(self):
    with (
      patch.object(wifi_tethering, "dnsmasq_running", side_effect=[False, True]),
      patch.object(wifi_tethering.subprocess, "run", return_value=MagicMock(returncode=0)) as run,
    ):
      assert wifi_tethering.start_dnsmasq()

    dnsmasq_command = run.call_args_list[2].args[0]
    assert "--leasefile-ro" in dnsmasq_command

  def test_dnsmasq_ownership_checks_arguments(self):
    command = "\0".join((
      "/usr/sbin/dnsmasq",
      "--interface=wlan0",
      f"--pid-file={wifi_tethering.DNSMASQ_PID_FILE}",
      f"--dhcp-option=3,{wifi_tethering.TETHERING_ADDRESS}",
      "",
    )).encode()
    with (
      patch.object(Path, "read_text", return_value="123"),
      patch.object(Path, "read_bytes", return_value=command),
    ):
      assert wifi_tethering._owned_dnsmasq_pid() == 123

  def test_firewall_uses_separate_input_and_forward_chains(self):
    _, _, rules, jumps = wifi_tethering._commands()
    input_rules = [rule for rule in rules if wifi_tethering.INPUT_CHAIN in rule]
    forward_rules = [rule for rule in rules if wifi_tethering.FORWARD_CHAIN in rule]

    assert len(input_rules) == 3
    assert len(forward_rules) == 2
    assert [jump[-1] for jump in jumps] == [
      wifi_tethering.NAT_CHAIN,
      wifi_tethering.INPUT_CHAIN,
      wifi_tethering.FORWARD_CHAIN,
    ]

  def test_jump_cleanup_replaces_append_with_delete(self):
    command = ["sudo", "iptables", "-A", "INPUT", "-j", wifi_tethering.INPUT_CHAIN]
    assert wifi_tethering._replace_operation(command, "-D") == [
      "sudo", "iptables", "-D", "INPUT", "-j", wifi_tethering.INPUT_CHAIN,
    ]

  def test_stop_keeps_pidfile_when_dnsmasq_does_not_exit(self):
    with (
      patch.object(wifi_tethering, "_owned_dnsmasq_pid", return_value=123),
      patch.object(wifi_tethering.subprocess, "run") as run,
      patch.object(wifi_tethering.time, "monotonic", side_effect=[0.0, 0.0, 3.0]),
      patch.object(wifi_tethering.time, "sleep"),
    ):
      run.return_value.returncode = 0
      assert not wifi_tethering.stop_dnsmasq(timeout=2.0)

    assert run.call_args_list == [call(["sudo", "kill", "123"], check=False)]

  def test_stop_accepts_dnsmasq_exit_before_signal(self):
    with (
      patch.object(wifi_tethering, "_owned_dnsmasq_pid", side_effect=[123, None]),
      patch.object(wifi_tethering.subprocess, "run", side_effect=[MagicMock(returncode=1), MagicMock(returncode=0)]) as run,
    ):
      assert wifi_tethering.stop_dnsmasq()

    assert run.call_args_list == [
      call(["sudo", "kill", "123"], check=False),
      call(["sudo", "rm", "-f", wifi_tethering.DNSMASQ_PID_FILE], check=False),
    ]

  def test_forwarding_command_failure_is_reported(self):
    with (
      patch.object(wifi_tethering, "get_ipv4_forward", return_value=False),
      patch.object(wifi_tethering.subprocess, "run", return_value=MagicMock(returncode=1)),
      self.assertRaisesRegex(RuntimeError, "failed to update IPv4 forwarding"),
    ):
      wifi_tethering.set_ipv4_forward(True)

  def test_session_restores_previous_forwarding_state(self):
    session = wifi_tethering.TetheringSession()
    with (
      patch.object(wifi_tethering, "get_ipv4_forward", return_value=True),
      patch.object(wifi_tethering, "_write_previous_ipv4_forward"),
      patch.object(wifi_tethering, "_clear_previous_ipv4_forward", return_value=True),
      patch.object(wifi_tethering, "configure_interface"),
      patch.object(wifi_tethering, "install_firewall"),
      patch.object(wifi_tethering, "set_ipv4_forward") as set_forward,
      patch.object(wifi_tethering, "start_dnsmasq", return_value=True),
      patch.object(wifi_tethering, "stop_dnsmasq", return_value=True),
      patch.object(wifi_tethering, "remove_firewall", return_value=True),
      patch.object(wifi_tethering, "clear_interface", return_value=True),
    ):
      assert session.start(False)
      assert session.stop()

    assert set_forward.call_args_list == [call(False), call(True)]

  def test_session_keeps_resources_when_dnsmasq_will_not_stop(self):
    session = wifi_tethering.TetheringSession()
    session._previous_ipv4_forward = False
    with (
      patch.object(wifi_tethering, "stop_dnsmasq", return_value=False),
      patch.object(wifi_tethering, "remove_firewall") as remove_firewall,
      patch.object(wifi_tethering, "clear_interface") as clear_interface,
    ):
      assert not session.stop()

    remove_firewall.assert_not_called()
    clear_interface.assert_not_called()

  def test_forwarding_restore_failure_does_not_resurrect_stopped_hotspot(self):
    session = wifi_tethering.TetheringSession()
    session._previous_ipv4_forward = False
    with (
      patch.object(wifi_tethering, "stop_dnsmasq", return_value=True),
      patch.object(wifi_tethering, "remove_firewall", return_value=True) as remove_firewall,
      patch.object(wifi_tethering, "clear_interface", return_value=True) as clear_interface,
      patch.object(wifi_tethering, "set_ipv4_forward", side_effect=OSError),
      patch.object(wifi_tethering.cloudlog, "exception") as log_exception,
    ):
      assert not session.stop()

    remove_firewall.assert_called_once_with()
    clear_interface.assert_called_once_with()
    log_exception.assert_called_once_with("Failed to restore IPv4 forwarding after tethering")
    assert session._previous_ipv4_forward is False

  def test_failed_start_rolls_back_resources(self):
    session = wifi_tethering.TetheringSession()
    with (
      patch.object(wifi_tethering, "get_ipv4_forward", return_value=False),
      patch.object(wifi_tethering, "_write_previous_ipv4_forward"),
      patch.object(wifi_tethering, "_clear_previous_ipv4_forward", return_value=True),
      patch.object(wifi_tethering, "configure_interface"),
      patch.object(wifi_tethering, "install_firewall"),
      patch.object(wifi_tethering, "set_ipv4_forward"),
      patch.object(wifi_tethering, "start_dnsmasq", return_value=False),
      patch.object(wifi_tethering, "dnsmasq_running", return_value=False),
      patch.object(wifi_tethering, "remove_firewall", return_value=True) as remove_firewall,
      patch.object(wifi_tethering, "clear_interface", return_value=True) as clear_interface,
    ):
      assert not session.start(True)

    remove_firewall.assert_called_once()
    clear_interface.assert_called_once()

  def test_start_records_forwarding_before_tethering_resources(self):
    session = wifi_tethering.TetheringSession()
    events = []
    with (
      patch.object(wifi_tethering, "get_ipv4_forward", return_value=True),
      patch.object(wifi_tethering, "_write_previous_ipv4_forward", side_effect=lambda value: events.append(("marker", value))),
      patch.object(wifi_tethering, "configure_interface", side_effect=lambda: events.append(("interface", None))),
      patch.object(wifi_tethering, "install_firewall"),
      patch.object(wifi_tethering, "set_ipv4_forward"),
      patch.object(wifi_tethering, "start_dnsmasq", return_value=True),
    ):
      assert session.start(False)

    assert events == [("marker", True), ("interface", None)]

  def test_stale_forwarding_marker_is_restored_without_other_resources(self):
    with (
      patch.object(wifi_tethering, "_read_previous_ipv4_forward", return_value=True),
      patch.object(wifi_tethering, "dnsmasq_running", return_value=False),
      patch.object(wifi_tethering, "firewall_present", return_value=False),
      patch.object(wifi_tethering, "interface_configured", return_value=False),
      patch.object(wifi_tethering, "stop_dnsmasq", return_value=True),
      patch.object(wifi_tethering, "remove_firewall", return_value=True),
      patch.object(wifi_tethering, "clear_interface", return_value=True),
      patch.object(wifi_tethering, "set_ipv4_forward") as set_forward,
      patch.object(wifi_tethering, "_clear_previous_ipv4_forward", return_value=True) as clear_marker,
    ):
      assert wifi_tethering.TetheringSession.cleanup_stale()

    set_forward.assert_called_once_with(True)
    clear_marker.assert_called_once_with()

  def test_clean_startup_does_not_touch_global_forwarding(self):
    with (
      patch.object(wifi_tethering, "_read_previous_ipv4_forward", return_value=None),
      patch.object(wifi_tethering, "dnsmasq_running", return_value=False),
      patch.object(wifi_tethering, "firewall_present", return_value=False),
      patch.object(wifi_tethering, "interface_configured", return_value=False),
      patch.object(wifi_tethering, "set_ipv4_forward") as set_forward,
      patch.object(wifi_tethering, "clear_interface") as clear_interface,
    ):
      assert wifi_tethering.TetheringSession.cleanup_stale()

    set_forward.assert_not_called()
    clear_interface.assert_not_called()

  def test_adopt_reattaches_live_tethering_resources(self):
    session = wifi_tethering.TetheringSession()
    with (
      patch.object(wifi_tethering, "_read_previous_ipv4_forward", return_value=False),
      patch.object(wifi_tethering, "dnsmasq_running", return_value=True),
      patch.object(wifi_tethering, "firewall_ready", return_value=True),
      patch.object(wifi_tethering, "start_dnsmasq") as start_dnsmasq,
      patch.object(wifi_tethering, "configure_interface") as configure_interface,
    ):
      assert session.adopt()

    start_dnsmasq.assert_not_called()
    configure_interface.assert_not_called()
    assert session._previous_ipv4_forward is False
    with (
      patch.object(wifi_tethering, "dnsmasq_running", return_value=True),
      patch.object(wifi_tethering, "firewall_ready", return_value=True),
    ):
      assert session.start(True)

  def test_adopt_rejects_incomplete_tethering(self):
    session = wifi_tethering.TetheringSession()
    with (
      patch.object(wifi_tethering, "_read_previous_ipv4_forward", return_value=False),
      patch.object(wifi_tethering, "dnsmasq_running", return_value=True),
      patch.object(wifi_tethering, "firewall_ready", return_value=False),
    ):
      assert not session.adopt()
    assert session._previous_ipv4_forward is None
