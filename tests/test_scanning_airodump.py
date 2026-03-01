"""Tests for scanning/airodump.py — monitor mode and AirodumpScanner.

Follows TDD agent standards:
- test_<what>_<condition>_<expected_outcome> naming
- One concept per test
- pytest.fixture for shared setup
- Unhappy-path coverage (malformed input, edge cases)
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, mock_open, patch

from wifimonitor.scanning.airodump import (
    AirodumpScanner,
    _interface_supports_monitor,
    _set_nm_managed,
    _enable_monitor_mode,
    _verify_monitor_mode,
    _disable_monitor_mode,
    _log_airodump_exit,
    _log_monitor_failure,
    _enable_monitor_mode_virtual,
    _disable_monitor_mode_virtual,
)
from wifimonitor.scanning.nmcli import parse_nmcli_output


class _FakeRunner:
    """A fake CommandRunner for injection-based tests."""

    def __init__(self):
        self.run_calls: list[tuple[list[str], dict]] = []
        self.popen_calls: list[tuple[list[str], dict]] = []
        self._run_results: list = []
        self._run_side_effects: list = []
        self._popen_result = None

    def set_run_results(self, *results):
        self._run_results = list(results)

    def set_run_side_effect(self, exc):
        self._run_side_effects = [exc]

    def set_popen_result(self, proc):
        self._popen_result = proc

    def set_popen_side_effect(self, exc):
        self._popen_result = exc

    def run(self, cmd, **kwargs):
        self.run_calls.append((cmd, kwargs))
        if self._run_side_effects:
            raise self._run_side_effects.pop(0)
        if self._run_results:
            return self._run_results.pop(0)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def popen(self, cmd, **kwargs):
        self.popen_calls.append((cmd, kwargs))
        if isinstance(self._popen_result, Exception):
            raise self._popen_result
        return self._popen_result



class TestAirodumpScanner:
    """AirodumpScanner manages airodump-ng process and parses CSV for client counts."""

    def test_scan_returns_networks_with_clients_from_csv(self):
        """When CSV has station data, scan returns networks with clients populated."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV

        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi-01.csv"]), \
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)):
            networks = scanner.scan()
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        assert home.clients == 2
        assert coffee.clients == 1

    def test_scan_no_csv_returns_empty_list(self):
        """When no CSV file exists yet, scan returns empty list."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=[]):
            networks = scanner.scan()
        assert networks == []

    def test_scan_file_read_error_returns_empty_list(self):
        """When CSV file cannot be read, scan returns empty list."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi-01.csv"]), \
            patch("builtins.open", side_effect=OSError("Permission denied")):
            networks = scanner.scan()
        assert networks == []

    def test_scan_hybrid_uses_nmcli_when_virtual_monitor(self):
        """When using virtual monitor (mon0), scan uses nmcli for BSSID list and overlays client counts from airodump."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV

        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        scanner._monitor_is_virtual = True  # Simulate virtual monitor after start()
        nmcli_networks = parse_nmcli_output(
            r"aa\:bb\:cc\:dd\:ee\:01:HomeNetwork:6:85:WPA2" + "\n"
            r"aa\:bb\:cc\:dd\:ee\:02:CoffeeShop:11:42:" + "\n"
            r"aa\:bb\:cc\:dd\:ee\:03:OtherNet:1:70:WPA2" + "\n"
        )
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi-01.csv"]), \
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)), \
            patch(
                "wifimonitor.scanning.airodump.scan_wifi_nmcli", \
                return_value=nmcli_networks, \
            ):
            networks = scanner.scan()
        # nmcli returns 3 networks; airodump has clients for aa:bb:cc:dd:ee:01 (2) and aa:bb:cc:dd:ee:02 (1)
        assert len(networks) == 3
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        other = [n for n in networks if n.ssid == "OtherNet"][0]
        assert home.clients == 2
        assert coffee.clients == 1
        assert other.clients == 0  # Not in airodump CSV

    def test_start_passes_cwd_and_background_to_airodump(self):
        """start() spawns airodump with cwd=/tmp, --background 1, stdin=DEVNULL, start_new_session=True, --hoptime 500."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        # Virtual monitor path: 2 for _interface_supports_monitor, 2 for pre-scan,
        # 1 for rfkill unblock, 3 for _enable_monitor_mode_virtual, 1 for stop (iw dev mon0 del)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: nmcli rescan + list (returns empty channel list)
            success,  # rfkill unblock wifi
            iw_dev_info, success, success,  # virtual: iw dev info, iw phy interface add, ip up
            success,  # stop: iw dev mon0 del
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        assert len(fake.popen_calls) == 1
        cmd, kwargs = fake.popen_calls[0]
        assert kwargs.get("cwd") == "/tmp"
        assert kwargs.get("start_new_session") is True
        assert kwargs.get("stdin") == subprocess.DEVNULL
        assert "--background" in cmd
        idx = cmd.index("--background")
        assert cmd[idx + 1] == "1"
        assert "--hoptime" in cmd
        ht_idx = cmd.index("--hoptime")
        assert cmd[ht_idx + 1] == "500"
        scanner.stop()

    def test_start_airodump_detached_from_terminal(self):
        """start() passes start_new_session=True to popen so airodump cannot open /dev/tty."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: nmcli rescan + list
            success,           # rfkill unblock wifi
            iw_dev_info, success, success,  # virtual: iw dev info, iw phy add, ip up
            success,           # stop: iw dev mon0 del
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        _, kwargs = fake.popen_calls[0]
        assert kwargs.get("start_new_session") is True
        assert kwargs.get("stdin") == subprocess.DEVNULL
        scanner.stop()

    def test_start_returns_false_when_airodump_exits_immediately(self):
        """start() returns False when airodump process exits right after spawn."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        fake.set_popen_result(mock_proc)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: nmcli rescan + list
            success,  # rfkill unblock wifi
            iw_dev_info, success, success,  # virtual: iw dev info, iw phy interface add, ip up
            success,  # stop: iw dev mon0 del
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, reason = scanner.start()
        assert ok is False
        assert reason == "airodump_exit"

    def test_start_returns_false_when_nmcli_managed_no_fails(self):
        """start() returns (False, 'monitor_mode') when nmcli device set managed no fails."""
        fake = _FakeRunner()
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        nmcli_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Error: Device not found"
        )
        iw_phy_add_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="not supported"
        )
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: nmcli rescan + list
            success,  # rfkill unblock wifi
            iw_dev_info, iw_phy_add_fail,  # virtual fails at iw phy interface add
            success,  # nmcli disconnect
            nmcli_fail,  # nmcli managed no — fails
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, reason = scanner.start()
        assert ok is False
        assert reason == "monitor_mode"

    def test_start_uses_set_type_fallback_when_virtual_fails(self):
        """start() falls back to set-type when virtual monitor interface creation fails."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        iw_phy_add_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="not supported"
        )
        iw_verify = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: nmcli rescan + list
            success,  # rfkill unblock wifi
            iw_dev_info, iw_phy_add_fail,  # virtual fails at iw phy interface add
            success, success,  # nmcli disconnect, nmcli managed no
            success, success, success,  # ip down, iw set type, ip up
            iw_verify,
            success, success, success, success,  # stop: ip down, iw set managed, ip up, nmcli
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        assert not scanner._monitor_is_virtual
        assert scanner._monitor_interface == "wlan0"
        scanner.stop()

    def test_start_uses_channel_list_from_pre_scan(self):
        """start() passes -c <channels> to airodump when pre-scan discovers APs."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        # Pre-scan list returns two APs on channels 6 and 36
        nmcli_list = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=(
                r"AA\:BB\:CC\:DD\:EE\:01:HomeNet:6:85:WPA2" + "\n"
                r"AA\:BB\:CC\:DD\:EE\:02:Office:36:70:WPA2"
            ),
            stderr="",
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success,       # pre-scan: nmcli rescan
            nmcli_list,    # pre-scan: nmcli list → channels 6, 36
            success,       # rfkill unblock wifi
            iw_dev_info, success, success,  # virtual: iw dev info, iw phy add, ip up
            success,       # stop: iw dev mon0 del
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        assert scanner._channels == [6, 36]
        cmd, _ = fake.popen_calls[0]
        assert "-c" in cmd
        c_idx = cmd.index("-c")
        channel_val = cmd[c_idx + 1]
        assert "6" in channel_val
        assert "36" in channel_val
        assert "--band" not in cmd
        assert "--hoptime" in cmd
        ht_idx = cmd.index("--hoptime")
        assert cmd[ht_idx + 1] == "500"
        scanner.stop()

    def test_start_falls_back_to_band_when_pre_scan_empty(self):
        """start() uses --band abg when pre-scan returns no networks."""
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr=""
        )
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan: rescan + empty list → no channels
            success,           # rfkill unblock wifi
            iw_dev_info, success, success,  # virtual: iw dev info, iw phy add, ip up
            success,           # stop: iw dev mon0 del
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        assert scanner._channels == []
        cmd, _ = fake.popen_calls[0]
        assert "--band" in cmd
        band_idx = cmd.index("--band")
        assert cmd[band_idx + 1] == "abg"
        assert "-c" not in cmd
        assert "--hoptime" in cmd
        ht_idx = cmd.index("--hoptime")
        assert cmd[ht_idx + 1] == "500"
        scanner.stop()




# ---------------------------------------------------------------------------
# _interface_supports_monitor — branch coverage
# ---------------------------------------------------------------------------


class TestInterfaceSupportsMonitor:
    """Branch coverage for _interface_supports_monitor."""

    def test_iw_dev_info_fails_returns_true(self):
        """Returns True when 'iw dev info' returns non-zero (allow attempt)."""
        fake = _FakeRunner()
        fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        fake.set_run_results(fail)
        assert _interface_supports_monitor("wlan0", runner=fake) is True

    def test_no_wiphy_in_output_returns_true(self):
        """Returns True when 'wiphy' not found in iw dev info output."""
        fake = _FakeRunner()
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type managed\n", stderr=""
        )
        fake.set_run_results(result)
        assert _interface_supports_monitor("wlan0", runner=fake) is True

    def test_phy_info_fails_returns_true(self):
        """Returns True when iw phy info returns non-zero."""
        fake = _FakeRunner()
        dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        phy_fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        fake.set_run_results(dev_info, phy_fail)
        assert _interface_supports_monitor("wlan0", runner=fake) is True

    def test_band_line_breaks_mode_search_returns_false(self):
        """Returns False when 'Band' terminates the mode search before finding monitor."""
        fake = _FakeRunner()
        dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=(
                "Supported interface modes:\n"
                " * managed\n"
                " * IBSS\n"
                "\tBand 1:\n"
                " * monitor\n"  # after break, not reached
            ),
            stderr="",
        )
        fake.set_run_results(dev_info, phy_info)
        assert _interface_supports_monitor("wlan0", runner=fake) is False

    def test_no_monitor_in_modes_returns_false(self):
        """Returns False when supported modes section has no monitor entry."""
        fake = _FakeRunner()
        dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=(
                "Supported interface modes:\n"
                " * managed\n"
                " * IBSS\n"
                " * AP\n"
            ),
            stderr="",
        )
        fake.set_run_results(dev_info, phy_info)
        assert _interface_supports_monitor("wlan0", runner=fake) is False

    def test_exception_returns_true(self):
        """Returns True when runner raises an exception (allow attempt)."""
        fake = _FakeRunner()
        fake.set_run_side_effect(OSError("iw not found"))
        assert _interface_supports_monitor("wlan0", runner=fake) is True


# ---------------------------------------------------------------------------
# _set_nm_managed — exception path
# ---------------------------------------------------------------------------


class TestSetNmManaged:
    """Exception path for _set_nm_managed."""

    def test_exception_returns_false(self):
        """Returns False when runner raises an exception."""
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd="nmcli", timeout=5))
        result = _set_nm_managed("wlan0", True, runner=fake)
        assert result is False


# ---------------------------------------------------------------------------
# _enable_monitor_mode — failure paths
# ---------------------------------------------------------------------------


class TestEnableMonitorMode:
    """Failure paths for _enable_monitor_mode."""

    def test_disconnect_exception_is_ignored_and_continues(self):
        """nmcli disconnect exception is caught; execution continues."""
        runner = MagicMock()
        managed_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ip_down = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_type = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ip_up = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        verify_ok = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type monitor\n", stderr=""
        )
        runner.run.side_effect = [
            OSError("not connected"),  # nmcli disconnect → caught
            managed_ok,                # _set_nm_managed: nmcli managed no
            ip_down, iw_type, ip_up,   # cmds
            verify_ok,                 # _verify_monitor_mode
        ]
        with patch("wifimonitor.scanning.airodump.time.sleep"):
            result = _enable_monitor_mode("wlan0", runner=runner)
        assert result is True

    def test_cmd_failure_returns_false(self, tmp_path):
        """Returns False when a cmd in the cmds loop fails."""
        log_file = str(tmp_path / "monitor.log")
        runner = MagicMock()
        managed_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ip_down_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="device busy"
        )
        runner.run.side_effect = [
            managed_ok,     # disconnect (success)
            managed_ok,     # _set_nm_managed
            ip_down_fail,   # ip link down → fails
        ]
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            result = _enable_monitor_mode("wlan0", runner=runner)
        assert result is False

    def test_exception_in_cmd_loop_returns_false(self, tmp_path):
        """Returns False when runner raises during cmd loop."""
        log_file = str(tmp_path / "monitor.log")
        runner = MagicMock()
        managed_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        runner.run.side_effect = [
            managed_ok,            # disconnect
            managed_ok,            # _set_nm_managed
            OSError("ip not found"),  # ip link down → exception
        ]
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            result = _enable_monitor_mode("wlan0", runner=runner)
        assert result is False


# ---------------------------------------------------------------------------
# _verify_monitor_mode — failure paths
# ---------------------------------------------------------------------------


class TestVerifyMonitorMode:
    """Failure paths for _verify_monitor_mode."""

    def test_iw_dev_info_nonzero_returns_false(self, tmp_path):
        """Returns False when iw dev info returns non-zero."""
        log_file = str(tmp_path / "monitor.log")
        fake = _FakeRunner()
        fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
        fake.set_run_results(fail)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file):
            result = _verify_monitor_mode("wlan0", runner=fake)
        assert result is False

    def test_not_type_monitor_returns_false(self, tmp_path):
        """Returns False when 'type monitor' not in iw dev info output."""
        log_file = str(tmp_path / "monitor.log")
        fake = _FakeRunner()
        result_ok = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type managed\n", stderr=""
        )
        fake.set_run_results(result_ok)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file):
            result = _verify_monitor_mode("wlan0", runner=fake, iw_set_type_returncode=0)
        assert result is False

    def test_exception_returns_false(self, tmp_path):
        """Returns False when runner raises an exception."""
        log_file = str(tmp_path / "monitor.log")
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd="iw", timeout=5))
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file):
            result = _verify_monitor_mode("wlan0", runner=fake)
        assert result is False


# ---------------------------------------------------------------------------
# _log_airodump_exit — file write coverage
# ---------------------------------------------------------------------------


class TestLogAirodumpExit:
    """Coverage for _log_airodump_exit file write paths."""

    def test_writes_exit_info_and_flushes_stderr_file(self, tmp_path):
        """Writes exit details and calls flush() on stderr_file."""
        log_file = str(tmp_path / "airodump.log")
        mock_file = MagicMock()
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file):
            _log_airodump_exit(returncode=1, cmd=["airodump-ng"], stderr_file=mock_file)
        mock_file.flush.assert_called_once()
        content = open(log_file).read()
        assert "airodump exited" in content
        assert "returncode=1" in content


# ---------------------------------------------------------------------------
# _log_monitor_failure — inner decode and returncode paths
# ---------------------------------------------------------------------------


class TestLogMonitorFailure:
    """Coverage for _log_monitor_failure: bytes decode, returncode, OSError."""

    def test_writes_details_with_bytes_stdout_and_returncode(self, tmp_path):
        """Covers bytes decode path and returncode write."""
        log_file = str(tmp_path / "monitor.log")
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file):
            _log_monitor_failure("test failure", 1, b"stdout bytes", b"stderr bytes")
        content = open(log_file).read()
        assert "[monitor] test failure" in content
        assert "returncode: 1" in content
        assert "stdout bytes" in content

    def test_oserror_silently_ignored(self):
        """Does not raise when writing to log file fails with OSError."""
        with patch("builtins.open", side_effect=OSError("no space left")):
            _log_monitor_failure("msg", None, None, None)  # must not raise


# ---------------------------------------------------------------------------
# _disable_monitor_mode — exception path
# ---------------------------------------------------------------------------


class TestDisableMonitorMode:
    """Exception path for _disable_monitor_mode."""

    def test_runner_exception_is_ignored(self):
        """Exceptions during ip/iw commands are silently caught."""
        runner = MagicMock()
        runner.run.side_effect = OSError("ip not found")
        _disable_monitor_mode("wlan0", runner=runner)  # must not raise


# ---------------------------------------------------------------------------
# _enable_monitor_mode_virtual — failure paths
# ---------------------------------------------------------------------------


class TestEnableMonitorModeVirtual:
    """Failure paths for _enable_monitor_mode_virtual."""

    def test_iw_dev_info_fails_returns_none(self):
        """Returns None when iw dev info fails."""
        fake = _FakeRunner()
        fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        fake.set_run_results(fail)
        result = _enable_monitor_mode_virtual("wlan0", runner=fake)
        assert result is None

    def test_no_wiphy_match_returns_none(self):
        """Returns None when wiphy not found in iw dev info output."""
        fake = _FakeRunner()
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type managed\n", stderr=""
        )
        fake.set_run_results(result)
        assert _enable_monitor_mode_virtual("wlan0", runner=fake) is None

    def test_ip_link_up_fails_cleans_up_and_returns_none(self):
        """Returns None when ip link up fails; deletes mon0."""
        fake = _FakeRunner()
        dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        phy_add_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ip_up_fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        del_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        fake.set_run_results(dev_info, phy_add_ok, ip_up_fail, del_ok)
        result = _enable_monitor_mode_virtual("wlan0", runner=fake)
        assert result is None

    def test_exception_returns_none(self):
        """Returns None when runner raises an exception."""
        fake = _FakeRunner()
        fake.set_run_side_effect(OSError("iw not found"))
        result = _enable_monitor_mode_virtual("wlan0", runner=fake)
        assert result is None


# ---------------------------------------------------------------------------
# _disable_monitor_mode_virtual — exception path
# ---------------------------------------------------------------------------


class TestDisableMonitorModeVirtual:
    """Exception path for _disable_monitor_mode_virtual."""

    def test_runner_exception_is_ignored(self):
        """Exceptions during iw dev del are silently caught."""
        fake = _FakeRunner()
        fake.set_run_side_effect(OSError("iw not found"))
        _disable_monitor_mode_virtual("mon0", runner=fake)  # must not raise


# ---------------------------------------------------------------------------
# AirodumpScanner — additional coverage paths
# ---------------------------------------------------------------------------


class TestAirodumpScannerAdditionalPaths:
    """Additional AirodumpScanner paths not covered by primary tests."""

    def _make_virtual_start_results(self):
        """Helper returning run results for a successful virtual monitor start."""
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n", stderr="",
        )
        return iw_dev_info, iw_phy_info, success

    def test_start_opens_stderr_log_and_writes_header(self, tmp_path):
        """start() writes header to AIRODUMP_STDERR_LOG when file is writable."""
        log_file = str(tmp_path / "airodump.log")
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        iw_dev_info, iw_phy_info, success = self._make_virtual_start_results()
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan
            success,           # rfkill
            iw_dev_info, success, success,  # virtual monitor
            success,           # stop
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        content = open(log_file).read()
        assert "capturing airodump-ng stderr" in content
        scanner.stop()

    def test_start_with_debug_logs_interface_support(self, tmp_path):
        """start(debug=True) logs _interface_supports_monitor result."""
        log_file = str(tmp_path / "airodump.log")
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        iw_dev_info, iw_phy_info, success = self._make_virtual_start_results()
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan
            success,           # rfkill
            iw_dev_info, success, success,  # virtual monitor
            success,           # stop
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake, debug=True)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        scanner.stop()

    def test_start_monitor_unsupported_returns_false(self):
        """start() returns (False, 'monitor_unsupported') when phy has no monitor mode."""
        fake = _FakeRunner()
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * IBSS\n",
            stderr="",
        )
        fake.set_run_results(iw_dev_info, iw_phy_info)
        scanner = AirodumpScanner(interface="wlan0", runner=fake, debug=True)
        ok, reason = scanner.start()
        assert ok is False
        assert reason == "monitor_unsupported"

    def test_start_rfkill_exception_is_ignored(self, tmp_path):
        """start() continues when rfkill raises an exception."""
        log_file = str(tmp_path / "airodump.log")
        runner = MagicMock()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        runner.popen.return_value = mock_proc
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n",
            stderr="",
        )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        runner.run.side_effect = [
            iw_dev_info, iw_phy_info,            # _interface_supports_monitor
            success, success,                     # scan_wifi_nmcli (rescan + list)
            OSError("rfkill not found"),          # rfkill → caught
            iw_dev_info, success, success,        # _enable_monitor_mode_virtual
            success,                              # stop: iw dev del
        ]
        scanner = AirodumpScanner(interface="wlan0", runner=runner, debug=True)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        scanner.stop()

    def test_start_popen_raises_file_not_found(self, tmp_path):
        """start() returns (False, 'airodump_spawn') when popen raises FileNotFoundError."""
        log_file = str(tmp_path / "airodump.log")
        fake = _FakeRunner()
        fake.set_popen_side_effect(FileNotFoundError("airodump-ng not found"))
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n",
            stderr="",
        )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,  # pre-scan
            success,           # rfkill
            iw_dev_info, success, success,  # virtual monitor
            success,           # stop
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, reason = scanner.start()
        assert ok is False
        assert reason == "airodump_spawn"

    def test_stop_kills_process_on_wait_timeout(self):
        """stop() kills the process when wait() times out."""
        scanner = AirodumpScanner(interface="wlan0")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # still running
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="airodump-ng", timeout=5)
        scanner._proc = mock_proc
        scanner._monitor_enabled = False  # skip monitor teardown
        scanner.stop()
        mock_proc.kill.assert_called_once()

    def test_stop_closes_stderr_file_if_open(self):
        """stop() closes _stderr_file when it is open."""
        scanner = AirodumpScanner(interface="wlan0")
        mock_file = MagicMock()
        scanner._stderr_file = mock_file
        scanner._monitor_enabled = False  # skip monitor teardown
        scanner.stop()
        mock_file.close.assert_called_once()
        assert scanner._stderr_file is None

    def test_is_alive_returns_true_when_running(self):
        """is_alive() returns True when process is running."""
        scanner = AirodumpScanner(interface="wlan0")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        scanner._proc = mock_proc
        assert scanner.is_alive() is True

    def test_log_exit_if_dead_returns_false_and_logs(self, tmp_path):
        """log_exit_if_dead() returns False and logs when process has exited."""
        log_file = str(tmp_path / "airodump.log")
        scanner = AirodumpScanner(interface="wlan0")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        scanner._proc = mock_proc
        scanner._last_cmd = ["airodump-ng"]
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file):
            result = scanner.log_exit_if_dead()
        assert result is False
        assert scanner._exit_logged is True

    def test_scan_debug_logs_csv_parse_results(self, tmp_path):
        """scan() with debug=True logs parse results for direct monitor mode."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi_cov", debug=True)
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]), \
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)):
            networks = scanner.scan()
        assert len(networks) > 0

    def test_scan_oserror_with_debug_logs_failure(self, tmp_path):
        """scan() with debug=True logs when CSV read fails with OSError."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi_cov", debug=True)
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]), \
            patch("builtins.open", side_effect=OSError("permission denied")):
            networks = scanner.scan()
        assert networks == []

    def test_scan_hybrid_debug_logs(self, tmp_path):
        """scan() with debug=True and virtual monitor logs hybrid scan."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi_cov", debug=True)
        scanner._monitor_is_virtual = True
        nmcli_networks = parse_nmcli_output(
            r"aa\:bb\:cc\:dd\:ee\:01:HomeNetwork:6:85:WPA2" + "\n"
        )
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]), \
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)), \
            patch("wifimonitor.scanning.airodump.scan_wifi_nmcli", return_value=nmcli_networks):
            networks = scanner.scan()
        assert len(networks) == 1

    def test_cleanup_old_files_oserror_silently_ignored(self, tmp_path):
        """_cleanup_old_files continues when os.remove raises OSError."""
        scanner = AirodumpScanner(interface="wlan0", prefix=str(tmp_path / "wifi"))
        # Create a file that matches the prefix pattern
        test_file = tmp_path / "wifi-01.csv"
        test_file.write_text("content")
        with patch("wifimonitor.scanning.airodump.os.remove", side_effect=OSError("busy")):
            scanner._cleanup_old_files()  # must not raise

    def test_start_direct_monitor_debug_logs(self, tmp_path):
        """start() with debug=True and direct monitor path logs virtual-failed and direct-success."""
        log_file = str(tmp_path / "airodump.log")
        runner = MagicMock()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        runner.popen.return_value = mock_proc
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n",
            stderr="",
        )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        phy_add_fail = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="not supported"
        )
        verify_ok = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type monitor\n", stderr=""
        )
        runner.run.side_effect = [
            iw_dev_info, iw_phy_info,                # _interface_supports_monitor
            success, success,                         # scan_wifi_nmcli (rescan + list)
            success,                                  # rfkill
            iw_dev_info, phy_add_fail,               # _enable_monitor_mode_virtual (fails at phy add)
            success, success,                         # nmcli disconnect, nmcli managed no
            success, success, success,                # ip down, iw set type, ip up
            verify_ok,                               # _verify_monitor_mode
            success, success, success, success,       # stop: ip down, iw set managed, ip up, nmcli
        ]
        scanner = AirodumpScanner(interface="wlan0", runner=runner, debug=True)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=0), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        assert not scanner._monitor_is_virtual
        scanner.stop()


# ---------------------------------------------------------------------------
# _dump_startup_config — logging coverage
# ---------------------------------------------------------------------------


class TestEnableMonitorModeVerifyFails:
    """Line 558: _verify_monitor_mode returns False inside _enable_monitor_mode."""

    def test_all_cmds_succeed_but_verify_fails_returns_false(self, tmp_path):
        """Returns False when all cmds succeed but _verify_monitor_mode says not monitor."""
        log_file = str(tmp_path / "monitor.log")
        runner = MagicMock()
        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        verify_fail = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  type managed\n", stderr=""
        )
        runner.run.side_effect = [
            ok,      # disconnect
            ok,      # _set_nm_managed
            ok, ok, ok,      # ip down, iw set type, ip up
            verify_fail,     # _verify_monitor_mode: "type managed" → False
        ]
        with patch("wifimonitor.scanning.airodump.AIRODUMP_MONITOR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            result = _enable_monitor_mode("wlan0", runner=runner)
        assert result is False


class TestEnableMonitorModeVirtualCleanupException:
    """Lines 732-733: ip up fails and cleanup iw dev del also raises."""

    def test_ip_up_fails_and_cleanup_raises(self):
        """Returns None when ip up fails and cleanup also raises OSError."""
        runner = MagicMock()
        dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        phy_add_ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ip_up_fail = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        runner.run.side_effect = [
            dev_info, phy_add_ok, ip_up_fail,
            OSError("iw del failed"),  # cleanup raises
        ]
        result = _enable_monitor_mode_virtual("wlan0", runner=runner)
        assert result is None


class TestAirodumpScannerNonRootPath:
    """Line 863: geteuid() != 0 makes start() use 'sudo airodump-ng'."""

    def test_start_non_root_uses_sudo_airodump(self, tmp_path):
        """start() uses 'sudo airodump-ng' when not running as root."""
        log_file = str(tmp_path / "airodump.log")
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        fake.set_popen_result(mock_proc)
        iw_dev_info = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Interface wlan0\n  wiphy 0\n", stderr=""
        )
        iw_phy_info = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="Supported interface modes:\n * managed\n * monitor\n",
            stderr="",
        )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        fake.set_run_results(
            iw_dev_info, iw_phy_info,
            success, success,
            success,
            iw_dev_info, success, success,
            success,
        )
        scanner = AirodumpScanner(interface="wlan0", runner=fake)
        with patch("wifimonitor.scanning.airodump.AIRODUMP_STDERR_LOG", log_file), \
            patch("wifimonitor.scanning.airodump.os.geteuid", return_value=1000), \
            patch("wifimonitor.scanning.airodump.time.sleep"):
            ok, _ = scanner.start()
        assert ok is True
        cmd, _ = fake.popen_calls[0]
        assert cmd[0] == "sudo"
        assert "airodump-ng" in cmd
        scanner.stop()


class TestAirodumpScannerStopCloseError:
    """Lines 938-939: stderr_file.close() raises OSError in stop()."""

    def test_stop_close_oserror_is_ignored(self):
        """stop() continues cleanly when closing _stderr_file raises OSError."""
        scanner = AirodumpScanner(interface="wlan0")
        mock_file = MagicMock()
        mock_file.close.side_effect = OSError("file already closed")
        scanner._stderr_file = mock_file
        scanner._monitor_enabled = False
        scanner.stop()  # must not raise
        assert scanner._stderr_file is None


class TestLogExitIfDeadAlive:
    """Line 956: log_exit_if_dead returns True when process is still alive or None."""

    def test_log_exit_if_dead_returns_true_when_alive(self):
        """Returns True when process is still running (poll() returns None)."""
        scanner = AirodumpScanner(interface="wlan0")
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        scanner._proc = mock_proc
        assert scanner.log_exit_if_dead() is True

    def test_log_exit_if_dead_returns_true_when_proc_none(self):
        """Returns True when _proc is None."""
        scanner = AirodumpScanner(interface="wlan0")
        scanner._proc = None
        assert scanner.log_exit_if_dead() is True


class TestScanDebugMoreThanTenNetworks:
    """Line 1033: scan() debug log when CSV has >10 networks."""

    def test_scan_debug_logs_truncation_above_ten(self):
        """scan() with debug=True and >10 networks executes the truncation log."""
        header = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, "
            "ID-length, ESSID, Key\n"
        )
        rows = ""
        for i in range(12):
            rows += (
                f"AA:BB:CC:DD:EE:{i:02X}, 2024-01-01 00:00:00, 2024-01-01 00:00:01, "
                f"6, 54, WPA2, CCMP, PSK, -60, 10, 0, 0.0.0.0, 4, Net{i:02d}, \n"
            )
        csv_content = (
            header + rows
            + "\n\nStation MAC, First time seen, Last time seen, Power, "
            "# packets, BSSID, Probed ESSIDs\n"
        )
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_dbg11", debug=True)
        with patch("wifimonitor.scanning.airodump.glob.glob", return_value=["/tmp/test_dbg11-01.csv"]), \
            patch("builtins.open", mock_open(read_data=csv_content)):
            networks = scanner.scan()
        assert len(networks) >= 10

