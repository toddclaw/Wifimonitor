"""Tests for wifimonitor.detection.arp — canonical ARP client detection module.

Imports from the canonical location (wifimonitor.detection.arp) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

from wifimonitor.detection.arp import (
    ArpScanner,
    _get_connected_bssid,
    _get_subnet,
    _parse_arp_scan_output,
    _parse_nmap_output,
)


# ---------------------------------------------------------------------------
# _parse_arp_scan_output
# ---------------------------------------------------------------------------

class TestParseArpScanOutput:
    """_parse_arp_scan_output counts unique hosts from arp-scan output."""

    def test_counts_host_lines(self):
        output = (
            "Interface: wlan0, type: EN10MB\n"
            "192.168.1.1\t00:11:22:33:44:55\tRouter Inc.\n"
            "192.168.1.100\taa:bb:cc:dd:ee:ff\tDevice Corp.\n"
            "\n"
            "2 packets received by filter, 0 packets dropped by kernel\n"
        )
        assert _parse_arp_scan_output(output) == 2

    def test_empty_output(self):
        assert _parse_arp_scan_output("") == 0

    def test_no_hosts_found(self):
        output = (
            "Interface: wlan0, type: EN10MB\n"
            "0 packets received by filter\n"
        )
        assert _parse_arp_scan_output(output) == 0

    def test_single_host(self):
        output = "192.168.1.1\t00:11:22:33:44:55\tRouter\n"
        assert _parse_arp_scan_output(output) == 1


# ---------------------------------------------------------------------------
# _parse_nmap_output
# ---------------------------------------------------------------------------

class TestParseNmapOutput:
    """_parse_nmap_output counts hosts from nmap greppable output."""

    def test_counts_up_hosts(self):
        output = (
            "# Nmap 7.80 scan initiated\n"
            "Host: 192.168.1.1 ()\tStatus: Up\n"
            "Host: 192.168.1.100 ()\tStatus: Up\n"
            "# Nmap done: 256 scanned, 2 up\n"
        )
        assert _parse_nmap_output(output) == 2

    def test_empty_output(self):
        assert _parse_nmap_output("") == 0

    def test_no_hosts_up(self):
        output = "# Nmap done: 256 scanned, 0 up\n"
        assert _parse_nmap_output(output) == 0

    def test_ignores_down_hosts(self):
        output = (
            "Host: 192.168.1.1 ()\tStatus: Up\n"
            "Host: 192.168.1.2 ()\tStatus: Down\n"
        )
        assert _parse_nmap_output(output) == 1


# ---------------------------------------------------------------------------
# _get_connected_bssid
# ---------------------------------------------------------------------------

class TestGetConnectedBssid:
    """_get_connected_bssid returns the BSSID of the connected network."""

    def test_returns_bssid_when_connected(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = "yes:AA\\:BB\\:CC\\:DD\\:EE\\:01\nno:FF\\:FF\\:FF\\:FF\\:FF\\:FF\n"
        mock_runner.run.return_value = result
        bssid = _get_connected_bssid(runner=mock_runner)
        assert bssid == "aa:bb:cc:dd:ee:01"

    def test_returns_none_when_not_connected(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = "no:AA\\:BB\\:CC\\:DD\\:EE\\:01\n"
        mock_runner.run.return_value = result
        bssid = _get_connected_bssid(runner=mock_runner)
        assert bssid is None

    def test_returns_none_on_empty_output(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = ""
        mock_runner.run.return_value = result
        bssid = _get_connected_bssid(runner=mock_runner)
        assert bssid is None

    def test_returns_none_on_timeout(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = subprocess.TimeoutExpired("nmcli", 10)
        bssid = _get_connected_bssid(runner=mock_runner)
        assert bssid is None

    def test_returns_none_on_file_not_found(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = FileNotFoundError("nmcli")
        bssid = _get_connected_bssid(runner=mock_runner)
        assert bssid is None

    def test_includes_interface_in_command(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = ""
        mock_runner.run.return_value = result
        _get_connected_bssid(interface="wlan1", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "ifname" in cmd
        assert "wlan1" in cmd


# ---------------------------------------------------------------------------
# _get_subnet
# ---------------------------------------------------------------------------

class TestGetSubnet:
    """_get_subnet returns the local subnet in CIDR notation."""

    def test_returns_subnet_from_route(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100\n"
        mock_runner.run.return_value = result
        subnet = _get_subnet(runner=mock_runner)
        assert subnet == "192.168.1.0/24"

    def test_returns_none_on_empty_output(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = ""
        mock_runner.run.return_value = result
        subnet = _get_subnet(runner=mock_runner)
        assert subnet is None

    def test_returns_none_on_timeout(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = subprocess.TimeoutExpired("ip", 5)
        subnet = _get_subnet(runner=mock_runner)
        assert subnet is None

    def test_includes_interface_in_command(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.stdout = ""
        mock_runner.run.return_value = result
        _get_subnet(interface="wlan0", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "show" in cmd
        assert "dev" in cmd
        assert "wlan0" in cmd


# ---------------------------------------------------------------------------
# ArpScanner
# ---------------------------------------------------------------------------

class TestArpScanner:
    """ArpScanner detects clients via arp-scan or nmap fallback."""

    def test_scan_uses_arp_scan_when_available(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        result.stdout = "192.168.1.1\t00:11:22:33:44:55\tRouter\n"
        mock_runner.run.return_value = result
        scanner = ArpScanner(runner=mock_runner)
        count = scanner.scan()
        assert count == 1
        cmd = mock_runner.run.call_args[0][0]
        assert "arp-scan" in cmd

    def test_scan_falls_back_to_nmap(self):
        mock_runner = MagicMock()
        # First call (arp-scan) fails
        # Second call (ip route) returns subnet
        # Third call (nmap) succeeds
        arp_exc = FileNotFoundError("arp-scan not installed")
        route_result = MagicMock()
        route_result.stdout = "192.168.1.0/24 dev wlan0 proto kernel scope link\n"
        nmap_result = MagicMock()
        nmap_result.stdout = "Host: 192.168.1.1 ()\tStatus: Up\n"
        mock_runner.run.side_effect = [arp_exc, route_result, nmap_result]
        scanner = ArpScanner(runner=mock_runner)
        count = scanner.scan()
        assert count == 1

    def test_scan_returns_zero_when_both_fail(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = FileNotFoundError("not found")
        scanner = ArpScanner(runner=mock_runner)
        count = scanner.scan()
        assert count == 0

    def test_interface_passed_to_arp_scan(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        mock_runner.run.return_value = result
        scanner = ArpScanner(interface="wlan1", runner=mock_runner)
        scanner.scan()
        cmd = mock_runner.run.call_args[0][0]
        assert "-I" in cmd
        assert "wlan1" in cmd

    def test_arp_scan_partial_result_accepted(self):
        """arp-scan exit code 1 (partial results) is still accepted."""
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 1
        result.stdout = "192.168.1.1\t00:11:22:33:44:55\tRouter\n"
        mock_runner.run.return_value = result
        scanner = ArpScanner(runner=mock_runner)
        count = scanner.scan()
        assert count == 1

    def test_arp_scan_bad_exit_code_falls_through(self):
        """arp-scan exit codes other than 0,1 trigger nmap fallback."""
        mock_runner = MagicMock()
        arp_result = MagicMock()
        arp_result.returncode = 2
        arp_result.stdout = ""
        route_result = MagicMock()
        route_result.stdout = "192.168.1.0/24 dev wlan0\n"
        nmap_result = MagicMock()
        nmap_result.stdout = "Host: 192.168.1.1 ()\tStatus: Up\n"
        mock_runner.run.side_effect = [arp_result, route_result, nmap_result]
        scanner = ArpScanner(runner=mock_runner)
        count = scanner.scan()
        assert count == 1
