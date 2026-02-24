"""Tests for wifimonitor.scanning.nmcli — nmcli scanning module.

These tests import directly from the canonical module location
(wifimonitor.scanning.nmcli) rather than the backward-compat re-exports
in wifi_monitor_nitro5.  This validates the new module in isolation.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from wifimonitor.wifi_common import Network, _minimal_env
from wifimonitor.scanning.nmcli import (
    scan_wifi_nmcli,
    parse_nmcli_output,
    _split_nmcli_line,
    _pct_to_dbm,
    _map_nmcli_security,
    main as nmcli_main,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_NMCLI_OUTPUT = r"""AA\:BB\:CC\:DD\:EE\:01:HomeNetwork:6:85:WPA2
AA\:BB\:CC\:DD\:EE\:02:CoffeeShop:11:42:
AA\:BB\:CC\:DD\:EE\:03:My\:Weird\:SSID:1:70:WPA1 WPA2
AA\:BB\:CC\:DD\:EE\:04::36:30:WPA2
AA\:BB\:CC\:DD\:EE\:05:Office 5G:149:65:WPA3"""


@pytest.fixture
def sample_networks():
    return parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)


# ---------------------------------------------------------------------------
# _split_nmcli_line
# ---------------------------------------------------------------------------

class TestSplitNmcliLine:
    def test_simple_fields_splits_on_colons(self):
        assert _split_nmcli_line("a:b:c") == ["a", "b", "c"]

    def test_escaped_colons_preserved_in_field(self):
        assert _split_nmcli_line(r"AA\:BB:SSID\:Name:6") == ["AA:BB", "SSID:Name", "6"]

    def test_escaped_backslash_unescaped(self):
        assert _split_nmcli_line(r"field\\value:other") == ["field\\value", "other"]

    def test_empty_field_returns_empty_string(self):
        assert _split_nmcli_line("a::c") == ["a", "", "c"]

    def test_no_colons_returns_single_element(self):
        assert _split_nmcli_line("nocolons") == ["nocolons"]


# ---------------------------------------------------------------------------
# _pct_to_dbm
# ---------------------------------------------------------------------------

class TestPctToDbm:
    @pytest.mark.parametrize("pct, expected_dbm", [
        (0, -100), (1, -100), (50, -75), (100, -50), (85, -58),
    ])
    def test_known_values(self, pct, expected_dbm):
        assert _pct_to_dbm(pct) == expected_dbm

    def test_negative_clamped_to_zero(self):
        assert _pct_to_dbm(-10) == -100

    def test_over_100_clamped(self):
        assert _pct_to_dbm(150) == -50


# ---------------------------------------------------------------------------
# _map_nmcli_security
# ---------------------------------------------------------------------------

class TestMapNmcliSecurity:
    @pytest.mark.parametrize("raw, expected", [
        ("WPA2", "WPA2"), ("WPA1 WPA2", "WPA2"), ("WPA3", "WPA3"),
        ("SAE", "WPA3"), ("WPA", "WPA"), ("WEP", "WEP"),
        ("", "Open"), ("--", "Open"),
    ])
    def test_maps_correctly(self, raw, expected):
        assert _map_nmcli_security(raw) == expected

    def test_case_insensitive(self):
        assert _map_nmcli_security("wpa2") == "WPA2"


# ---------------------------------------------------------------------------
# parse_nmcli_output
# ---------------------------------------------------------------------------

class TestParseNmcliOutput:
    def test_returns_correct_count(self, sample_networks):
        assert len(sample_networks) == 5

    def test_bssid_lowercased(self, sample_networks):
        home = [n for n in sample_networks if n.ssid == "HomeNetwork"][0]
        assert home.bssid == "aa:bb:cc:dd:ee:01"

    def test_ssid_with_colons_unescaped(self, sample_networks):
        weird = [n for n in sample_networks if "Weird" in n.ssid][0]
        assert weird.ssid == "My:Weird:SSID"

    def test_signal_converted_to_dbm(self, sample_networks):
        home = [n for n in sample_networks if n.ssid == "HomeNetwork"][0]
        assert home.signal == -58  # 85% → (85//2)-100

    def test_sorts_by_signal_descending(self, sample_networks):
        signals = [n.signal for n in sample_networks]
        assert signals == sorted(signals, reverse=True)

    def test_empty_string_returns_empty_list(self):
        assert parse_nmcli_output("") == []

    def test_truncated_line_skipped(self):
        assert parse_nmcli_output(r"AA\:BB\:CC\:DD\:EE\:01:Short:6") == []

    def test_hidden_ssid_preserved_as_empty(self, sample_networks):
        hidden = [n for n in sample_networks if n.ssid == ""][0]
        assert hidden.channel == 36


# ---------------------------------------------------------------------------
# scan_wifi_nmcli — via mock subprocess
# ---------------------------------------------------------------------------

class TestScanWifiNmcli:
    """scan_wifi_nmcli handles subprocess failures gracefully."""

    @patch("wifimonitor.scanning.nmcli.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmcli"], timeout=15))
    def test_timeout_returns_empty_list(self, _mock):
        assert scan_wifi_nmcli() == []

    @patch("wifimonitor.scanning.nmcli.subprocess.run", side_effect=FileNotFoundError("nmcli not found"))
    def test_file_not_found_returns_empty_list(self, _mock):
        assert scan_wifi_nmcli() == []


# ---------------------------------------------------------------------------
# _minimal_env — now in wifi_common
# ---------------------------------------------------------------------------

class TestMinimalEnv:
    def test_contains_required_keys(self):
        env = _minimal_env()
        assert "PATH" in env
        assert "LC_ALL" in env
        assert "HOME" in env

    def test_lc_all_is_c(self):
        env = _minimal_env()
        assert env["LC_ALL"] == "C"

    def test_does_not_leak_full_environment(self):
        assert len(_minimal_env()) <= 4


# ---------------------------------------------------------------------------
# Standalone main
# ---------------------------------------------------------------------------

class TestNmcliMain:
    """The standalone main() prints scan results."""

    @patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=[])
    def test_no_networks_prints_message(self, _mock, capsys):
        nmcli_main([])
        assert "No networks found" in capsys.readouterr().out

    @patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=[
        Network(bssid="aa:bb:cc:dd:ee:01", ssid="TestNet", signal=-55, channel=6, security="WPA2"),
    ])
    def test_table_output(self, _mock, capsys):
        nmcli_main([])
        out = capsys.readouterr().out
        assert "TestNet" in out
        assert "1 network(s) found" in out

    @patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=[
        Network(bssid="aa:bb:cc:dd:ee:01", ssid="TestNet", signal=-55, channel=6, security="WPA2"),
    ])
    def test_json_output(self, _mock, capsys):
        nmcli_main(["--json"])
        import json
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1
        assert data[0]["ssid"] == "TestNet"

    @patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=[])
    def test_interface_flag_passed(self, mock_scan):
        nmcli_main(["-i", "wlan1"])
        mock_scan.assert_called_once_with(interface="wlan1")
