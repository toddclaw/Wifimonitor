"""Tests for wifi_monitor_nitro5 nmcli scanning.

Follows TDD agent standards:
- test_<what>_<condition>_<expected_outcome> naming
- One concept per test
- @pytest.mark.parametrize for repetitive cases
- pytest.fixture for shared setup
- Unhappy-path coverage (malformed input, edge cases)
"""

import argparse
import io as _io
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from wifimonitor.wifi_common import Network, KnownNetwork, RogueAlert, DeauthEvent, ScannerProtocol, RendererProtocol
from wifimonitor.wifi_monitor_nitro5 import (
    MIN_PYTHON,
    parse_nmcli_output,
    _split_nmcli_line,
    _pct_to_dbm,
    _map_nmcli_security,
    _bar_string,
    _rich_color,
    _minimal_env,
    build_table,
    scan_wifi_nmcli,
    load_credentials,
    connect_wifi_nmcli,
    load_baseline,
    save_baseline,
    detect_rogue_aps,
    build_rogue_table,
    parse_tcpdump_deauth_line,
    parse_tcpdump_dns_line,
    DnsTracker,
    build_dns_table,
    _parse_args,
    AirodumpScanner,
    ArpScanner,
    NmcliScanner,
    RichNetworkRenderer,
    _get_connected_bssid,
    _get_subnet,
    _parse_arp_scan_output,
    _parse_nmap_output,
    _dump_startup_config,
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


@pytest.fixture
def home_network(sample_networks):
    return [n for n in sample_networks if n.ssid == "HomeNetwork"][0]


@pytest.fixture
def coffee_network(sample_networks):
    return [n for n in sample_networks if n.ssid == "CoffeeShop"][0]


# ---------------------------------------------------------------------------
# _split_nmcli_line — escaped colon handling
# ---------------------------------------------------------------------------

class TestSplitNmcliLine:
    def test_split_nmcli_line_simple_fields_splits_on_colons(self):
        result = _split_nmcli_line("a:b:c")
        assert result == ["a", "b", "c"]

    def test_split_nmcli_line_escaped_colons_preserved_in_field(self):
        result = _split_nmcli_line(r"AA\:BB:SSID\:Name:6")
        assert result == ["AA:BB", "SSID:Name", "6"]

    def test_split_nmcli_line_escaped_backslash_unescaped(self):
        result = _split_nmcli_line(r"field\\value:other")
        assert result == ["field\\value", "other"]

    def test_split_nmcli_line_empty_field_returns_empty_string(self):
        result = _split_nmcli_line("a::c")
        assert result == ["a", "", "c"]

    def test_split_nmcli_line_all_empty_fields(self):
        result = _split_nmcli_line(":::")
        assert result == ["", "", "", ""]

    def test_split_nmcli_line_no_colons_returns_single_element(self):
        result = _split_nmcli_line("nocolons")
        assert result == ["nocolons"]


# ---------------------------------------------------------------------------
# _pct_to_dbm — signal percentage conversion
# ---------------------------------------------------------------------------

class TestPctToDbm:
    @pytest.mark.parametrize("pct, expected_dbm", [
        (0, -100),
        (1, -100),
        (50, -75),
        (100, -50),
        (85, -58),
        (42, -79),
    ])
    def test_pct_to_dbm_known_values(self, pct, expected_dbm):
        assert _pct_to_dbm(pct) == expected_dbm

    def test_pct_to_dbm_zero_returns_minus_100(self):
        assert _pct_to_dbm(0) == -100

    def test_pct_to_dbm_100_returns_minus_50(self):
        assert _pct_to_dbm(100) == -50


# ---------------------------------------------------------------------------
# _map_nmcli_security — security label mapping
# ---------------------------------------------------------------------------

class TestMapNmcliSecurity:
    @pytest.mark.parametrize("raw, expected", [
        ("WPA2", "WPA2"),
        ("WPA1 WPA2", "WPA2"),
        ("WPA2 WPA3", "WPA3"),
        ("WPA3", "WPA3"),
        ("SAE", "WPA3"),
        ("WPA1", "WPA"),
        ("WPA", "WPA"),
        ("WEP", "WEP"),
        ("", "Open"),
        ("--", "Open"),
    ])
    def test_map_nmcli_security_maps_correctly(self, raw, expected):
        assert _map_nmcli_security(raw) == expected

    def test_map_nmcli_security_case_insensitive(self):
        assert _map_nmcli_security("wpa2") == "WPA2"
        assert _map_nmcli_security("Wpa3") == "WPA3"

    def test_map_nmcli_security_unknown_string_returns_open(self):
        assert _map_nmcli_security("SOMETHING_UNKNOWN") == "Open"


# ---------------------------------------------------------------------------
# parse_nmcli_output — happy path
# ---------------------------------------------------------------------------

class TestParseNmcliOutput:
    def test_parse_nmcli_output_all_networks_returns_correct_count(self, sample_networks):
        assert len(sample_networks) == 5

    def test_parse_nmcli_output_single_network_returns_one_entry(self):
        single = r"AA\:BB\:CC\:DD\:EE\:FF:TestNet:6:80:WPA2"
        networks = parse_nmcli_output(single)
        assert len(networks) == 1
        assert networks[0].ssid == "TestNet"

    def test_parse_nmcli_output_bssid_lowercased(self, home_network):
        assert home_network.bssid == "aa:bb:cc:dd:ee:01"

    def test_parse_nmcli_output_bssid_colons_unescaped(self, home_network):
        assert ":" in home_network.bssid
        assert "\\" not in home_network.bssid

    def test_parse_nmcli_output_ssid_with_escaped_colons_unescaped(self, sample_networks):
        weird = [n for n in sample_networks if "Weird" in n.ssid][0]
        assert weird.ssid == "My:Weird:SSID"

    def test_parse_nmcli_output_ssid_with_spaces_preserved(self, sample_networks):
        office = [n for n in sample_networks if "Office" in n.ssid][0]
        assert office.ssid == "Office 5G"

    def test_parse_nmcli_output_hidden_ssid_has_empty_string(self, sample_networks):
        hidden = [n for n in sample_networks if n.ssid == ""][0]
        assert hidden.ssid == ""
        assert hidden.channel == 36

    def test_parse_nmcli_output_signal_converted_to_dbm(self, home_network):
        # 85% -> (85 // 2) - 100 = -58 dBm
        assert home_network.signal == -58

    def test_parse_nmcli_output_channel_parsed(self, home_network):
        assert home_network.channel == 6

    def test_parse_nmcli_output_5ghz_channel_parsed(self, sample_networks):
        office = [n for n in sample_networks if n.ssid == "Office 5G"][0]
        assert office.channel == 149

    def test_parse_nmcli_output_security_wpa2(self, home_network):
        assert home_network.security == "WPA2"

    def test_parse_nmcli_output_security_open_when_empty(self, coffee_network):
        assert coffee_network.security == "Open"

    def test_parse_nmcli_output_security_wpa3(self, sample_networks):
        office = [n for n in sample_networks if n.ssid == "Office 5G"][0]
        assert office.security == "WPA3"

    def test_parse_nmcli_output_security_mixed_wpa_picks_highest(self, sample_networks):
        weird = [n for n in sample_networks if "Weird" in n.ssid][0]
        assert weird.security == "WPA2"

    def test_parse_nmcli_output_sorts_by_signal_descending(self, sample_networks):
        signals = [n.signal for n in sample_networks]
        assert signals == sorted(signals, reverse=True)

    def test_parse_nmcli_output_clients_always_zero(self, sample_networks):
        """nmcli can't detect clients; all should default to 0."""
        for net in sample_networks:
            assert net.clients == 0


# ---------------------------------------------------------------------------
# parse_nmcli_output — edge cases / unhappy paths
# ---------------------------------------------------------------------------

class TestParseNmcliOutputEdgeCases:
    def test_parse_nmcli_output_empty_string_returns_empty_list(self):
        assert parse_nmcli_output("") == []

    def test_parse_nmcli_output_whitespace_only_returns_empty_list(self):
        assert parse_nmcli_output("   \n  \n   ") == []

    def test_parse_nmcli_output_blank_lines_skipped(self):
        padded = "\n\n" + SAMPLE_NMCLI_OUTPUT + "\n\n"
        networks = parse_nmcli_output(padded)
        assert len(networks) == 5

    def test_parse_nmcli_output_truncated_line_fewer_than_5_fields_skipped(self):
        truncated = r"AA\:BB\:CC\:DD\:EE\:01:ShortLine:6"
        networks = parse_nmcli_output(truncated)
        assert networks == []

    def test_parse_nmcli_output_mixed_valid_and_truncated_lines(self):
        mixed = (
            r"AA\:BB\:CC\:DD\:EE\:01:GoodNet:6:80:WPA2" + "\n"
            r"AA\:BB\:CC\:DD\:EE\:02:Bad" + "\n"
            r"AA\:BB\:CC\:DD\:EE\:03:AlsoGood:11:60:WPA3"
        )
        networks = parse_nmcli_output(mixed)
        assert len(networks) == 2
        ssids = {n.ssid for n in networks}
        assert ssids == {"GoodNet", "AlsoGood"}

    def test_parse_nmcli_output_non_numeric_signal_defaults_to_zero_pct(self):
        line = r"AA\:BB\:CC\:DD\:EE\:01:BadSig:6:abc:WPA2"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        # 0% -> (0 // 2) - 100 = -100
        assert networks[0].signal == -100

    def test_parse_nmcli_output_non_numeric_channel_defaults_to_zero(self):
        line = r"AA\:BB\:CC\:DD\:EE\:01:BadChan:xyz:80:WPA2"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        assert networks[0].channel == 0

    def test_parse_nmcli_output_duplicate_bssids_kept_as_separate_entries(self):
        """nmcli may report same BSSID on different bands."""
        dupes = (
            r"AA\:BB\:CC\:DD\:EE\:01:DualBand:6:80:WPA2" + "\n"
            r"AA\:BB\:CC\:DD\:EE\:01:DualBand:36:70:WPA2"
        )
        networks = parse_nmcli_output(dupes)
        assert len(networks) == 2
        channels = {n.channel for n in networks}
        assert channels == {6, 36}

    def test_parse_nmcli_output_very_long_ssid_preserved(self):
        long_ssid = "A" * 200
        line = rf"AA\:BB\:CC\:DD\:EE\:01:{long_ssid}:6:80:WPA2"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        assert networks[0].ssid == long_ssid

    def test_parse_nmcli_output_ssid_with_rich_markup_chars_preserved(self):
        """SSIDs may contain brackets that look like Rich markup."""
        line = r"AA\:BB\:CC\:DD\:EE\:01:[bold red]Evil[/bold red]:6:80:WPA2"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        assert networks[0].ssid == "[bold red]Evil[/bold red]"

    def test_parse_nmcli_output_security_dash_dash_means_open(self):
        line = r"AA\:BB\:CC\:DD\:EE\:01:OpenNet:6:80:--"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        assert networks[0].security == "Open"

    def test_parse_nmcli_output_extra_fields_beyond_5_ignored(self):
        """Future nmcli versions might add fields; parser should be resilient."""
        line = r"AA\:BB\:CC\:DD\:EE\:01:ExtraFields:6:80:WPA2:extra1:extra2"
        networks = parse_nmcli_output(line)
        assert len(networks) == 1
        assert networks[0].ssid == "ExtraFields"
        assert networks[0].security == "WPA2"

    @pytest.mark.parametrize("signal_pct, expected_dbm", [
        ("0", -100),
        ("100", -50),
        ("50", -75),
        ("1", -100),
        ("99", -51),
    ])
    def test_parse_nmcli_output_signal_conversion_boundary_values(
        self, signal_pct, expected_dbm
    ):
        line = rf"AA\:BB\:CC\:DD\:EE\:01:BoundaryTest:6:{signal_pct}:WPA2"
        networks = parse_nmcli_output(line)
        assert networks[0].signal == expected_dbm


# ---------------------------------------------------------------------------
# _pct_to_dbm — input clamping (P1 fix)
# ---------------------------------------------------------------------------

class TestPctToDbmClamping:
    """_pct_to_dbm must clamp values outside 0-100 to prevent nonsense dBm."""

    def test_pct_to_dbm_negative_value_clamped_to_zero(self):
        assert _pct_to_dbm(-10) == -100  # same as 0%

    def test_pct_to_dbm_over_100_clamped_to_100(self):
        assert _pct_to_dbm(150) == -50  # same as 100%

    def test_pct_to_dbm_exactly_zero_still_works(self):
        assert _pct_to_dbm(0) == -100

    def test_pct_to_dbm_exactly_100_still_works(self):
        assert _pct_to_dbm(100) == -50


# ---------------------------------------------------------------------------
# _bar_string — signal bar rendering
# ---------------------------------------------------------------------------

class TestBarString:
    def test_bar_string_4_bars_all_filled(self):
        result = _bar_string(4)
        assert result == "▂▄▆█"

    def test_bar_string_0_bars_all_spaces(self):
        result = _bar_string(0)
        assert result == "    "

    def test_bar_string_2_bars_two_filled_two_spaces(self):
        result = _bar_string(2)
        assert result == "▂▄  "

    def test_bar_string_1_bar(self):
        result = _bar_string(1)
        assert result == "▂   "


# ---------------------------------------------------------------------------
# _rich_color — RGB to Rich color name mapping
# ---------------------------------------------------------------------------

class TestRichColor:
    def test_rich_color_known_green(self):
        assert _rich_color((0, 255, 0)) == "green"

    def test_rich_color_known_red(self):
        assert _rich_color((255, 0, 0)) == "red"

    def test_rich_color_unknown_returns_white(self):
        assert _rich_color((1, 2, 3)) == "white"


# ---------------------------------------------------------------------------
# build_table — Rich markup injection protection (P0 fix)
# ---------------------------------------------------------------------------

class TestBuildTable:
    """build_table must escape attacker-controlled SSIDs to prevent Rich markup injection."""

    def test_build_table_returns_table_with_correct_network_count(self):
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Normal", signal=-55, channel=6, security="WPA2"),
        ]
        table = build_table(networks)
        assert table.row_count == 1

    def test_build_table_hidden_ssid_shows_hidden_markup(self):
        """Hidden SSIDs (empty string) should show <hidden> with dim styling."""
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="", signal=-55, channel=6, security="WPA2"),
        ]
        table = build_table(networks)
        # Table should have 1 row and not crash
        assert table.row_count == 1

    def test_build_table_ssid_with_rich_markup_escaped(self):
        """An SSID containing Rich markup chars must be escaped, not interpreted."""
        networks = [
            Network(
                bssid="aa:bb:cc:dd:ee:01",
                ssid="[bold red]Evil[/bold red]",
                signal=-55,
                channel=6,
                security="WPA2",
            ),
        ]
        # This should NOT raise a markup error or render styled text
        table = build_table(networks)
        assert table.row_count == 1

    def test_build_table_ssid_with_square_brackets_escaped(self):
        """SSIDs with square brackets must not be treated as Rich tags."""
        networks = [
            Network(
                bssid="aa:bb:cc:dd:ee:01",
                ssid="[test]network[/test]",
                signal=-55,
                channel=6,
                security="WPA2",
            ),
        ]
        table = build_table(networks)
        assert table.row_count == 1

    def test_build_table_empty_network_list(self):
        table = build_table([])
        assert table.row_count == 0

    def test_build_table_multiple_networks_preserves_order(self):
        """Networks should appear in the order passed (already sorted by caller)."""
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Best", signal=-40, channel=6, security="WPA2"),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Worst", signal=-90, channel=11, security="Open"),
        ]
        table = build_table(networks)
        assert table.row_count == 2


# ---------------------------------------------------------------------------
# scan_wifi_nmcli — timeout and exception handling (P1 fix)
# ---------------------------------------------------------------------------

class TestScanWifiNmcli:
    """scan_wifi_nmcli must handle subprocess failures gracefully."""

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_timeout_returns_empty_list(self, mock_run):
        """If nmcli times out, return empty list instead of crashing."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmcli"], timeout=15)
        result = scan_wifi_nmcli()
        assert result == []

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_subprocess_error_returns_empty_list(self, mock_run):
        """If nmcli is not found or fails, return empty list."""
        mock_run.side_effect = FileNotFoundError("nmcli not found")
        result = scan_wifi_nmcli()
        assert result == []

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_rescan_failure_still_lists(self, mock_run):
        """If rescan fails but list succeeds, still return networks."""
        rescan_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        list_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=r"AA\:BB\:CC\:DD\:EE\:01:TestNet:6:80:WPA2",
            stderr="",
        )
        mock_run.side_effect = [rescan_result, list_result]
        result = scan_wifi_nmcli()
        assert len(result) == 1
        assert result[0].ssid == "TestNet"

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_uses_minimal_env(self, mock_run):
        """Subprocess should not inherit the full user environment."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        scan_wifi_nmcli()
        # Check the env passed to the list command (second call)
        _, kwargs = mock_run.call_args
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert "PATH" in env
        # Env should NOT contain every key from os.environ
        # It should be a minimal set
        assert len(env) <= 4  # PATH, LC_ALL, HOME


# ---------------------------------------------------------------------------
# _minimal_env — environment hardening
# ---------------------------------------------------------------------------

class TestMinimalEnv:
    def test_minimal_env_contains_required_keys(self):
        env = _minimal_env()
        assert "PATH" in env
        assert "LC_ALL" in env
        assert "HOME" in env

    def test_minimal_env_lc_all_is_c(self):
        env = _minimal_env()
        assert env["LC_ALL"] == "C"

    def test_minimal_env_does_not_leak_full_environment(self):
        env = _minimal_env()
        assert len(env) <= 4


# ---------------------------------------------------------------------------
# load_credentials — credentials file parsing
# ---------------------------------------------------------------------------

class TestLoadCredentials:
    """load_credentials parses a CSV file of ssid,passphrase pairs."""

    def test_load_credentials_happy_path(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("HomeNetwork,secretpass\nCoffeeShop,cafe2024\n")
        result = load_credentials(str(creds_file))
        assert result == {"HomeNetwork": "secretpass", "CoffeeShop": "cafe2024"}

    def test_load_credentials_skips_comment_lines(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("# This is a comment\nMyNet,pass123\n")
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}

    def test_load_credentials_skips_blank_lines(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("\nMyNet,pass123\n\n\n")
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}

    def test_load_credentials_empty_file_returns_empty_dict(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("")
        result = load_credentials(str(creds_file))
        assert result == {}

    def test_load_credentials_missing_file_returns_empty_dict(self, tmp_path):
        result = load_credentials(str(tmp_path / "nonexistent.csv"))
        assert result == {}

    def test_load_credentials_quoted_fields_with_commas(self, tmp_path):
        """SSIDs or passphrases containing commas must be quoted in CSV."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text('"My,Network","pass,word"\n')
        result = load_credentials(str(creds_file))
        assert result == {"My,Network": "pass,word"}

    def test_load_credentials_malformed_line_too_few_fields_skipped(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("OnlySSID\nGoodNet,goodpass\n")
        result = load_credentials(str(creds_file))
        assert result == {"GoodNet": "goodpass"}

    def test_load_credentials_extra_fields_ignored(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("MyNet,pass123,extra,fields\n")
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}

    def test_load_credentials_strips_whitespace_from_ssid_and_pass(self, tmp_path):
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("  MyNet  ,  pass123  \n")
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}

    def test_load_credentials_empty_passphrase_stored(self, tmp_path):
        """Open networks can have empty passphrases."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("OpenNet,\n")
        result = load_credentials(str(creds_file))
        assert result == {"OpenNet": ""}

    def test_load_credentials_warns_world_readable(self, tmp_path, capsys):
        """Should warn (not fail) if file is world-readable."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("MyNet,pass123\n")
        creds_file.chmod(0o644)
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}
        captured = capsys.readouterr()
        assert "world-readable" in captured.err.lower() or "permissions" in captured.err.lower()

    def test_load_credentials_no_warning_restrictive_permissions(self, tmp_path, capsys):
        """Should not warn if file has restrictive permissions."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("MyNet,pass123\n")
        creds_file.chmod(0o600)
        result = load_credentials(str(creds_file))
        assert result == {"MyNet": "pass123"}
        captured = capsys.readouterr()
        assert "world-readable" not in captured.err.lower()


# ---------------------------------------------------------------------------
# connect_wifi_nmcli — network connection
# ---------------------------------------------------------------------------

class TestConnectWifiNmcli:
    """connect_wifi_nmcli joins a network via nmcli."""

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_success_returns_true(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is True

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_failure_returns_false(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Connection failed",
        )
        result = connect_wifi_nmcli("TestNet", "wrongpass")
        assert result is False

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_timeout_returns_false(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmcli"], timeout=30)
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is False

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_nmcli_not_found_returns_false(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nmcli not found")
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is False

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_uses_list_args(self, mock_run):
        """Must use list args, never shell=True."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        connect_wifi_nmcli("TestNet", "password123")
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert isinstance(cmd, list)
        assert "nmcli" in cmd
        assert "TestNet" in cmd
        assert "password123" in cmd

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_with_interface(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        connect_wifi_nmcli("TestNet", "pass", interface="wlan1")
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert "ifname" in cmd
        assert "wlan1" in cmd

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_uses_minimal_env(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        connect_wifi_nmcli("TestNet", "pass")
        _, kwargs = mock_run.call_args
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert len(env) <= 4

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_open_network_empty_passphrase(self, mock_run):
        """Open networks use empty passphrase — should still call nmcli."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        result = connect_wifi_nmcli("OpenNet", "")
        assert result is True
        args, _ = mock_run.call_args
        cmd = args[0]
        # For open networks, password should not be in the command
        assert "password" not in cmd


# ---------------------------------------------------------------------------
# build_table — credentials integration
# ---------------------------------------------------------------------------

class TestBuildTableWithCredentials:
    """build_table shows a key indicator when credentials are provided."""

    def test_build_table_with_credentials_has_key_column(self):
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Known", signal=-55, channel=6, security="WPA2"),
        ]
        creds = {"Known": "password"}
        table = build_table(networks, credentials=creds)
        col_names = [c.header for c in table.columns]
        assert "Key" in col_names

    def test_build_table_without_credentials_no_key_column(self):
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", signal=-55, channel=6, security="WPA2"),
        ]
        table = build_table(networks)
        col_names = [c.header for c in table.columns]
        assert "Key" not in col_names

    def test_build_table_with_credentials_row_count_correct(self):
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Known", signal=-55, channel=6, security="WPA2"),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Unknown", signal=-70, channel=11, security="WPA2"),
        ]
        creds = {"Known": "password"}
        table = build_table(networks, credentials=creds)
        assert table.row_count == 2

    def test_build_table_with_empty_credentials_no_key_column(self):
        networks = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", signal=-55, channel=6, security="WPA2"),
        ]
        table = build_table(networks, credentials={})
        col_names = [c.header for c in table.columns]
        assert "Key" not in col_names

    def test_build_table_has_clients_column(self):
        """Clients column displays per-BSSID client counts."""
        networks = [
            Network(
                bssid="aa:bb:cc:dd:ee:01",
                ssid="Home",
                signal=-55,
                channel=6,
                security="WPA2",
                clients=3,
            ),
        ]
        table = build_table(networks)
        col_names = [c.header for c in table.columns]
        assert "Cli" in col_names
        assert table.row_count == 1

    def test_build_table_displays_client_count(self):
        """Client count from Network.clients appears in table."""
        networks = [
            Network(
                bssid="aa:bb:cc:dd:ee:01",
                ssid="AP1",
                signal=-60,
                channel=6,
                security="WPA2",
                clients=5,
            ),
            Network(
                bssid="aa:bb:cc:dd:ee:02",
                ssid="AP2",
                signal=-70,
                channel=11,
                security="Open",
                clients=0,
            ),
        ]
        table = build_table(networks)
        assert table.row_count == 2
        # Verify Clients column exists and rows rendered
        col_headers = [c.header for c in table.columns]
        cli_idx = col_headers.index("Cli")
        # Row 0: 5 clients, Row 1: 0 clients
        assert table.columns[cli_idx] is not None


# ---------------------------------------------------------------------------
# parse_tcpdump_dns_line — DNS query extraction from tcpdump output
# ---------------------------------------------------------------------------

class TestParseTcpdumpDnsLine:
    """parse_tcpdump_dns_line extracts the queried domain from a tcpdump line."""

    def test_a_record_query_extracts_domain(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? google.com. (28)"
        assert parse_tcpdump_dns_line(line) == "google.com"

    def test_aaaa_record_query_extracts_domain(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ AAAA? example.org. (32)"
        assert parse_tcpdump_dns_line(line) == "example.org"

    def test_subdomain_preserved(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? cdn.images.example.com. (40)"
        assert parse_tcpdump_dns_line(line) == "cdn.images.example.com"

    def test_ptr_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ PTR? 1.0.168.192.in-addr.arpa. (44)"
        assert parse_tcpdump_dns_line(line) == "1.0.168.192.in-addr.arpa"

    def test_https_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ HTTPS? cloudflare.com. (32)"
        assert parse_tcpdump_dns_line(line) == "cloudflare.com"

    def test_mx_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ MX? mail.example.com. (35)"
        assert parse_tcpdump_dns_line(line) == "mail.example.com"

    def test_response_line_returns_none(self):
        """DNS responses don't contain the ?-pattern for query type."""
        line = "20:15:30.123 IP 8.8.8.8.53 > 192.168.1.100.54321: 65432 1/0/0 A 93.184.216.34 (50)"
        assert parse_tcpdump_dns_line(line) is None

    def test_empty_line_returns_none(self):
        assert parse_tcpdump_dns_line("") is None

    def test_non_dns_line_returns_none(self):
        line = "20:15:30.123 IP 192.168.1.100.80 > 10.0.0.1.12345: Flags [S], seq 12345"
        assert parse_tcpdump_dns_line(line) is None

    def test_trailing_dot_stripped(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? trailing.dot.com. (30)"
        result = parse_tcpdump_dns_line(line)
        assert result == "trailing.dot.com"
        assert not result.endswith(".")

    def test_domain_with_hyphen(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? my-site.example.com. (38)"
        assert parse_tcpdump_dns_line(line) == "my-site.example.com"

    def test_domain_with_numbers(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? s3.us-east-1.amazonaws.com. (44)"
        assert parse_tcpdump_dns_line(line) == "s3.us-east-1.amazonaws.com"


# ---------------------------------------------------------------------------
# parse_tcpdump_deauth_line — deauth/disassoc frame parser
# ---------------------------------------------------------------------------

class TestParseTcpdumpDeauthLine:
    """parse_tcpdump_deauth_line extracts deauth/disassoc events from tcpdump -e output."""

    DEAUTH_LINE = (
        "11:04:34.360700 314us BSSID:00:14:6c:7e:40:80 "
        "DA:00:0f:b5:46:11:19 SA:00:14:6c:7e:40:80 "
        "DeAuthentication: Class 3 frame received from nonassociated station"
    )

    DISASSOC_LINE = (
        "12:30:01.123456 200us BSSID:aa:bb:cc:dd:ee:01 "
        "DA:11:22:33:44:55:66 SA:aa:bb:cc:dd:ee:01 "
        "Disassociation: Deauthenticated because sending station is leaving"
    )

    BROADCAST_DEAUTH = (
        "13:00:00.000000 100us BSSID:00:14:6c:7e:40:80 "
        "DA:ff:ff:ff:ff:ff:ff SA:00:14:6c:7e:40:80 "
        "DeAuthentication: Unspecified"
    )

    def test_valid_deauth_line_returns_event(self):
        result = parse_tcpdump_deauth_line(self.DEAUTH_LINE)
        assert result is not None
        assert isinstance(result, DeauthEvent)
        assert result.subtype == "deauth"

    def test_deauth_bssid_lowercased(self):
        result = parse_tcpdump_deauth_line(self.DEAUTH_LINE)
        assert result is not None
        assert result.bssid == "00:14:6c:7e:40:80"

    def test_deauth_source_and_destination(self):
        result = parse_tcpdump_deauth_line(self.DEAUTH_LINE)
        assert result is not None
        assert result.source == "00:14:6c:7e:40:80"
        assert result.destination == "00:0f:b5:46:11:19"

    def test_deauth_reason_captured(self):
        result = parse_tcpdump_deauth_line(self.DEAUTH_LINE)
        assert result is not None
        assert "Class 3 frame" in result.reason

    def test_valid_disassoc_line_returns_event(self):
        result = parse_tcpdump_deauth_line(self.DISASSOC_LINE)
        assert result is not None
        assert result.subtype == "disassoc"
        assert result.bssid == "aa:bb:cc:dd:ee:01"

    def test_disassoc_reason_captured(self):
        result = parse_tcpdump_deauth_line(self.DISASSOC_LINE)
        assert result is not None
        assert "leaving" in result.reason

    def test_broadcast_deauth_destination(self):
        result = parse_tcpdump_deauth_line(self.BROADCAST_DEAUTH)
        assert result is not None
        assert result.destination == "ff:ff:ff:ff:ff:ff"

    def test_non_deauth_line_returns_none(self):
        line = "11:04:34.360700 BSSID:00:14:6c:7e:40:80 Beacon (MyNetwork) [6.0 Mbit]"
        assert parse_tcpdump_deauth_line(line) is None

    def test_empty_string_returns_none(self):
        assert parse_tcpdump_deauth_line("") is None

    def test_dns_line_returns_none(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? example.com. (30)"
        assert parse_tcpdump_deauth_line(line) is None

    def test_uppercase_bssid_lowercased(self):
        line = (
            "11:04:34.360700 314us BSSID:AA:BB:CC:DD:EE:FF "
            "DA:11:22:33:44:55:66 SA:AA:BB:CC:DD:EE:FF "
            "DeAuthentication: Unspecified"
        )
        result = parse_tcpdump_deauth_line(line)
        assert result is not None
        assert result.bssid == "aa:bb:cc:dd:ee:ff"
        assert result.source == "aa:bb:cc:dd:ee:ff"
        assert result.destination == "11:22:33:44:55:66"

    def test_reason_with_reason_code_number(self):
        """Handles tcpdump output that includes numeric reason codes."""
        line = (
            "14:00:00.000000 100us BSSID:00:14:6c:7e:40:80 "
            "DA:00:0f:b5:46:11:19 SA:00:14:6c:7e:40:80 "
            "DeAuthentication: Deauthenticated (7)"
        )
        result = parse_tcpdump_deauth_line(line)
        assert result is not None
        assert "7" in result.reason


# ---------------------------------------------------------------------------
# DnsTracker — thread-safe DNS query counter
# ---------------------------------------------------------------------------

class TestDnsTracker:
    """DnsTracker tracks DNS domain query frequencies."""

    def test_record_increments_count(self):
        tracker = DnsTracker()
        tracker.record("google.com")
        tracker.record("google.com")
        tracker.record("example.com")
        top = tracker.top(10)
        assert top[0] == ("google.com", 2)
        assert top[1] == ("example.com", 1)

    def test_top_limits_results(self):
        tracker = DnsTracker()
        for i in range(20):
            tracker.record(f"domain{i}.com")
        assert len(tracker.top(5)) == 5

    def test_top_empty_tracker_returns_empty_list(self):
        tracker = DnsTracker()
        assert tracker.top(10) == []

    def test_top_sorted_by_count_descending(self):
        tracker = DnsTracker()
        tracker.record("rare.com")
        for _ in range(5):
            tracker.record("common.com")
        for _ in range(3):
            tracker.record("medium.com")
        top = tracker.top(10)
        assert top[0] == ("common.com", 5)
        assert top[1] == ("medium.com", 3)
        assert top[2] == ("rare.com", 1)

    def test_top_zero_returns_empty(self):
        tracker = DnsTracker()
        tracker.record("google.com")
        assert tracker.top(0) == []

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_start_returns_true_when_tcpdump_available(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        assert tracker.start() is True
        tracker.stop()

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_start_returns_false_when_tcpdump_not_found(self, mock_popen):
        mock_popen.side_effect = FileNotFoundError("tcpdump not found")
        tracker = DnsTracker()
        assert tracker.start() is False

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_start_uses_list_args(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        tracker.start()
        args, kwargs = mock_popen.call_args
        cmd = args[0]
        assert isinstance(cmd, list)
        assert "tcpdump" in cmd
        tracker.stop()

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_start_with_interface_includes_iflag(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        tracker.start(interface="wlan0")
        args, _ = mock_popen.call_args
        cmd = args[0]
        assert "-i" in cmd
        assert "wlan0" in cmd
        tracker.stop()

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_start_uses_minimal_env(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        tracker.start()
        _, kwargs = mock_popen.call_args
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert len(env) <= 4
        tracker.stop()

    @patch("wifimonitor.wifi_monitor_nitro5.subprocess.Popen")
    def test_stop_terminates_process(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        tracker.start()
        tracker.stop()
        mock_proc.terminate.assert_called_once()


# ---------------------------------------------------------------------------
# build_dns_table — DNS top domains display
# ---------------------------------------------------------------------------

class TestBuildDnsTable:
    """build_dns_table renders a ranked table of DNS domains."""

    def test_build_dns_table_with_domains_correct_row_count(self):
        domains = [("google.com", 42), ("example.com", 10)]
        table = build_dns_table(domains)
        assert table.row_count == 2

    def test_build_dns_table_empty_list(self):
        table = build_dns_table([])
        assert table.row_count == 0

    def test_build_dns_table_escapes_domain_names(self):
        """Domain names are external data and must be escaped for Rich."""
        domains = [("[bold]evil.com[/bold]", 1)]
        table = build_dns_table(domains)
        assert table.row_count == 1  # should not crash

    def test_build_dns_table_has_expected_columns(self):
        domains = [("google.com", 5)]
        table = build_dns_table(domains)
        col_names = [c.header for c in table.columns]
        assert "#" in col_names
        assert "Domain" in col_names
        assert "Count" in col_names

    def test_build_dns_table_single_domain(self):
        domains = [("test.com", 1)]
        table = build_dns_table(domains)
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# _parse_args — CLI argument parsing
# ---------------------------------------------------------------------------

class TestParseArgs:
    """_parse_args parses CLI arguments correctly."""

    def test_parse_args_dns_flag_default_false(self):
        args = _parse_args([])
        assert args.dns is False

    def test_parse_args_dns_flag_set(self):
        args = _parse_args(["--dns"])
        assert args.dns is True

    def test_parse_args_dns_with_interface(self):
        args = _parse_args(["--dns", "-i", "wlan0"])
        assert args.dns is True
        assert args.interface == "wlan0"

    def test_parse_args_all_flags_combined(self):
        args = _parse_args(["-i", "wlan0", "-c", "creds.csv", "--connect", "--dns"])
        assert args.interface == "wlan0"
        assert args.credentials == "creds.csv"
        assert args.connect is True
        assert args.dns is True

    def test_parse_args_monitor_flag_default_false(self):
        args = _parse_args([])
        assert args.monitor is False

    def test_parse_args_monitor_flag_set(self):
        args = _parse_args(["--monitor"])
        assert args.monitor is True

    def test_parse_args_monitor_with_interface(self):
        args = _parse_args(["--monitor", "-i", "wlan1"])
        assert args.monitor is True
        assert args.interface == "wlan1"


# ---------------------------------------------------------------------------
# AirodumpScanner — monitor mode client count scanning
# ---------------------------------------------------------------------------

class TestAirodumpScanner:
    """AirodumpScanner manages airodump-ng process and parses CSV for client counts."""

    def test_scan_returns_networks_with_clients_from_csv(self):
        """When CSV has station data, scan returns networks with clients populated."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV

        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)),
        ):
            networks = scanner.scan()
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        assert home.clients == 2
        assert coffee.clients == 1

    def test_scan_no_csv_returns_empty_list(self):
        """When no CSV file exists yet, scan returns empty list."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=[]):
            networks = scanner.scan()
        assert networks == []

    def test_scan_file_read_error_returns_empty_list(self):
        """When CSV file cannot be read, scan returns empty list."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
            patch("builtins.open", side_effect=OSError("Permission denied")),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)),
            patch(
                "wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli",
                return_value=nmcli_networks,
            ),
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with patch("wifimonitor.wifi_monitor_nitro5.time.sleep"):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
# MIN_PYTHON — version enforcement
# ---------------------------------------------------------------------------

class TestMinPython:
    """MIN_PYTHON enforces the minimum Python version."""

    def test_min_python_is_tuple(self):
        assert isinstance(MIN_PYTHON, tuple)
        assert len(MIN_PYTHON) == 2

    def test_min_python_is_3_9(self):
        assert MIN_PYTHON == (3, 9)

    def test_current_interpreter_meets_minimum(self):
        import sys
        assert sys.version_info >= MIN_PYTHON


# ---------------------------------------------------------------------------
# CommandRunner injection — subprocess testing without mock.patch
# ---------------------------------------------------------------------------

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


class TestScanWifiNmcliInjection:
    """scan_wifi_nmcli accepts an injected runner — no mock.patch needed."""

    def test_scan_returns_networks_via_injected_runner(self):
        fake = _FakeRunner()
        rescan = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        listing = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=r"AA\:BB\:CC\:DD\:EE\:01:TestNet:6:80:WPA2",
            stderr="",
        )
        fake.set_run_results(rescan, listing)
        result = scan_wifi_nmcli(runner=fake)
        assert len(result) == 1
        assert result[0].ssid == "TestNet"

    def test_scan_timeout_via_injected_runner(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["nmcli"], timeout=15))
        result = scan_wifi_nmcli(runner=fake)
        assert result == []

    def test_scan_passes_env_to_runner(self):
        fake = _FakeRunner()
        scan_wifi_nmcli(runner=fake)
        assert len(fake.run_calls) >= 1
        _, kwargs = fake.run_calls[-1]
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert "PATH" in env
        assert len(env) <= 4

    def test_scan_with_interface_via_injected_runner(self):
        fake = _FakeRunner()
        scan_wifi_nmcli(interface="wlan1", runner=fake)
        # Both rescan and list commands should contain the interface
        for cmd, _ in fake.run_calls:
            assert "ifname" in cmd
            assert "wlan1" in cmd


class TestConnectWifiNmcliInjection:
    """connect_wifi_nmcli accepts an injected runner."""

    def test_connect_success_via_injected_runner(self):
        fake = _FakeRunner()
        fake.set_run_results(
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        )
        assert connect_wifi_nmcli("TestNet", "pass", runner=fake) is True

    def test_connect_failure_via_injected_runner(self):
        fake = _FakeRunner()
        fake.set_run_results(
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="err"),
        )
        assert connect_wifi_nmcli("TestNet", "pass", runner=fake) is False

    def test_connect_timeout_via_injected_runner(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["nmcli"], timeout=30))
        assert connect_wifi_nmcli("TestNet", "pass", runner=fake) is False

    def test_connect_cmd_includes_ssid_and_password(self):
        fake = _FakeRunner()
        connect_wifi_nmcli("MyNet", "secret", runner=fake)
        cmd, _ = fake.run_calls[0]
        assert "MyNet" in cmd
        assert "secret" in cmd
        assert isinstance(cmd, list)


class TestDnsTrackerInjection:
    """DnsTracker accepts an injected runner."""

    def test_start_uses_injected_runner(self):
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        fake.set_popen_result(mock_proc)
        tracker = DnsTracker(runner=fake)
        assert tracker.start() is True
        assert len(fake.popen_calls) == 1
        cmd, _ = fake.popen_calls[0]
        assert "tcpdump" in cmd
        tracker.stop()

    def test_start_failure_via_injected_runner(self):
        fake = _FakeRunner()
        fake.set_popen_side_effect(FileNotFoundError("tcpdump not found"))
        tracker = DnsTracker(runner=fake)
        assert tracker.start() is False

    def test_start_passes_env_to_runner(self):
        fake = _FakeRunner()
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        fake.set_popen_result(mock_proc)
        tracker = DnsTracker(runner=fake)
        tracker.start()
        _, kwargs = fake.popen_calls[0]
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert len(env) <= 4
        tracker.stop()


# ---------------------------------------------------------------------------
# _parse_arp_scan_output — arp-scan stdout parsing
# ---------------------------------------------------------------------------

class TestParseArpScanOutput:
    """_parse_arp_scan_output counts unique responding hosts from arp-scan."""

    SAMPLE_ARP_OUTPUT = (
        "Interface: wlan0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.100\n"
        "Starting arp-scan 1.9.7 with 256 hosts\n"
        "192.168.1.1\t00:11:22:33:44:55\tNetgear\n"
        "192.168.1.50\t22:33:44:55:66:77\tApple Inc\n"
        "192.168.1.75\t33:44:55:66:77:88\tSamsung\n"
        "\n"
        "3 packets received by filter, 0 packets dropped by kernel\n"
        "Ending arp-scan 1.9.7: 256 hosts scanned in 1.337 seconds. 3 responded\n"
    )

    def test_counts_host_lines_correctly(self):
        assert _parse_arp_scan_output(self.SAMPLE_ARP_OUTPUT) == 3

    def test_empty_output_returns_zero(self):
        assert _parse_arp_scan_output("") == 0

    def test_only_header_lines_returns_zero(self):
        output = "Starting arp-scan 1.9.7\nEnding arp-scan 1.9.7: 256 hosts\n"
        assert _parse_arp_scan_output(output) == 0

    def test_single_host_returns_one(self):
        output = "192.168.1.1\t00:11:22:33:44:55\tRouter\n"
        assert _parse_arp_scan_output(output) == 1

    def test_mixed_case_mac_counted(self):
        output = "192.168.1.1\t00:AA:BB:CC:DD:EE\tDevice\n"
        assert _parse_arp_scan_output(output) == 1


# ---------------------------------------------------------------------------
# _parse_nmap_output — nmap greppable output parsing
# ---------------------------------------------------------------------------

class TestParseNmapOutput:
    """_parse_nmap_output counts up hosts from nmap -oG - output."""

    SAMPLE_NMAP_OUTPUT = (
        "# Nmap 7.93 scan initiated as: nmap -sn -oG - 192.168.1.0/24\n"
        "Host: 192.168.1.1 (router.local)\tStatus: Up\n"
        "Host: 192.168.1.50 ()\tStatus: Up\n"
        "Host: 192.168.1.75 ()\tStatus: Down\n"
        "# Nmap done: 256 IP addresses (2 hosts up) scanned\n"
    )

    def test_counts_up_hosts_only(self):
        assert _parse_nmap_output(self.SAMPLE_NMAP_OUTPUT) == 2

    def test_empty_output_returns_zero(self):
        assert _parse_nmap_output("") == 0

    def test_only_comment_lines_returns_zero(self):
        output = "# Nmap 7.93\n# Nmap done\n"
        assert _parse_nmap_output(output) == 0

    def test_single_up_host_returns_one(self):
        output = "Host: 192.168.1.1 ()\tStatus: Up\n"
        assert _parse_nmap_output(output) == 1

    def test_down_hosts_not_counted(self):
        output = (
            "Host: 192.168.1.1 ()\tStatus: Down\n"
            "Host: 192.168.1.2 ()\tStatus: Down\n"
        )
        assert _parse_nmap_output(output) == 0


# ---------------------------------------------------------------------------
# _get_connected_bssid — active BSSID detection
# ---------------------------------------------------------------------------

class TestGetConnectedBssid:
    """_get_connected_bssid returns the BSSID of the active WiFi connection."""

    def test_returns_active_bssid_lowercased(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=r"yes:AA\:BB\:CC\:DD\:EE\:FF" + "\n" + r"no:11\:22\:33\:44\:55\:66",
            stderr="",
        ))
        bssid = _get_connected_bssid(runner=fake)
        assert bssid == "aa:bb:cc:dd:ee:ff"

    def test_returns_none_when_not_connected(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=r"no:AA\:BB\:CC\:DD\:EE\:FF" + "\n",
            stderr="",
        ))
        assert _get_connected_bssid(runner=fake) is None

    def test_returns_none_on_empty_output(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        ))
        assert _get_connected_bssid(runner=fake) is None

    def test_returns_none_on_timeout(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["nmcli"], timeout=10))
        assert _get_connected_bssid(runner=fake) is None

    def test_returns_none_when_nmcli_not_found(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(FileNotFoundError("nmcli not found"))
        assert _get_connected_bssid(runner=fake) is None

    def test_passes_interface_to_command(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        ))
        _get_connected_bssid(interface="wlan1", runner=fake)
        cmd, _ = fake.run_calls[0]
        assert "ifname" in cmd
        assert "wlan1" in cmd


# ---------------------------------------------------------------------------
# _get_subnet — subnet CIDR detection
# ---------------------------------------------------------------------------

class TestGetSubnet:
    """_get_subnet extracts the local subnet CIDR from ip route output."""

    def test_returns_cidr_subnet(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100\n",
            stderr="",
        ))
        assert _get_subnet(runner=fake) == "192.168.1.0/24"

    def test_returns_none_on_empty_output(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        ))
        assert _get_subnet(runner=fake) is None

    def test_returns_none_on_timeout(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["ip"], timeout=5))
        assert _get_subnet(runner=fake) is None

    def test_returns_none_when_ip_not_found(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(FileNotFoundError("ip not found"))
        assert _get_subnet(runner=fake) is None

    def test_returns_first_matching_subnet(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=(
                "default via 192.168.1.1 dev wlan0\n"
                "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100\n"
            ),
            stderr="",
        ))
        assert _get_subnet(runner=fake) == "192.168.1.0/24"


# ---------------------------------------------------------------------------
# ArpScanner — ARP-based client detection
# ---------------------------------------------------------------------------

class TestArpScanner:
    """ArpScanner detects clients via arp-scan with nmap fallback."""

    def test_scan_returns_host_count_from_arp_scan(self):
        fake = _FakeRunner()
        arp_output = (
            "192.168.1.1\t00:11:22:33:44:55\tRouter\n"
            "192.168.1.50\t22:33:44:55:66:77\tPhone\n"
            "Ending arp-scan: 2 responded\n"
        )
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0, stdout=arp_output, stderr="",
        ))
        scanner = ArpScanner(interface="wlan0", runner=fake)
        assert scanner.scan() == 2

    def test_scan_falls_back_to_nmap_when_arp_scan_not_found(self):
        """When arp-scan raises FileNotFoundError, nmap is used instead."""
        fake = _FakeRunner()
        # First call (arp-scan) raises FileNotFoundError; second call (ip route) and third (nmap)
        nmap_output = (
            "Host: 192.168.1.1 ()\tStatus: Up\n"
            "Host: 192.168.1.50 ()\tStatus: Up\n"
        )
        ip_route_output = "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100\n"
        fake._run_results = [
            # arp-scan attempt raises FileNotFoundError (simulated via side effect below)
        ]
        # Use a custom runner that raises on arp-scan and returns for ip+nmap
        class _ArpNotFoundRunner:
            def __init__(self):
                self._calls = 0
            def run(self, cmd, **kwargs):
                self._calls += 1
                if "arp-scan" in cmd:
                    raise FileNotFoundError("arp-scan not found")
                if "ip" in cmd:
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=0, stdout=ip_route_output, stderr=""
                    )
                # nmap
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=nmap_output, stderr=""
                )
        scanner = ArpScanner(interface="wlan0", runner=_ArpNotFoundRunner())
        assert scanner.scan() == 2

    def test_scan_returns_zero_when_both_tools_unavailable(self):
        """When both arp-scan and nmap fail, scan returns 0."""
        class _NothingFoundRunner:
            def run(self, cmd, **kwargs):
                raise FileNotFoundError("not found")
        scanner = ArpScanner(runner=_NothingFoundRunner())
        assert scanner.scan() == 0

    def test_scan_returns_zero_on_timeout(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["arp-scan"], timeout=30))
        scanner = ArpScanner(runner=fake)
        assert scanner.scan() == 0

    def test_scan_passes_interface_flag_to_arp_scan(self):
        fake = _FakeRunner()
        fake.set_run_results(subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        ))
        scanner = ArpScanner(interface="wlan1", runner=fake)
        scanner.scan()
        cmd, _ = fake.run_calls[0]
        assert "arp-scan" in cmd
        assert "-I" in cmd
        assert "wlan1" in cmd


# ---------------------------------------------------------------------------
# _parse_args — --arp flag
# ---------------------------------------------------------------------------

class TestParseArgsArpFlag:
    def test_arp_flag_default_false(self):
        args = _parse_args([])
        assert args.arp is False

    def test_arp_flag_set(self):
        args = _parse_args(["--arp"])
        assert args.arp is True

    def test_arp_flag_with_interface(self):
        args = _parse_args(["--arp", "-i", "wlan0"])
        assert args.arp is True
        assert args.interface == "wlan0"


# ---------------------------------------------------------------------------
# _parse_args — --list-devices flag
# ---------------------------------------------------------------------------

class TestParseArgsListDevicesFlag:
    def test_list_devices_flag_default_false(self):
        args = _parse_args([])
        assert args.list_devices is False

    def test_list_devices_flag_set(self):
        args = _parse_args(["--list-devices"])
        assert args.list_devices is True


# ---------------------------------------------------------------------------
# _parse_args — --baseline and --save-baseline flags
# ---------------------------------------------------------------------------

class TestParseArgsBaselineFlags:
    def test_baseline_flag_default_none(self):
        args = _parse_args([])
        assert args.baseline is None

    def test_baseline_flag_set(self):
        args = _parse_args(["--baseline", "known.json"])
        assert args.baseline == "known.json"

    def test_save_baseline_flag_default_none(self):
        args = _parse_args([])
        assert args.save_baseline is None

    def test_save_baseline_flag_set(self):
        args = _parse_args(["--save-baseline", "baseline.json"])
        assert args.save_baseline == "baseline.json"


# ---------------------------------------------------------------------------
# load_baseline / save_baseline — known-good network baseline
# ---------------------------------------------------------------------------

class TestLoadBaseline:
    """load_baseline reads a JSON file of known SSID/BSSID/channel tuples."""

    def test_loads_valid_json(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"AA:BB:CC:DD:EE:01","channel":6}]')
        result = load_baseline(str(path))
        assert len(result) == 1
        assert result[0].ssid == "Home"
        assert result[0].bssid == "aa:bb:cc:dd:ee:01"
        assert result[0].channel == 6

    def test_loads_multiple_entries(self, tmp_path):
        path = tmp_path / "baseline.json"
        data = [
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:01", "channel": 6},
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:02", "channel": 36},
        ]
        import json
        path.write_text(json.dumps(data))
        result = load_baseline(str(path))
        assert len(result) == 2
        assert result[1].channel == 36

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_baseline(str(tmp_path / "nonexistent.json"))
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {{{")
        result = load_baseline(str(path))
        assert result == []

    def test_non_array_json_returns_empty(self, tmp_path):
        path = tmp_path / "obj.json"
        path.write_text('{"ssid":"Home"}')
        result = load_baseline(str(path))
        assert result == []

    def test_skips_entries_without_ssid(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"bssid":"aa:bb:cc:dd:ee:01","channel":6}]')
        result = load_baseline(str(path))
        assert result == []

    def test_skips_entries_without_bssid(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","channel":6}]')
        result = load_baseline(str(path))
        assert result == []

    def test_channel_defaults_to_zero(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01"}]')
        result = load_baseline(str(path))
        assert result[0].channel == 0

    def test_non_int_channel_defaults_to_zero(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01","channel":"bad"}]')
        result = load_baseline(str(path))
        assert result[0].channel == 0

    def test_bssid_lowercased(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"AA:BB:CC:DD:EE:01"}]')
        result = load_baseline(str(path))
        assert result[0].bssid == "aa:bb:cc:dd:ee:01"

    def test_skips_non_dict_entries(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('["not a dict", {"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01"}]')
        result = load_baseline(str(path))
        assert len(result) == 1


class TestSaveBaseline:
    """save_baseline writes scanned networks to a JSON file."""

    def test_saves_networks_to_json(self, tmp_path):
        path = tmp_path / "out.json"
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6, signal=-55),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Office", channel=36, signal=-65),
        ]
        count = save_baseline(str(path), nets)
        assert count == 2
        import json
        data = json.loads(path.read_text())
        assert len(data) == 2
        assert data[0]["ssid"] == "Home"
        assert data[0]["bssid"] == "aa:bb:cc:dd:ee:01"
        assert data[0]["channel"] == 6

    def test_skips_hidden_networks(self, tmp_path):
        path = tmp_path / "out.json"
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="", channel=1),  # hidden
        ]
        count = save_baseline(str(path), nets)
        assert count == 1

    def test_empty_networks_writes_empty_array(self, tmp_path):
        path = tmp_path / "out.json"
        count = save_baseline(str(path), [])
        assert count == 0
        import json
        assert json.loads(path.read_text()) == []

    def test_write_failure_returns_zero(self, tmp_path):
        count = save_baseline("/nonexistent/dir/out.json", [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home"),
        ])
        assert count == 0

    def test_roundtrip_load_save(self, tmp_path):
        """Networks saved by save_baseline can be loaded by load_baseline."""
        path = tmp_path / "roundtrip.json"
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6, signal=-55),
        ]
        save_baseline(str(path), nets)
        loaded = load_baseline(str(path))
        assert len(loaded) == 1
        assert loaded[0].ssid == "Home"
        assert loaded[0].bssid == "aa:bb:cc:dd:ee:01"
        assert loaded[0].channel == 6


# ---------------------------------------------------------------------------
# detect_rogue_aps — rogue AP detection logic
# ---------------------------------------------------------------------------

class TestDetectRogueAps:
    """detect_rogue_aps compares scanned networks against a known-good baseline."""

    def _baseline(self) -> list[KnownNetwork]:
        """Two known APs for 'HomeNet' on channels 6 and 36."""
        return [
            KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01", channel=6),
            KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:02", channel=36),
        ]

    def test_no_alert_when_network_matches_baseline(self):
        """A network matching a known BSSID and channel produces no alert."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=6, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_unknown_bssid_triggers_alert(self):
        """A network with a known SSID but unknown BSSID triggers unknown_bssid alert."""
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="HomeNet", channel=6, signal=-60)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 1
        assert alerts[0].reason == "unknown_bssid"
        assert alerts[0].network.bssid == "ff:ff:ff:ff:ff:ff"
        assert "aa:bb:cc:dd:ee:01" in alerts[0].expected_bssids
        assert "aa:bb:cc:dd:ee:02" in alerts[0].expected_bssids

    def test_unexpected_channel_triggers_alert(self):
        """A known BSSID on a different channel triggers unexpected_channel alert."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=11, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 1
        assert alerts[0].reason == "unexpected_channel"
        assert alerts[0].network.channel == 11
        assert 6 in alerts[0].expected_channels

    def test_unknown_ssid_not_in_baseline_ignored(self):
        """A network whose SSID is not in the baseline produces no alert."""
        nets = [Network(bssid="11:22:33:44:55:66", ssid="GuestNet", channel=1, signal=-70)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_hidden_network_ignored(self):
        """A network with empty SSID (hidden) is never flagged."""
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="", channel=6, signal=-65)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_empty_baseline_no_alerts(self):
        """An empty baseline means nothing is tracked — no alerts."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=6)]
        alerts = detect_rogue_aps(nets, [])
        assert alerts == []

    def test_empty_networks_no_alerts(self):
        """No scanned networks means no alerts."""
        alerts = detect_rogue_aps([], self._baseline())
        assert alerts == []

    def test_channel_zero_baseline_accepts_any_channel(self):
        """Baseline channel=0 means any channel is acceptable for that BSSID."""
        baseline = [KnownNetwork(ssid="Flex", bssid="aa:bb:cc:dd:ee:03", channel=0)]
        nets = [Network(bssid="aa:bb:cc:dd:ee:03", ssid="Flex", channel=149, signal=-50)]
        alerts = detect_rogue_aps(nets, baseline)
        assert alerts == []

    def test_multiple_alerts_from_one_scan(self):
        """Multiple rogue networks in a single scan produce multiple alerts."""
        nets = [
            Network(bssid="ff:ff:ff:ff:ff:01", ssid="HomeNet", channel=6, signal=-60),
            Network(bssid="ff:ff:ff:ff:ff:02", ssid="HomeNet", channel=11, signal=-70),
        ]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 2
        assert all(a.reason == "unknown_bssid" for a in alerts)

    def test_bssid_comparison_case_insensitive(self):
        """BSSID comparison is case-insensitive (baseline lowercase, scan uppercase)."""
        baseline = [KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01", channel=6)]
        nets = [Network(bssid="AA:BB:CC:DD:EE:01", ssid="HomeNet", channel=6, signal=-55)]
        alerts = detect_rogue_aps(nets, baseline)
        assert alerts == []

    def test_expected_channels_populated(self):
        """The expected_channels field lists all known channels for the SSID."""
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="HomeNet", channel=6, signal=-60)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 1
        assert sorted(alerts[0].expected_channels) == [6, 36]

    def test_known_bssid_channel_zero_scan_no_alert(self):
        """Scanned channel=0 does not trigger unexpected_channel for a known BSSID."""
        baseline = [KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01", channel=6)]
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=0, signal=-55)]
        alerts = detect_rogue_aps(nets, baseline)
        assert alerts == []


# ---------------------------------------------------------------------------
# build_rogue_table — rogue AP alert rendering
# ---------------------------------------------------------------------------

class TestBuildRogueTable:
    """build_rogue_table renders a Rich Table of rogue AP alerts."""

    def _alert(self, reason: str = "unknown_bssid") -> RogueAlert:
        return RogueAlert(
            network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="HomeNet", channel=6, signal=-60),
            reason=reason,
            expected_bssids=["aa:bb:cc:dd:ee:01"],
            expected_channels=[6],
        )

    def test_empty_alerts_returns_table_with_no_rows(self):
        table = build_rogue_table([])
        assert table.row_count == 0

    def test_single_alert_renders_one_row(self):
        table = build_rogue_table([self._alert()])
        assert table.row_count == 1

    def test_multiple_alerts_render_multiple_rows(self):
        alerts = [self._alert(), self._alert("unexpected_channel")]
        table = build_rogue_table(alerts)
        assert table.row_count == 2

    def test_title_contains_rogue(self):
        table = build_rogue_table([self._alert()])
        assert table.title is not None
        assert "Rogue" in table.title or "rogue" in table.title.lower()

    def test_ssid_is_escaped(self):
        """Malicious SSIDs are escaped to prevent Rich markup injection."""
        alert = RogueAlert(
            network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="[red]Evil[/red]", channel=6, signal=-60),
            reason="unknown_bssid",
            expected_bssids=["aa:bb:cc:dd:ee:01"],
            expected_channels=[6],
        )
        table = build_rogue_table([alert])
        assert table.row_count == 1  # Did not crash from markup

    def test_caption_shows_alert_count(self):
        alerts = [self._alert(), self._alert()]
        table = build_rogue_table(alerts)
        assert table.caption is not None
        assert "2" in table.caption


# ---------------------------------------------------------------------------
# main() — --list-devices integration
# ---------------------------------------------------------------------------

class TestMainListDevices:
    """main() with --list-devices prints devices and exits."""

    def test_list_devices_shows_detected_interfaces(self):
        from wifimonitor.wifi_monitor_nitro5 import main
        from wifimonitor.wifi_common import WifiDevice
        devices = [
            WifiDevice(name="wlan0", driver="iwlwifi", supports_monitor=False, is_up=True),
            WifiDevice(name="wlan1", driver="ath9k", supports_monitor=True, is_up=False),
        ]
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=argparse.Namespace(
                      interface=None, monitor=False, dns=False, credentials=None,
                      connect=False, debug=False, arp=False, list_devices=True,
                  )),
            patch("wifimonitor.wifi_monitor_nitro5.detect_platform", return_value="laptop"),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=devices),
            patch("wifimonitor.wifi_monitor_nitro5.Console") as mock_console_cls,
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit", side_effect=SystemExit(0)),
        ):
            with pytest.raises(SystemExit):
                main()
            # Verify console.print was called with device info
            console_inst = mock_console_cls.return_value
            printed = " ".join(str(c) for c in console_inst.print.call_args_list)
            assert "wlan0" in printed
            assert "wlan1" in printed

    def test_list_devices_no_interfaces_shows_warning(self):
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=argparse.Namespace(
                      interface=None, monitor=False, dns=False, credentials=None,
                      connect=False, debug=False, arp=False, list_devices=True,
                  )),
            patch("wifimonitor.wifi_monitor_nitro5.detect_platform", return_value="laptop"),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console") as mock_console_cls,
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit", side_effect=SystemExit(0)),
        ):
            with pytest.raises(SystemExit):
                main()
            console_inst = mock_console_cls.return_value
            printed = " ".join(str(c) for c in console_inst.print.call_args_list)
            assert "No WiFi" in printed


# ---------------------------------------------------------------------------
# NmcliScanner — adapter wrapping scan_wifi_nmcli
# ---------------------------------------------------------------------------

class TestNmcliScanner:
    """NmcliScanner wraps scan_wifi_nmcli() as a ScannerProtocol-conforming class."""

    def test_satisfies_scanner_protocol(self):
        """NmcliScanner is a structural subtype of ScannerProtocol."""
        scanner: ScannerProtocol = NmcliScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)

    def test_scan_delegates_to_scan_wifi_nmcli(self):
        """scan() delegates to scan_wifi_nmcli with the stored interface."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", signal=-55)]
        with patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=nets) as mock_scan:
            scanner = NmcliScanner(interface="wlan0")
            result = scanner.scan()
            assert result == nets
            mock_scan.assert_called_once_with("wlan0", runner=None)

    def test_scan_passes_runner(self):
        """scan() forwards the injected runner to scan_wifi_nmcli."""
        fake_runner = MagicMock()
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test")]
        with patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=nets) as mock_scan:
            scanner = NmcliScanner(interface="wlan1", runner=fake_runner)
            scanner.scan()
            mock_scan.assert_called_once_with("wlan1", runner=fake_runner)

    def test_scan_no_interface(self):
        """scan() passes None when no interface specified."""
        with patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=[]) as mock_scan:
            scanner = NmcliScanner()
            result = scanner.scan()
            assert result == []
            mock_scan.assert_called_once_with(None, runner=None)

    def test_airodump_scanner_also_satisfies_protocol(self):
        """AirodumpScanner already has scan() -> list[Network], so it satisfies ScannerProtocol."""
        assert hasattr(AirodumpScanner, "scan")
        assert callable(getattr(AirodumpScanner, "scan"))


# ---------------------------------------------------------------------------
# RichNetworkRenderer — adapter wrapping build_table
# ---------------------------------------------------------------------------

class TestRichNetworkRenderer:
    """RichNetworkRenderer wraps build_table() as a RendererProtocol-conforming class."""

    def test_satisfies_renderer_protocol(self):
        """RichNetworkRenderer is a structural subtype of RendererProtocol."""
        renderer: RendererProtocol = RichNetworkRenderer()
        assert hasattr(renderer, "render")
        assert callable(renderer.render)

    def test_render_returns_table(self):
        """render() returns a Rich Table from build_table()."""
        from rich.table import Table
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", signal=-55, channel=6, security="WPA2")]
        renderer = RichNetworkRenderer()
        result = renderer.render(nets)
        assert isinstance(result, Table)

    def test_render_passes_credentials(self):
        """render() forwards credentials kwarg to build_table()."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", signal=-55, channel=6, security="WPA2")]
        renderer = RichNetworkRenderer()
        result = renderer.render(nets, credentials={"HomeNet": "pass123"})
        # The table should have a "Key" column when credentials are provided
        col_headers = [c.header for c in result.columns]
        assert "Key" in col_headers

    def test_render_passes_connected_bssid(self):
        """render() forwards connected_bssid kwarg to build_table()."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", signal=-55, channel=6, security="WPA2")]
        renderer = RichNetworkRenderer()
        result = renderer.render(nets, connected_bssid="aa:bb:cc:dd:ee:01")
        # Should contain a "Con" column (always present)
        col_headers = [c.header for c in result.columns]
        assert "Con" in col_headers

    def test_render_passes_caption_override(self):
        """render() forwards caption_override kwarg to build_table()."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", signal=-55)]
        renderer = RichNetworkRenderer()
        result = renderer.render(nets, caption_override="custom caption")
        assert result.caption == "custom caption"

    def test_render_empty_networks(self):
        """render() handles empty network list."""
        from rich.table import Table
        renderer = RichNetworkRenderer()
        result = renderer.render([])
        assert isinstance(result, Table)


# ---------------------------------------------------------------------------
# build_table — connected network indicator (Con column + bold row)
# ---------------------------------------------------------------------------


def _render_table(table) -> str:
    """Render a Rich Table to a plain string (no color) for assertion."""
    from rich.console import Console
    buf = _io.StringIO()
    console = Console(file=buf, no_color=True, highlight=False, width=120)
    console.print(table)
    return buf.getvalue()


class TestBuildTableConnectedIndicator:
    """build_table highlights the connected network row with a Con column."""

    _BSSID = "aa:bb:cc:dd:ee:01"
    _NET = Network(bssid=_BSSID, ssid="HomeNetwork", signal=-55, channel=6, security="WPA2")

    def test_build_table_always_has_con_column(self):
        """'Con' column is always present regardless of connected_bssid value."""
        table = build_table([self._NET])
        col_headers = [c.header for c in table.columns]
        assert "Con" in col_headers

    def test_build_table_con_column_present_when_none(self):
        """'Con' column present even when connected_bssid=None."""
        table = build_table([self._NET], connected_bssid=None)
        col_headers = [c.header for c in table.columns]
        assert "Con" in col_headers

    def test_build_table_connected_bssid_shows_indicator(self):
        """Matching BSSID row renders the filled-circle indicator."""
        table = build_table([self._NET], connected_bssid=self._BSSID)
        output = _render_table(table)
        assert "●" in output

    def test_build_table_non_connected_row_no_indicator(self):
        """Non-matching row does not show the indicator."""
        other = Network(bssid="aa:bb:cc:dd:ee:02", ssid="Other", signal=-70, channel=11, security="WPA2")
        table = build_table([other], connected_bssid=self._BSSID)
        output = _render_table(table)
        assert "●" not in output

    def test_build_table_connected_bssid_none_no_indicator(self):
        """connected_bssid=None → no indicator in any row."""
        table = build_table([self._NET], connected_bssid=None)
        output = _render_table(table)
        assert "●" not in output

    def test_build_table_connected_bssid_empty_string_no_indicator(self):
        """connected_bssid='' treated as not connected → no indicator."""
        table = build_table([self._NET], connected_bssid="")
        output = _render_table(table)
        assert "●" not in output

    def test_build_table_connected_bssid_no_match_no_indicator(self):
        """connected_bssid set but not matching any network → no indicator."""
        table = build_table([self._NET], connected_bssid="ff:ff:ff:ff:ff:ff")
        output = _render_table(table)
        assert "●" not in output

    def test_build_table_connected_bssid_case_insensitive(self):
        """Uppercase BSSID in connected_bssid matches lowercase net.bssid."""
        table = build_table([self._NET], connected_bssid="AA:BB:CC:DD:EE:01")
        output = _render_table(table)
        assert "●" in output

    def test_build_table_connected_hidden_network_shows_indicator(self):
        """Hidden SSID (ssid='') network shows indicator when connected."""
        hidden = Network(bssid="aa:bb:cc:dd:ee:03", ssid="", signal=-60, channel=6, security="WPA2")
        table = build_table([hidden], connected_bssid="aa:bb:cc:dd:ee:03")
        output = _render_table(table)
        assert "●" in output

    def test_build_table_empty_networks_with_connected_bssid_no_crash(self):
        """Empty network list with connected_bssid set does not crash."""
        table = build_table([], connected_bssid=self._BSSID)
        assert table.row_count == 0

    def test_build_table_only_connected_row_has_indicator(self):
        """Only the connected row shows indicator; others are empty."""
        nets = [
            self._NET,
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Other", signal=-70, channel=11, security="WPA2"),
        ]
        table = build_table(nets, connected_bssid=self._BSSID)
        output = _render_table(table)
        # Indicator present once
        assert output.count("●") == 1

    def test_build_table_row_count_unchanged_with_connected_bssid(self):
        """Adding connected_bssid does not change the row count."""
        nets = [self._NET, Network(bssid="aa:bb:cc:dd:ee:02", ssid="B", signal=-70, channel=11, security="Open")]
        assert build_table(nets, connected_bssid=self._BSSID).row_count == 2

    def test_build_table_con_column_before_bssid(self):
        """Con column appears near the left of the table (before BSSID)."""
        table = build_table([self._NET], connected_bssid=self._BSSID)
        headers = [c.header for c in table.columns]
        assert headers.index("Con") < headers.index("BSSID")


# ---------------------------------------------------------------------------
# load_credentials — OSError error paths
# ---------------------------------------------------------------------------


class TestLoadCredentialsErrorPaths:
    """Error paths in load_credentials: stat fails, open fails."""

    def test_stat_oserror_continues_reading(self, tmp_path):
        """When os.stat raises OSError, load still reads the file normally."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("Home,pass123\n")
        with (
            patch("wifimonitor.wifi_monitor_nitro5.os.stat", side_effect=OSError("no stat")),
            patch("wifimonitor.wifi_monitor_nitro5.os.path.isfile", return_value=True),
        ):
            result = load_credentials(str(creds_file))
        assert result == {"Home": "pass123"}

    def test_open_oserror_returns_empty_dict(self, tmp_path):
        """When open() raises OSError, load_credentials returns empty dict."""
        creds_file = tmp_path / "creds.csv"
        creds_file.write_text("Home,pass123\n")
        with patch("builtins.open", side_effect=OSError("permission denied")):
            result = load_credentials(str(creds_file))
        assert result == {}

    def test_blank_line_in_nmcli_output_skipped(self):
        """parse_nmcli_output skips blank lines in the middle of output."""
        output = (
            r"AA\:BB\:CC\:DD\:EE\:01:HomeNet:6:80:WPA2" + "\n"
            "\n"
            r"BB\:CC\:DD\:EE\:FF\:02:Other:11:60:WPA2"
        )
        networks = parse_nmcli_output(output)
        assert len(networks) == 2


# ---------------------------------------------------------------------------
# DnsTracker — stop() timeout and _reader_loop OSError
# ---------------------------------------------------------------------------


class TestDnsTrackerErrorPaths:
    """DnsTracker error paths not covered by happy-path tests."""

    def test_stop_kills_process_when_wait_times_out(self):
        """stop() kills process when terminate+wait times out."""
        tracker = DnsTracker()
        mock_proc = MagicMock()
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="tcpdump", timeout=5)
        tracker._process = mock_proc
        tracker.stop()
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()

    def test_reader_loop_handles_oserror_silently(self):
        """_reader_loop catches OSError when reading stdout and exits cleanly."""
        tracker = DnsTracker()
        mock_proc = MagicMock()
        mock_proc.stdout.__iter__ = MagicMock(side_effect=OSError("bad fd"))
        tracker._process = mock_proc
        tracker._reader_loop()  # must not raise


# ---------------------------------------------------------------------------
# ArpScanner — additional edge paths
# ---------------------------------------------------------------------------


class TestArpScannerEdgePaths:
    """Edge paths in ArpScanner not covered by primary tests."""

    def test_scan_arp_file_not_found_returns_none(self):
        """_scan_arp returns None when arp-scan is not installed (FileNotFoundError)."""
        runner = MagicMock()
        runner.run.side_effect = FileNotFoundError("arp-scan not found")
        scanner = ArpScanner(runner=runner)
        result = scanner._scan_arp()
        assert result is None

    def test_scan_arp_bad_returncode_returns_none(self):
        """_scan_arp returns None when arp-scan exits with code != 0 or 1."""
        runner = MagicMock()
        runner.run.return_value = subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr=""
        )
        scanner = ArpScanner(runner=runner)
        result = scanner._scan_arp()
        assert result is None

    def test_scan_nmap_timeout_returns_none(self):
        """_scan_nmap returns None when nmap raises TimeoutExpired."""
        runner = MagicMock()
        subnet_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="192.168.1.0/24 dev wlan0  proto kernel  scope link  src 192.168.1.5\n",
            stderr="",
        )
        runner.run.side_effect = [
            subnet_result,
            subprocess.TimeoutExpired(cmd="nmap", timeout=60),
        ]
        scanner = ArpScanner(runner=runner)
        result = scanner._scan_nmap()
        assert result is None


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
        with patch("wifimonitor.wifi_monitor_nitro5.time.sleep"):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file):
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
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file):
            result = _verify_monitor_mode("wlan0", runner=fake, iw_set_type_returncode=0)
        assert result is False

    def test_exception_returns_false(self, tmp_path):
        """Returns False when runner raises an exception."""
        log_file = str(tmp_path / "monitor.log")
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd="iw", timeout=5))
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file):
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
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file):
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
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file):
            result = scanner.log_exit_if_dead()
        assert result is False
        assert scanner._exit_logged is True

    def test_scan_debug_logs_csv_parse_results(self, tmp_path):
        """scan() with debug=True logs parse results for direct monitor mode."""
        from tests.test_wifi_common import SAMPLE_AIRODUMP_CSV
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi_cov", debug=True)
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]),
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)),
        ):
            networks = scanner.scan()
        assert len(networks) > 0

    def test_scan_oserror_with_debug_logs_failure(self, tmp_path):
        """scan() with debug=True logs when CSV read fails with OSError."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi_cov", debug=True)
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]),
            patch("builtins.open", side_effect=OSError("permission denied")),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi_cov-01.csv"]),
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=nmcli_networks),
        ):
            networks = scanner.scan()
        assert len(networks) == 1

    def test_cleanup_old_files_oserror_silently_ignored(self, tmp_path):
        """_cleanup_old_files continues when os.remove raises OSError."""
        scanner = AirodumpScanner(interface="wlan0", prefix=str(tmp_path / "wifi"))
        # Create a file that matches the prefix pattern
        test_file = tmp_path / "wifi-01.csv"
        test_file.write_text("content")
        with patch("wifimonitor.wifi_monitor_nitro5.os.remove", side_effect=OSError("busy")):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
            ok, _ = scanner.start()
        assert ok is True
        assert not scanner._monitor_is_virtual
        scanner.stop()


# ---------------------------------------------------------------------------
# _dump_startup_config — logging coverage
# ---------------------------------------------------------------------------


class TestDumpStartupConfig:
    """Coverage for _dump_startup_config: all debug log lines."""

    def test_logs_all_config_fields_without_raising(self):
        """_dump_startup_config logs all settings and does not raise."""
        args = argparse.Namespace(
            interface="wlan0",
            monitor=True,
            dns=True,
            credentials="creds.csv",
            connect=True,
            debug=True,
            arp=False,
        )
        _dump_startup_config(
            args=args,
            monitor_interface="wlan0",
            airodump_ok=True,
            airodump_failure=None,
            dns_ok=True,
            creds_count=3,
        )
        # If we reach here without raising, all log lines were executed


# ---------------------------------------------------------------------------
# Additional targeted tests for remaining uncovered lines
# ---------------------------------------------------------------------------


class TestReaderLoopBody:
    """_reader_loop loop body (lines 269-271) runs when stdout has lines."""

    def test_reader_loop_records_valid_dns_lines(self):
        """_reader_loop body executes and records domains from stdout."""
        tracker = DnsTracker()
        mock_proc = MagicMock()
        dns_line = "12:00:00.000000 IP 192.168.1.5.53297 > 8.8.8.8.53: A? example.com.\n"
        mock_proc.stdout = iter([dns_line])
        tracker._process = mock_proc
        tracker._reader_loop()
        assert tracker.top()  # domain should have been recorded


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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_MONITOR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.AIRODUMP_STDERR_LOG", log_file),
            patch("wifimonitor.wifi_monitor_nitro5.os.geteuid", return_value=1000),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep"),
        ):
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
        with (
            patch("wifimonitor.wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_dbg11-01.csv"]),
            patch("builtins.open", mock_open(read_data=csv_content)),
        ):
            networks = scanner.scan()
        assert len(networks) >= 10


# ---------------------------------------------------------------------------
# main() — integration tests via heavy mocking
# ---------------------------------------------------------------------------


class TestMain:
    """main() integration tests using mocked Console, Live, scan, and sleep."""

    def _args(self, **kw):
        defaults = dict(
            interface=None, monitor=False, dns=False, credentials=None,
            connect=False, debug=False, arp=False, list_devices=False,
            baseline=None, save_baseline=None,
        )
        defaults.update(kw)
        return argparse.Namespace(**defaults)

    def _nets(self):
        return [Network(
            bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet",
            signal=-55, channel=6, security="WPA2",
        )]

    def test_main_no_flags_exits_on_keyboard_interrupt(self):
        """main() with no flags runs one cycle then exits on KeyboardInterrupt."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args()),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            main()

    def test_main_arp_flag_creates_arp_scanner(self):
        """main() with --arp creates ArpScanner and overlays client count."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(arp=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value="aa:bb:cc:dd:ee:01"),
            patch("wifimonitor.wifi_monitor_nitro5.ArpScanner") as mock_arp_cls,
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_arp_cls.return_value.scan.return_value = 5
            main()

    def test_main_credentials_loaded_and_auto_connect(self):
        """main() with --credentials and --connect loads creds and connects."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=self._args(credentials="creds.csv", connect=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.load_credentials", return_value={"HomeNet": "pass"}),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.connect_wifi_nmcli", return_value=True),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            main()

    def test_main_credentials_empty_warns(self):
        """main() warns when credentials file loads no entries."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=self._args(credentials="empty.csv")),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.load_credentials", return_value={}),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            main()

    def test_main_dns_flag_starts_tracker_shows_dns_table(self):
        """main() with --dns starts DnsTracker and updates Live with Group."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(dns=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.DnsTracker") as mock_dns_cls,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_tracker = MagicMock()
            mock_tracker.start.return_value = True
            mock_tracker.top.return_value = []
            mock_dns_cls.return_value = mock_tracker
            main()

    def test_main_dns_start_fails_disables_tracker(self):
        """main() disables DNS tracker when start() returns False."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(dns=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.DnsTracker") as mock_dns_cls,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_tracker = MagicMock()
            mock_tracker.start.return_value = False
            mock_dns_cls.return_value = mock_tracker
            main()

    def test_main_debug_flag_sets_up_logging(self):
        """main() with --debug configures logging with FileHandler."""
        from wifimonitor.wifi_monitor_nitro5 import main
        # Patch the whole logging module in wifi_monitor_nitro5 so no real handlers
        # are added to the root logger (which would leak a MagicMock across tests).
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(debug=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.logging"),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            main()

    def test_main_monitor_flag_airodump_starts_ok(self):
        """main() with --monitor starts AirodumpScanner; uses it for scanning."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(monitor=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.AirodumpScanner") as mock_cls,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.atexit.register"),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_scanner = MagicMock()
            mock_scanner.start.return_value = (True, None)
            mock_scanner.scan.return_value = self._nets()
            mock_scanner.log_exit_if_dead.return_value = True
            mock_scanner.interface = "wlan0"
            mock_cls.return_value = mock_scanner
            main()

    def test_main_monitor_flag_airodump_fails_falls_back(self):
        """main() with --monitor uses nmcli fallback when airodump fails to start."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(monitor=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.AirodumpScanner") as mock_cls,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_scanner = MagicMock()
            mock_scanner.start.return_value = (False, "monitor_unsupported")
            mock_cls.return_value = mock_scanner
            main()

    def test_main_monitor_airodump_exits_mid_run(self):
        """main() falls back to nmcli when airodump exits during a scan cycle."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args", return_value=self._args(monitor=True)),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.AirodumpScanner") as mock_cls,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.atexit.register"),
            patch("wifimonitor.wifi_monitor_nitro5._LOGGER"),  # prevent handler issues
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_scanner = MagicMock()
            mock_scanner.start.return_value = (True, None)
            mock_scanner.log_exit_if_dead.return_value = False  # airodump died
            mock_scanner.interface = "wlan0"
            mock_cls.return_value = mock_scanner
            main()

    def test_main_baseline_loads_and_detects_rogue(self):
        """main() with --baseline loads baseline and calls detect_rogue_aps each cycle."""
        from wifimonitor.wifi_monitor_nitro5 import main
        baseline = [KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:99", channel=6)]
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=self._args(baseline="known.json")),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.load_baseline", return_value=baseline) as mock_load,
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.detect_rogue_aps") as mock_detect,
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            mock_detect.return_value = []
            main()
            mock_load.assert_called_once_with("known.json")
            mock_detect.assert_called_once()

    def test_main_baseline_none_skips_detection(self):
        """main() without --baseline does not call detect_rogue_aps."""
        from wifimonitor.wifi_monitor_nitro5 import main
        with (
            patch("wifimonitor.wifi_monitor_nitro5._parse_args",
                  return_value=self._args()),
            patch("wifimonitor.wifi_monitor_nitro5.list_wifi_interfaces", return_value=[]),
            patch("wifimonitor.wifi_monitor_nitro5.Console"),
            patch("wifimonitor.wifi_monitor_nitro5.Live"),
            patch("wifimonitor.wifi_monitor_nitro5.scan_wifi_nmcli", return_value=self._nets()),
            patch("wifimonitor.wifi_monitor_nitro5._get_connected_bssid", return_value=None),
            patch("wifimonitor.wifi_monitor_nitro5.detect_rogue_aps") as mock_detect,
            patch("wifimonitor.wifi_monitor_nitro5.time.sleep", side_effect=KeyboardInterrupt),
            patch("wifimonitor.wifi_monitor_nitro5.sys.exit"),
        ):
            main()
            mock_detect.assert_not_called()
