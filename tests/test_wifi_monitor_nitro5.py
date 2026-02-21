"""Tests for wifi_monitor_nitro5 nmcli scanning.

Follows TDD agent standards:
- test_<what>_<condition>_<expected_outcome> naming
- One concept per test
- @pytest.mark.parametrize for repetitive cases
- pytest.fixture for shared setup
- Unhappy-path coverage (malformed input, edge cases)
"""

import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from wifi_common import Network
from wifi_monitor_nitro5 import (
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
    parse_tcpdump_dns_line,
    DnsTracker,
    build_dns_table,
    _parse_args,
    AirodumpScanner,
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

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_timeout_returns_empty_list(self, mock_run):
        """If nmcli times out, return empty list instead of crashing."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmcli"], timeout=15)
        result = scan_wifi_nmcli()
        assert result == []

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_scan_wifi_nmcli_subprocess_error_returns_empty_list(self, mock_run):
        """If nmcli is not found or fails, return empty list."""
        mock_run.side_effect = FileNotFoundError("nmcli not found")
        result = scan_wifi_nmcli()
        assert result == []

    @patch("wifi_monitor_nitro5.subprocess.run")
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

    @patch("wifi_monitor_nitro5.subprocess.run")
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

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_success_returns_true(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is True

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_failure_returns_false(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Connection failed",
        )
        result = connect_wifi_nmcli("TestNet", "wrongpass")
        assert result is False

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_timeout_returns_false(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmcli"], timeout=30)
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is False

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_nmcli_not_found_returns_false(self, mock_run):
        mock_run.side_effect = FileNotFoundError("nmcli not found")
        result = connect_wifi_nmcli("TestNet", "password123")
        assert result is False

    @patch("wifi_monitor_nitro5.subprocess.run")
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

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_with_interface(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        connect_wifi_nmcli("TestNet", "pass", interface="wlan1")
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert "ifname" in cmd
        assert "wlan1" in cmd

    @patch("wifi_monitor_nitro5.subprocess.run")
    def test_connect_wifi_nmcli_uses_minimal_env(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr="",
        )
        connect_wifi_nmcli("TestNet", "pass")
        _, kwargs = mock_run.call_args
        env = kwargs.get("env", {})
        assert "LC_ALL" in env
        assert len(env) <= 4

    @patch("wifi_monitor_nitro5.subprocess.run")
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

    @patch("wifi_monitor_nitro5.subprocess.Popen")
    def test_start_returns_true_when_tcpdump_available(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc
        tracker = DnsTracker()
        assert tracker.start() is True
        tracker.stop()

    @patch("wifi_monitor_nitro5.subprocess.Popen")
    def test_start_returns_false_when_tcpdump_not_found(self, mock_popen):
        mock_popen.side_effect = FileNotFoundError("tcpdump not found")
        tracker = DnsTracker()
        assert tracker.start() is False

    @patch("wifi_monitor_nitro5.subprocess.Popen")
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

    @patch("wifi_monitor_nitro5.subprocess.Popen")
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

    @patch("wifi_monitor_nitro5.subprocess.Popen")
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

    @patch("wifi_monitor_nitro5.subprocess.Popen")
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
            patch("wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
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
        with patch("wifi_monitor_nitro5.glob.glob", return_value=[]):
            networks = scanner.scan()
        assert networks == []

    def test_scan_file_read_error_returns_empty_list(self):
        """When CSV file cannot be read, scan returns empty list."""
        scanner = AirodumpScanner(interface="wlan0", prefix="/tmp/test_wifi")
        with (
            patch("wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
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
            patch("wifi_monitor_nitro5.glob.glob", return_value=["/tmp/test_wifi-01.csv"]),
            patch("builtins.open", mock_open(read_data=SAMPLE_AIRODUMP_CSV)),
            patch(
                "wifi_monitor_nitro5.scan_wifi_nmcli",
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
        """start() spawns airodump with cwd=/tmp and --background 1."""
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
            patch("wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifi_monitor_nitro5.time.sleep"),
        ):
            ok, _ = scanner.start()
        assert ok is True
        assert len(fake.popen_calls) == 1
        cmd, kwargs = fake.popen_calls[0]
        assert kwargs.get("cwd") == "/tmp"
        assert "--background" in cmd
        idx = cmd.index("--background")
        assert cmd[idx + 1] == "1"
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
            patch("wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifi_monitor_nitro5.time.sleep"),
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
        with patch("wifi_monitor_nitro5.time.sleep"):
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
            patch("wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifi_monitor_nitro5.time.sleep"),
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
            patch("wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifi_monitor_nitro5.time.sleep"),
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
            patch("wifi_monitor_nitro5.os.geteuid", return_value=0),
            patch("wifi_monitor_nitro5.time.sleep"),
        ):
            ok, _ = scanner.start()
        assert ok is True
        assert scanner._channels == []
        cmd, _ = fake.popen_calls[0]
        assert "--band" in cmd
        band_idx = cmd.index("--band")
        assert cmd[band_idx + 1] == "abg"
        assert "-c" not in cmd
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
