"""Tests for wifi_monitor_nitro5 nmcli scanning.

Follows TDD agent standards:
- test_<what>_<condition>_<expected_outcome> naming
- One concept per test
- @pytest.mark.parametrize for repetitive cases
- pytest.fixture for shared setup
- Unhappy-path coverage (malformed input, edge cases)
"""

import pytest

from wifi_monitor_nitro5 import (
    parse_nmcli_output,
    _split_nmcli_line,
    _pct_to_dbm,
    _map_nmcli_security,
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
