"""Tests for wifi_monitor_nitro5 nmcli scanning."""

import pytest

from wifi_monitor_nitro5 import parse_nmcli_output


# ---------------------------------------------------------------------------
# nmcli terse output parsing
# ---------------------------------------------------------------------------

# nmcli -t -f BSSID,SSID,CHAN,SIGNAL,SECURITY device wifi list
# Fields are colon-separated; colons in values are escaped as \:

SAMPLE_NMCLI_OUTPUT = r"""AA\:BB\:CC\:DD\:EE\:01:HomeNetwork:6:85:WPA2
AA\:BB\:CC\:DD\:EE\:02:CoffeeShop:11:42:
AA\:BB\:CC\:DD\:EE\:03:My\:Weird\:SSID:1:70:WPA1 WPA2
AA\:BB\:CC\:DD\:EE\:04::36:30:WPA2
AA\:BB\:CC\:DD\:EE\:05:Office 5G:149:65:WPA3"""


class TestParseNmcliOutput:
    def test_parses_all_networks(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        assert len(networks) == 5

    def test_bssid_unescaped(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        assert home.bssid == "aa:bb:cc:dd:ee:01"

    def test_ssid_with_escaped_colons(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        weird = [n for n in networks if "Weird" in n.ssid][0]
        assert weird.ssid == "My:Weird:SSID"

    def test_signal_percentage_to_dbm(self):
        """nmcli reports signal as 0-100%, we convert via (pct//2)-100."""
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        # 85% -> (85 // 2) - 100 = -58 dBm
        assert home.signal == -58

    def test_channel(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        assert home.channel == 6

    def test_security_wpa2(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        assert home.security == "WPA2"

    def test_security_open(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        assert coffee.security == "Open"

    def test_security_wpa3(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        office = [n for n in networks if n.ssid == "Office 5G"][0]
        assert office.security == "WPA3"

    def test_security_mixed_wpa(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        weird = [n for n in networks if "Weird" in n.ssid][0]
        assert weird.security == "WPA2"

    def test_hidden_ssid(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        hidden = [n for n in networks if n.ssid == ""][0]
        assert hidden.channel == 36
        assert hidden.security == "WPA2"

    def test_sorted_by_signal(self):
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        signals = [n.signal for n in networks]
        assert signals == sorted(signals, reverse=True)

    def test_empty_input(self):
        assert parse_nmcli_output("") == []

    def test_blank_lines_skipped(self):
        networks = parse_nmcli_output("\n\n" + SAMPLE_NMCLI_OUTPUT + "\n\n")
        assert len(networks) == 5

    def test_clients_default_zero(self):
        """nmcli can't detect clients; all should be 0."""
        networks = parse_nmcli_output(SAMPLE_NMCLI_OUTPUT)
        for net in networks:
            assert net.clients == 0
