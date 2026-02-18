"""Tests for wifi_common shared functions."""

import pytest

from wifi_common import (
    Network,
    signal_to_bars,
    signal_color,
    security_color,
    map_airodump_privacy,
    parse_airodump_csv,
)

# -- Colors used in wifi_common --
GREEN = (0, 255, 0)
YELLOW = (255, 255, 0)
RED = (255, 0, 0)
ORANGE = (255, 165, 0)


# ---------------------------------------------------------------------------
# Network dataclass
# ---------------------------------------------------------------------------

class TestNetwork:
    def test_defaults(self):
        net = Network(bssid="aa:bb:cc:dd:ee:ff", ssid="Test")
        assert net.bssid == "aa:bb:cc:dd:ee:ff"
        assert net.ssid == "Test"
        assert net.signal == -100
        assert net.channel == 0
        assert net.security == "Open"
        assert net.clients == 0

    def test_custom_values(self):
        net = Network(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="MyNet",
            signal=-55,
            channel=6,
            security="WPA2",
            clients=3,
        )
        assert net.signal == -55
        assert net.channel == 6
        assert net.security == "WPA2"
        assert net.clients == 3


# ---------------------------------------------------------------------------
# Signal helpers
# ---------------------------------------------------------------------------

class TestSignalToBars:
    def test_excellent_signal(self):
        assert signal_to_bars(-40) == 4
        assert signal_to_bars(-50) == 4

    def test_good_signal(self):
        assert signal_to_bars(-55) == 3
        assert signal_to_bars(-60) == 3

    def test_fair_signal(self):
        assert signal_to_bars(-65) == 2
        assert signal_to_bars(-70) == 2

    def test_weak_signal(self):
        assert signal_to_bars(-75) == 1
        assert signal_to_bars(-80) == 1

    def test_very_weak_signal(self):
        assert signal_to_bars(-85) == 0
        assert signal_to_bars(-100) == 0

    def test_boundary_values(self):
        assert signal_to_bars(-50) == 4
        assert signal_to_bars(-51) == 3
        assert signal_to_bars(-60) == 3
        assert signal_to_bars(-61) == 2


class TestSignalColor:
    def test_strong_signal_green(self):
        assert signal_color(-40) == GREEN
        assert signal_color(-50) == GREEN

    def test_medium_signal_yellow(self):
        assert signal_color(-55) == YELLOW
        assert signal_color(-65) == YELLOW

    def test_weak_signal_red(self):
        assert signal_color(-70) == RED
        assert signal_color(-100) == RED

    def test_boundary(self):
        assert signal_color(-50) == GREEN
        assert signal_color(-51) == YELLOW
        assert signal_color(-65) == YELLOW
        assert signal_color(-66) == RED


class TestSecurityColor:
    def test_open_is_red(self):
        assert security_color("Open") == RED

    def test_wep_is_yellow(self):
        assert security_color("WEP") == YELLOW

    def test_wpa_variants_are_green(self):
        assert security_color("WPA") == GREEN
        assert security_color("WPA2") == GREEN
        assert security_color("WPA3") == GREEN


# ---------------------------------------------------------------------------
# Airodump privacy mapping
# ---------------------------------------------------------------------------

class TestMapAirodumpPrivacy:
    def test_wpa2_ccmp(self):
        assert map_airodump_privacy("WPA2 CCMP PSK") == "WPA2"

    def test_wpa2_alone(self):
        assert map_airodump_privacy("WPA2") == "WPA2"

    def test_wpa3_sae(self):
        assert map_airodump_privacy("WPA3 SAE") == "WPA3"

    def test_sae_alone(self):
        assert map_airodump_privacy("SAE") == "WPA3"

    def test_wpa_only(self):
        assert map_airodump_privacy("WPA TKIP") == "WPA"

    def test_wep(self):
        assert map_airodump_privacy("WEP") == "WEP"

    def test_open(self):
        assert map_airodump_privacy("OPN") == "Open"

    def test_empty(self):
        assert map_airodump_privacy("") == "Open"

    def test_mixed_wpa_wpa2(self):
        assert map_airodump_privacy("WPA2 WPA CCMP TKIP") == "WPA2"


# ---------------------------------------------------------------------------
# Airodump CSV parsing
# ---------------------------------------------------------------------------

SAMPLE_AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed,"
    " Privacy, Cipher, Authentication, Power, # beacons, # IV,"
    " LAN IP, ID-length, ESSID, Key\r\n"
    "AA:BB:CC:DD:EE:01, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    "  6, 54, WPA2 CCMP PSK,CCMP,PSK, -55, 100, 0,"
    "  0.  0.  0.  0, 10, HomeNetwork,\r\n"
    "AA:BB:CC:DD:EE:02, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    " 11, 54, OPN,,, -72, 50, 0,"
    "  0.  0.  0.  0,  8, CoffeeShop,\r\n"
    "AA:BB:CC:DD:EE:03, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    "  1, 54, WPA2 CCMP PSK,CCMP,PSK, -1, 10, 0,"
    "  0.  0.  0.  0,  0, ,\r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets,"
    " BSSID, Probed ESSIDs\r\n"
    "11:22:33:44:55:01, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    " -60, 100, AA:BB:CC:DD:EE:01, HomeNetwork\r\n"
    "11:22:33:44:55:02, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    " -65, 50, AA:BB:CC:DD:EE:01, HomeNetwork\r\n"
    "11:22:33:44:55:03, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    " -70, 30, AA:BB:CC:DD:EE:02, CoffeeShop\r\n"
    "11:22:33:44:55:04, 2025-01-01 00:00:00, 2025-01-01 00:01:00,"
    " -80, 10, (not associated), \r\n"
)


class TestParseAirodumpCsv:
    def test_parses_networks(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        assert len(networks) == 3

    def test_network_fields(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        assert home.bssid == "aa:bb:cc:dd:ee:01"
        assert home.signal == -55
        assert home.channel == 6
        assert home.security == "WPA2"

    def test_open_network(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        assert coffee.security == "Open"
        assert coffee.channel == 11

    def test_unknown_power_mapped_to_minus_100(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        hidden = [n for n in networks if n.ssid == ""][0]
        assert hidden.signal == -100

    def test_client_counts(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        home = [n for n in networks if n.ssid == "HomeNetwork"][0]
        coffee = [n for n in networks if n.ssid == "CoffeeShop"][0]
        assert home.clients == 2
        assert coffee.clients == 1

    def test_not_associated_clients_excluded(self):
        _, client_counts = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        for bssid in client_counts:
            assert "not associated" not in bssid

    def test_sorted_by_signal(self):
        networks, _ = parse_airodump_csv(SAMPLE_AIRODUMP_CSV)
        signals = [n.signal for n in networks]
        assert signals == sorted(signals, reverse=True)

    def test_empty_input(self):
        networks, client_counts = parse_airodump_csv("")
        assert networks == []
        assert client_counts == {}

    def test_only_header(self):
        header_only = (
            "BSSID, First time seen, Last time seen, channel, Speed,"
            " Privacy, Cipher, Authentication, Power, # beacons, # IV,"
            " LAN IP, ID-length, ESSID, Key\r\n"
        )
        networks, client_counts = parse_airodump_csv(header_only)
        assert networks == []
        assert client_counts == {}
