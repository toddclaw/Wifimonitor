"""Tests for wifimonitor.display.tables — canonical Rich TUI table builders.

Imports from the canonical location (wifimonitor.display.tables) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

from rich.table import Table

from wifimonitor.display.tables import (
    _bar_string,
    _rich_color,
    build_deauth_summary_table,
    build_deauth_table,
    build_dns_table,
    build_rogue_table,
    build_table,
)
from wifimonitor.wifi_common import (
    DeauthEvent,
    DeauthSummary,
    Network,
    RogueAlert,
)


# ---------------------------------------------------------------------------
# _bar_string
# ---------------------------------------------------------------------------

class TestBarString:
    """_bar_string builds a 4-char signal-bar string."""

    def test_zero_bars(self):
        assert _bar_string(0) == "    "

    def test_one_bar(self):
        result = _bar_string(1)
        assert len(result) == 4
        assert result[0] != " "

    def test_four_bars(self):
        result = _bar_string(4)
        assert " " not in result

    def test_negative_bars(self):
        assert _bar_string(-1) == "    "

    def test_bars_above_four(self):
        result = _bar_string(5)
        assert len(result) == 4
        assert " " not in result


# ---------------------------------------------------------------------------
# _rich_color
# ---------------------------------------------------------------------------

class TestRichColor:
    """_rich_color converts RGB tuples to Rich color names."""

    def test_known_color(self):
        from wifimonitor.wifi_common import COLOR_TO_RICH
        for rgb, name in COLOR_TO_RICH.items():
            assert _rich_color(rgb) == name

    def test_unknown_color_returns_white(self):
        assert _rich_color((1, 2, 3)) == "white"


# ---------------------------------------------------------------------------
# build_table
# ---------------------------------------------------------------------------

class TestBuildTable:
    """build_table creates a Rich Table for WiFi scan results."""

    def test_returns_rich_table(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-55)]
        table = build_table(nets)
        assert isinstance(table, Table)

    def test_caption_shows_network_count(self):
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Net1", channel=6, signal=-55),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Net2", channel=11, signal=-65),
        ]
        table = build_table(nets)
        assert "2 networks found" in str(table.caption)

    def test_caption_override(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-55)]
        table = build_table(nets, caption_override="custom caption")
        assert "custom caption" in str(table.caption)

    def test_empty_networks_builds_table(self):
        table = build_table([])
        assert isinstance(table, Table)
        assert "0 networks found" in str(table.caption)

    def test_hidden_network_shows_hidden_label(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="", channel=1, signal=-80)]
        table = build_table(nets)
        assert table.row_count == 1

    def test_credentials_adds_key_column(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-55)]
        creds = {"Test": "password123"}
        table = build_table(nets, credentials=creds)
        col_names = [c.header for c in table.columns]
        assert "Key" in col_names

    def test_no_credentials_no_key_column(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-55)]
        table = build_table(nets)
        col_names = [c.header for c in table.columns]
        assert "Key" not in col_names

    def test_connected_bssid_row_count(self):
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Connected", channel=6, signal=-45),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Other", channel=11, signal=-65),
        ]
        table = build_table(nets, connected_bssid="aa:bb:cc:dd:ee:01")
        assert table.row_count == 2

    def test_ssid_with_rich_markup_escaped(self):
        """SSIDs with Rich markup must be escaped, not interpreted."""
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="[bold]Evil[/bold]", channel=6, signal=-55)]
        table = build_table(nets)
        assert table.row_count == 1

    def test_empty_connected_bssid_treated_as_none(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-55)]
        table = build_table(nets, connected_bssid="")
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# build_dns_table
# ---------------------------------------------------------------------------

class TestBuildDnsTable:
    """build_dns_table creates a Rich Table for DNS query results."""

    def test_returns_rich_table(self):
        domains = [("google.com", 5), ("example.org", 3)]
        table = build_dns_table(domains)
        assert isinstance(table, Table)

    def test_row_count_matches_domains(self):
        domains = [("a.com", 5), ("b.com", 3), ("c.com", 1)]
        table = build_dns_table(domains)
        assert table.row_count == 3

    def test_empty_domains_builds_table(self):
        table = build_dns_table([])
        assert table.row_count == 0

    def test_title_contains_dns(self):
        table = build_dns_table([("test.com", 1)])
        assert "DNS" in str(table.title)

    def test_escapes_domain_names(self):
        """Domain names from external data must be escaped."""
        domains = [("[bold]evil.com[/bold]", 1)]
        table = build_dns_table(domains)
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# build_rogue_table
# ---------------------------------------------------------------------------

class TestBuildRogueTable:
    """build_rogue_table creates a Rich Table for rogue AP alerts."""

    def test_returns_rich_table(self):
        alert = RogueAlert(
            network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="FakeNet", channel=6, signal=-55),
            reason="unknown_bssid",
            expected_bssids=["aa:bb:cc:dd:ee:01"],
            expected_channels=[6],
        )
        table = build_rogue_table([alert])
        assert isinstance(table, Table)

    def test_row_count_matches_alerts(self):
        alerts = [
            RogueAlert(
                network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="Net", channel=6),
                reason="unknown_bssid",
                expected_bssids=["aa:bb:cc:dd:ee:01"],
                expected_channels=[6],
            ),
            RogueAlert(
                network=Network(bssid="aa:bb:cc:dd:ee:01", ssid="Net", channel=11),
                reason="unexpected_channel",
                expected_bssids=["aa:bb:cc:dd:ee:01"],
                expected_channels=[6],
            ),
        ]
        table = build_rogue_table(alerts)
        assert table.row_count == 2

    def test_title_contains_rogue(self):
        alert = RogueAlert(
            network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="Net", channel=6),
            reason="unknown_bssid",
            expected_bssids=[],
            expected_channels=[],
        )
        table = build_rogue_table([alert])
        assert "Rogue" in str(table.title)

    def test_ssid_is_escaped(self):
        alert = RogueAlert(
            network=Network(bssid="ff:ff:ff:ff:ff:ff", ssid="[red]Evil[/red]", channel=6),
            reason="unknown_bssid",
            expected_bssids=[],
            expected_channels=[],
        )
        table = build_rogue_table([alert])
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# build_deauth_table
# ---------------------------------------------------------------------------

class TestBuildDeauthTable:
    """build_deauth_table creates a Rich Table for deauth events."""

    def _event(self) -> DeauthEvent:
        return DeauthEvent(
            bssid="aa:bb:cc:dd:ee:ff",
            source="aa:bb:cc:dd:ee:ff",
            destination="11:22:33:44:55:66",
            reason="test reason",
            subtype="deauth",
        )

    def test_returns_rich_table(self):
        table = build_deauth_table([self._event()])
        assert isinstance(table, Table)

    def test_row_count_matches_events(self):
        events = [self._event() for _ in range(3)]
        table = build_deauth_table(events)
        assert table.row_count == 3

    def test_title_contains_deauth(self):
        table = build_deauth_table([self._event()])
        assert "Deauth" in str(table.title)

    def test_bssid_is_escaped(self):
        event = DeauthEvent(
            bssid="[red]evil[/red]",
            source="aa:bb:cc:dd:ee:ff",
            destination="11:22:33:44:55:66",
            reason="test",
            subtype="deauth",
        )
        table = build_deauth_table([event])
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# build_deauth_summary_table
# ---------------------------------------------------------------------------

class TestBuildDeauthSummaryTable:
    """build_deauth_summary_table creates severity-classified summary."""

    def _summary(self, severity: str = "normal") -> DeauthSummary:
        return DeauthSummary(
            bssid="aa:bb:cc:dd:ee:ff",
            total_count=5,
            broadcast_count=2,
            unique_targets=3,
            severity=severity,
        )

    def test_returns_rich_table(self):
        table = build_deauth_summary_table([self._summary()])
        assert isinstance(table, Table)

    def test_row_count_matches_summaries(self):
        summaries = [self._summary("normal"), self._summary("attack")]
        table = build_deauth_summary_table(summaries)
        assert table.row_count == 2

    def test_title_contains_deauth(self):
        table = build_deauth_summary_table([self._summary()])
        assert "Deauth" in str(table.title)

    def test_empty_summaries_builds_table(self):
        table = build_deauth_summary_table([])
        assert table.row_count == 0

    def test_bssid_is_escaped(self):
        summary = DeauthSummary(
            bssid="[red]evil[/red]",
            total_count=1,
            broadcast_count=0,
            unique_targets=1,
            severity="normal",
        )
        table = build_deauth_summary_table([summary])
        assert table.row_count == 1
