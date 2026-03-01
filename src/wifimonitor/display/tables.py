"""Rich TUI table builders for WiFi Monitor.

Builds Rich :class:`Table` objects for network scan results, DNS queries,
rogue AP alerts, and deauth/disassoc frame summaries.  Can be used
standalone for testing table rendering::

    python -m wifimonitor.display.tables          # render a demo table
"""

from __future__ import annotations

from rich.markup import escape
from rich.table import Table

from wifimonitor.wifi_common import (
    COLOR_TO_RICH,
    DeauthEvent,
    DeauthSummary,
    Network,
    RogueAlert,
    signal_color,
    signal_to_bars,
    security_color,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rich_color(rgb: tuple) -> str:  # type: ignore[type-arg]
    """Convert an RGB tuple to a Rich color name."""
    return COLOR_TO_RICH.get(rgb, "white")


def _bar_string(bars: int) -> str:
    """Build a signal-bar string like '▂▄▆█'."""
    chars = ["▂", "▄", "▆", "█"]
    return "".join(chars[i] if i < bars else " " for i in range(4))


# ---------------------------------------------------------------------------
# Network scan table
# ---------------------------------------------------------------------------

def build_table(
    networks: list[Network],
    credentials: dict[str, str] | None = None,
    caption_override: str | None = None,
    connected_bssid: str | None = None,
) -> Table:
    """Build a Rich Table displaying the scanned networks.

    Args:
        networks: List of scanned networks (already sorted by signal).
        credentials: Optional dict of SSID -> passphrase.  When provided,
            a "Key" column is added showing which networks have known
            passphrases.
        caption_override: Optional caption to use instead of default.
        connected_bssid: Optional BSSID of the currently connected network.
            When provided, the matching row is highlighted bold and shows a
            filled-circle indicator in the "Con" column.  Empty string is
            treated as None (not connected).
    """
    # Normalize: empty string or None both mean "not connected"
    _connected = connected_bssid.lower() if connected_bssid else None

    show_key = bool(credentials)
    caption = caption_override if caption_override is not None else f"{len(networks)} networks found"
    table = Table(
        title="WiFi Monitor — Acer Nitro 5",
        title_style="bold cyan",
        caption=caption,
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("Con", justify="center", width=3)
    table.add_column("SSID", style="white", min_width=15, max_width=30)
    if show_key:
        table.add_column("Key", justify="center", width=3)
    table.add_column("BSSID", style="grey50", width=17)
    table.add_column("Ch", justify="right", width=4)
    table.add_column("dBm", justify="right", width=5)
    table.add_column("Sig", width=5)
    table.add_column("Cli", justify="right", width=4)
    table.add_column("Security", width=8)

    for i, net in enumerate(networks, 1):
        is_connected = bool(_connected) and net.bssid == _connected
        ssid = escape(net.ssid) if net.ssid else "[dim]<hidden>[/dim]"
        sig_c = _rich_color(signal_color(net.signal))
        sec_c = _rich_color(security_color(net.security))
        bars = signal_to_bars(net.signal)
        bar_str = _bar_string(bars)

        row = [
            str(i),
            "[green]●[/green]" if is_connected else "",
            ssid,
        ]
        if show_key:
            has_key = (net.ssid in credentials) if (net.ssid and credentials) else False
            row.append("[green]*[/green]" if has_key else "")
        row.extend([
            escape(net.bssid.upper()),
            str(net.channel),
            f"[{sig_c}]{net.signal}[/{sig_c}]",
            f"[{sig_c}]{bar_str}[/{sig_c}]",
            str(net.clients),
            f"[{sec_c}]{net.security}[/{sec_c}]",
        ])

        table.add_row(*row, style="bold" if is_connected else "")

    return table


# ---------------------------------------------------------------------------
# DNS query table
# ---------------------------------------------------------------------------

def build_dns_table(domains: list[tuple[str, int]]) -> Table:
    """Build a Rich Table showing the top queried DNS domains.

    Args:
        domains: List of (domain, count) pairs, already sorted by count
            descending (as returned by DnsTracker.top()).
    """
    table = Table(
        title="DNS Queries (top domains)",
        title_style="bold cyan",
        caption=f"{len(domains)} domains tracked",
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("Domain", style="white", min_width=20, max_width=50)
    table.add_column("Count", justify="right", width=6)

    for i, (domain, count) in enumerate(domains, 1):
        table.add_row(str(i), escape(domain), str(count))

    return table


# ---------------------------------------------------------------------------
# Rogue AP alert table
# ---------------------------------------------------------------------------

def build_rogue_table(alerts: list[RogueAlert]) -> Table:
    """Build a Rich Table showing rogue AP detection alerts.

    Args:
        alerts: List of :class:`RogueAlert` objects from :func:`detect_rogue_aps`.
    """
    table = Table(
        title="Rogue AP Alerts",
        title_style="bold red",
        caption=f"{len(alerts)} alert(s)",
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("SSID", style="white", min_width=10, max_width=25)
    table.add_column("BSSID", style="red", width=17)
    table.add_column("Ch", justify="right", width=4)
    table.add_column("Reason", style="yellow", min_width=10, max_width=20)
    table.add_column("Expected BSSIDs", style="grey50", min_width=15, max_width=40)

    for i, alert in enumerate(alerts, 1):
        reason_display = alert.reason.replace("_", " ")
        expected = ", ".join(b.upper() for b in alert.expected_bssids)
        table.add_row(
            str(i),
            escape(alert.network.ssid),
            escape(alert.network.bssid.upper()),
            str(alert.network.channel),
            reason_display,
            expected,
        )

    return table


# ---------------------------------------------------------------------------
# Deauth event table
# ---------------------------------------------------------------------------

def build_deauth_table(events: list[DeauthEvent]) -> Table:
    """Build a Rich Table showing captured deauth/disassoc events.

    Args:
        events: List of :class:`DeauthEvent` objects, newest first.
    """
    table = Table(
        title="Deauth/Disassoc Frames",
        title_style="bold red",
        caption=f"{len(events)} event(s)",
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("BSSID", style="red", width=17)
    table.add_column("Source", style="yellow", width=17)
    table.add_column("Destination", style="white", width=17)
    table.add_column("Type", style="cyan", width=8)
    table.add_column("Reason", style="grey50", min_width=10, max_width=40)

    for i, evt in enumerate(events, 1):
        table.add_row(
            str(i),
            escape(evt.bssid.upper()),
            escape(evt.source.upper()),
            escape(evt.destination.upper()),
            evt.subtype,
            escape(evt.reason),
        )

    return table


# ---------------------------------------------------------------------------
# Deauth severity summary table
# ---------------------------------------------------------------------------

def build_deauth_summary_table(summaries: list[DeauthSummary]) -> Table:
    """Build a Rich Table showing severity-classified deauth summaries.

    Rows are color-coded by severity:
        - **normal** — default style
        - **suspicious** — yellow
        - **attack** — bold red

    Args:
        summaries: Aggregated summaries from :func:`classify_deauth_events`.
    """
    _SEVERITY_STYLE: dict[str, str] = {
        "normal": "",
        "suspicious": "yellow",
        "attack": "bold red",
    }

    table = Table(
        title="Deauth/Disassoc Summary",
        title_style="bold red",
        caption=f"{len(summaries)} BSSID(s)",
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("BSSID", width=17)
    table.add_column("Frames", justify="right", width=7)
    table.add_column("Broadcast", justify="right", width=10)
    table.add_column("Targets", justify="right", width=8)
    table.add_column("Severity", width=12)

    for i, s in enumerate(summaries, 1):
        row_style = _SEVERITY_STYLE.get(s.severity, "")
        sev_label = s.severity.upper()
        table.add_row(
            str(i),
            escape(s.bssid.upper()),
            str(s.total_count),
            str(s.broadcast_count),
            str(s.unique_targets),
            sev_label,
            style=row_style,
        )

    return table


# ---------------------------------------------------------------------------
# Standalone CLI (demo)
# ---------------------------------------------------------------------------

def main() -> None:
    """Render a demo table with sample data for visual testing."""
    from rich.console import Console

    sample_networks = [
        Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=6, signal=-45, security="WPA2"),
        Network(bssid="aa:bb:cc:dd:ee:02", ssid="Office", channel=36, signal=-65, security="WPA3"),
        Network(bssid="aa:bb:cc:dd:ee:03", ssid="", channel=1, signal=-80, security="Open"),
    ]
    console = Console()
    table = build_table(sample_networks)
    console.print(table)


if __name__ == "__main__":
    main()
