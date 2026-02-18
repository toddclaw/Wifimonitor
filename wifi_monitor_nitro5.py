#!/usr/bin/env python3
"""WiFi Monitor — Laptop version for Acer Nitro 5.

Uses nmcli to scan for nearby WiFi networks and displays results in a
real-time Rich terminal table.  No monitor mode or root required for
basic scanning (NetworkManager caches recent scan results).

Usage:
    python wifi_monitor_nitro5.py            # default wlan0
    python wifi_monitor_nitro5.py wlan1      # specify interface
    sudo python wifi_monitor_nitro5.py       # force fresh scans
"""

import os
import re
import subprocess
import sys
import time

from rich.console import Console
from rich.live import Live
from rich.table import Table

from wifi_common import Network, signal_to_bars, signal_color, security_color

# -- Timing --
SCAN_INTERVAL = 10  # seconds between refreshes

# Rich color names mapped from RGB tuples
_COLOR_MAP = {
    (0, 255, 0): "green",
    (255, 255, 0): "yellow",
    (255, 0, 0): "red",
    (0, 255, 255): "cyan",
    (128, 128, 128): "grey50",
    (40, 40, 40): "grey15",
    (255, 165, 0): "dark_orange",
}


def _rich_color(rgb: tuple) -> str:
    """Convert an RGB tuple to a Rich color name."""
    return _COLOR_MAP.get(rgb, "white")


# ---------------------------------------------------------------------------
# nmcli scanning
# ---------------------------------------------------------------------------

def scan_wifi_nmcli(interface: str | None = None) -> list[Network]:
    """Scan for WiFi networks using nmcli.

    Triggers a rescan first (needs root), then lists cached results.
    Falls back to cached results if rescan fails (non-root).
    """
    rescan_cmd = ["nmcli", "device", "wifi", "rescan"]
    if interface:
        rescan_cmd += ["ifname", interface]
    subprocess.run(rescan_cmd, capture_output=True, timeout=15)

    list_cmd = [
        "nmcli", "-t",
        "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
        "device", "wifi", "list",
    ]
    if interface:
        list_cmd += ["ifname", interface]

    env = {**os.environ, "LC_ALL": "C"}
    result = subprocess.run(
        list_cmd, capture_output=True, text=True, timeout=15, env=env,
    )
    return parse_nmcli_output(result.stdout)


def parse_nmcli_output(output: str) -> list[Network]:
    """Parse nmcli terse output into a list of Network objects.

    nmcli -t uses colon as delimiter and escapes literal colons as ``\\:``.
    """
    networks: list[Network] = []

    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _split_nmcli_line(line)
        if len(fields) < 5:
            continue

        bssid = fields[0].lower()
        ssid = fields[1]
        security = _map_nmcli_security(fields[4])

        try:
            channel = int(fields[2])
        except ValueError:
            channel = 0

        try:
            signal_pct = int(fields[3])
        except ValueError:
            signal_pct = 0

        signal_dbm = _pct_to_dbm(signal_pct)

        networks.append(Network(
            bssid=bssid,
            ssid=ssid,
            signal=signal_dbm,
            channel=channel,
            security=security,
        ))

    networks.sort(key=lambda n: n.signal, reverse=True)
    return networks


def _split_nmcli_line(line: str) -> list[str]:
    """Split a nmcli terse-mode line on unescaped colons.

    Colons inside field values are escaped as ``\\:``.  We split on
    unescaped colons and then unescape the fields.
    """
    # Split on colons NOT preceded by a backslash
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts]


def _pct_to_dbm(pct: int) -> int:
    """Convert nmcli signal percentage (0-100) to approximate dBm.

    nmcli maps dBm to percentage roughly as:
        dBm = (pct / 2) - 100
    This is the inverse of the common NM formula.
    """
    return (pct // 2) - 100


def _map_nmcli_security(security: str) -> str:
    """Map nmcli SECURITY field to a short label."""
    s = security.upper()
    if "WPA3" in s or "SAE" in s:
        return "WPA3"
    if "WPA2" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    if not s or s == "--":
        return "Open"
    return "Open"


# ---------------------------------------------------------------------------
# Rich TUI rendering
# ---------------------------------------------------------------------------

def _bar_string(bars: int) -> str:
    """Build a signal-bar string like '▂▄▆█'."""
    chars = ["▂", "▄", "▆", "█"]
    return "".join(chars[i] if i < bars else " " for i in range(4))


def build_table(networks: list[Network]) -> Table:
    """Build a Rich Table displaying the scanned networks."""
    table = Table(
        title="WiFi Monitor — Acer Nitro 5",
        title_style="bold cyan",
        caption=f"{len(networks)} networks found",
        caption_style="grey50",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("#", style="grey50", width=3, justify="right")
    table.add_column("SSID", style="white", min_width=15, max_width=30)
    table.add_column("BSSID", style="grey50", width=17)
    table.add_column("Ch", justify="right", width=4)
    table.add_column("dBm", justify="right", width=5)
    table.add_column("Sig", width=5)
    table.add_column("Security", width=8)

    for i, net in enumerate(networks, 1):
        ssid = net.ssid or "[dim]<hidden>[/dim]"
        sig_c = _rich_color(signal_color(net.signal))
        sec_c = _rich_color(security_color(net.security))
        bars = signal_to_bars(net.signal)
        bar_str = _bar_string(bars)

        table.add_row(
            str(i),
            ssid,
            net.bssid.upper(),
            str(net.channel),
            f"[{sig_c}]{net.signal}[/{sig_c}]",
            f"[{sig_c}]{bar_str}[/{sig_c}]",
            f"[{sec_c}]{net.security}[/{sec_c}]",
        )

    return table


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    console = Console()

    console.print("[bold cyan]WiFi Monitor[/bold cyan] — Acer Nitro 5")
    console.print(f"Scanning {'all interfaces' if not interface else interface}…\n")

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            networks = scan_wifi_nmcli(interface)
            live.update(build_table(networks))
            time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
