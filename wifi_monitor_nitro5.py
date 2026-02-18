#!/usr/bin/env python3
"""WiFi Monitor — Laptop version for Acer Nitro 5.

Uses nmcli to scan for nearby WiFi networks and displays results in a
real-time Rich terminal table.  No monitor mode or root required for
basic scanning (NetworkManager caches recent scan results).

Usage:
    python wifi_monitor_nitro5.py                     # scan all interfaces
    python wifi_monitor_nitro5.py -i wlan1            # specify interface
    python wifi_monitor_nitro5.py -c creds.csv        # load credentials file
    python wifi_monitor_nitro5.py -c creds.csv --connect  # auto-connect
    sudo python wifi_monitor_nitro5.py                # force fresh scans
"""

import argparse
import csv
import os
import re
import stat
import subprocess
import sys
import time

from rich.console import Console
from rich.live import Live
from rich.markup import escape
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

def _minimal_env() -> dict[str, str]:
    """Build a minimal environment for subprocess calls.

    Only passes PATH, LC_ALL, and HOME — avoids leaking the full user
    environment into child processes.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", ""),
    }


# ---------------------------------------------------------------------------
# Credentials file
# ---------------------------------------------------------------------------

def load_credentials(filepath: str) -> dict[str, str]:
    """Load SSID/passphrase pairs from a CSV file.

    File format: one ``ssid,passphrase`` per line.  Lines starting with
    ``#`` are comments.  Blank lines are ignored.  Fields may be quoted
    to include commas.  Returns an empty dict if the file is missing or
    unreadable.

    Warns to stderr if the file is world-readable (permissions concern).
    """
    creds: dict[str, str] = {}

    if not os.path.isfile(filepath):
        return creds

    # Check file permissions — warn if world-readable
    try:
        file_stat = os.stat(filepath)
        if file_stat.st_mode & stat.S_IROTH:
            print(
                f"WARNING: credentials file '{filepath}' is world-readable. "
                "Consider restricting permissions to 600.",
                file=sys.stderr,
            )
    except OSError:
        pass

    try:
        with open(filepath, newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                # Skip blank or comment lines
                if not row or row[0].strip().startswith("#"):
                    continue
                if len(row) < 2:
                    continue
                ssid = row[0].strip()
                passphrase = row[1].strip()
                creds[ssid] = passphrase
    except OSError:
        return creds

    return creds


# ---------------------------------------------------------------------------
# nmcli connection
# ---------------------------------------------------------------------------

def connect_wifi_nmcli(
    ssid: str,
    passphrase: str,
    interface: str | None = None,
) -> bool:
    """Connect to a WiFi network using nmcli.

    Args:
        ssid: The network SSID to connect to.
        passphrase: The network passphrase (empty string for open networks).
        interface: Optional wireless interface name.

    Returns:
        True if the connection succeeded, False otherwise.
    """
    env = _minimal_env()
    cmd = ["nmcli", "device", "wifi", "connect", ssid]

    if passphrase:
        cmd += ["password", passphrase]

    if interface:
        cmd += ["ifname", interface]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def scan_wifi_nmcli(interface: str | None = None) -> list[Network]:
    """Scan for WiFi networks using nmcli.

    Triggers a rescan first (needs root), then lists cached results.
    Falls back to cached results if rescan fails (non-root).
    Returns an empty list if nmcli is unavailable or times out.
    """
    env = _minimal_env()

    rescan_cmd = ["nmcli", "device", "wifi", "rescan"]
    if interface:
        rescan_cmd += ["ifname", interface]

    try:
        subprocess.run(rescan_cmd, capture_output=True, timeout=15, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass  # Rescan failure is non-fatal; fall through to list

    list_cmd = [
        "nmcli", "-t",
        "-f", "BSSID,SSID,CHAN,SIGNAL,SECURITY",
        "device", "wifi", "list",
    ]
    if interface:
        list_cmd += ["ifname", interface]

    try:
        result = subprocess.run(
            list_cmd, capture_output=True, text=True, timeout=15, env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

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
    Values outside 0-100 are clamped to prevent nonsensical results.
    """
    pct = max(0, min(100, pct))
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


def build_table(
    networks: list[Network],
    credentials: dict[str, str] | None = None,
) -> Table:
    """Build a Rich Table displaying the scanned networks.

    Args:
        networks: List of scanned networks (already sorted by signal).
        credentials: Optional dict of SSID -> passphrase.  When provided,
            a "Key" column is added showing which networks have known
            passphrases.
    """
    show_key = bool(credentials)
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
    if show_key:
        table.add_column("Key", justify="center", width=3)
    table.add_column("BSSID", style="grey50", width=17)
    table.add_column("Ch", justify="right", width=4)
    table.add_column("dBm", justify="right", width=5)
    table.add_column("Sig", width=5)
    table.add_column("Security", width=8)

    for i, net in enumerate(networks, 1):
        ssid = escape(net.ssid) if net.ssid else "[dim]<hidden>[/dim]"
        sig_c = _rich_color(signal_color(net.signal))
        sec_c = _rich_color(security_color(net.security))
        bars = signal_to_bars(net.signal)
        bar_str = _bar_string(bars)

        row = [
            str(i),
            ssid,
        ]
        if show_key:
            has_key = net.ssid in credentials if net.ssid else False
            row.append("[green]*[/green]" if has_key else "")
        row.extend([
            escape(net.bssid.upper()),
            str(net.channel),
            f"[{sig_c}]{net.signal}[/{sig_c}]",
            f"[{sig_c}]{bar_str}[/{sig_c}]",
            f"[{sec_c}]{net.security}[/{sec_c}]",
        ])

        table.add_row(*row)

    return table


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="WiFi Monitor — Acer Nitro 5",
    )
    parser.add_argument(
        "-i", "--interface",
        help="wireless interface name (e.g. wlan0)",
    )
    parser.add_argument(
        "-c", "--credentials",
        metavar="FILE",
        help="CSV file with ssid,passphrase pairs",
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help="auto-connect to the strongest network with known credentials",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Run the WiFi monitor TUI loop.

    Handles KeyboardInterrupt (Ctrl+C) gracefully so the terminal is left
    clean when the user exits.
    """
    args = _parse_args()
    console = Console()
    credentials: dict[str, str] | None = None
    connected = False

    if args.credentials:
        credentials = load_credentials(args.credentials)
        if credentials:
            console.print(
                f"[bold cyan]WiFi Monitor[/bold cyan] — "
                f"loaded {len(credentials)} credential(s)"
            )
        else:
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                "[yellow]no credentials loaded[/yellow]"
            )

    console.print("[bold cyan]WiFi Monitor[/bold cyan] — Acer Nitro 5")
    console.print(
        f"Scanning {'all interfaces' if not args.interface else args.interface}…\n"
    )

    try:
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                networks = scan_wifi_nmcli(args.interface)
                live.update(build_table(networks, credentials=credentials))

                # Auto-connect on first scan if requested
                if args.connect and credentials and not connected:
                    for net in networks:
                        if net.ssid and net.ssid in credentials:
                            ok = connect_wifi_nmcli(
                                net.ssid,
                                credentials[net.ssid],
                                interface=args.interface,
                            )
                            if ok:
                                connected = True
                            break

                time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        console.print("\n[bold cyan]WiFi Monitor[/bold cyan] — stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
