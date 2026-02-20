#!/usr/bin/env python3
"""WiFi Monitor — macOS version.

Uses the built-in airport utility to scan for nearby WiFi networks and
displays results in a real-time Rich terminal table. Supports credentials
file, auto-connect, and DNS query capture (with tcpdump).

Usage:
    python wifi_monitor_mac.py                     # scan (default interface en0)
    python wifi_monitor_mac.py -i en1             # specify interface
    python wifi_monitor_mac.py -c creds.csv        # load credentials file
    python wifi_monitor_mac.py -c creds.csv --connect  # auto-connect
    sudo python wifi_monitor_mac.py --dns          # capture DNS queries
"""

from __future__ import annotations

import sys

MIN_PYTHON = (3, 9)
if sys.version_info < MIN_PYTHON:
    sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (found {sys.version}).")

import argparse
import os
import re
import subprocess
import time

from rich.console import Console, Group
from rich.live import Live

from wifi_common import (
    Network,
    CommandRunner,
    SubprocessRunner,
    get_machine_name,
)

# Import platform-agnostic UI and utilities from nitro5 (no nmcli at import time)
from wifi_monitor_nitro5 import (
    load_credentials,
    build_table,
    build_dns_table,
    DnsTracker,
    SCAN_INTERVAL,
    _DEFAULT_RUNNER,
)

# Airport binary path (Apple80211 framework)
_AIRPORT_PATHS = [
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport",
]

_BSSID_RE = re.compile(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})")


def _find_airport() -> str | None:
    """Return path to airport binary, or None if not found."""
    for path in _AIRPORT_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _minimal_env() -> dict[str, str]:
    """Build minimal environment for subprocess calls."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/sbin"),
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", ""),
    }


def _map_airport_security(security: str) -> str:
    """Map airport SECURITY field to short label."""
    s = security.upper()
    if "WPA3" in s or "SAE" in s:
        return "WPA3"
    if "WPA2" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    if not s or "OPEN" in s or "NONE" in s:
        return "Open"
    return "Open"


def parse_airport_output(output: str) -> list[Network]:
    """Parse airport -s output into a list of Network objects.

    Airport outputs columns: SSID BSSID RSSI CHANNEL HT CC SECURITY
    SSID may contain spaces; BSSID is 17-char MAC. We use BSSID as anchor.
    """
    networks: list[Network] = []

    for line in output.strip().splitlines():
        line = line.strip()
        if not line or "BSSID" in line and "RSSI" in line:
            continue  # Skip header

        match = _BSSID_RE.search(line)
        if not match:
            continue

        bssid = match.group(1).lower()
        bssid_start = match.start()
        ssid = line[:bssid_start].strip()
        rest = line[match.end() :].split()

        if len(rest) < 2:
            continue

        try:
            rssi = int(rest[0])
        except ValueError:
            rssi = -100

        try:
            channel_str = rest[1].split(",")[0]
            channel = int(channel_str)
        except (ValueError, IndexError):
            channel = 0

        security = rest[-1] if len(rest) >= 3 else "Open"
        security = _map_airport_security(security)

        networks.append(
            Network(
                bssid=bssid,
                ssid=ssid,
                signal=rssi,
                channel=channel,
                security=security,
            )
        )

    networks.sort(key=lambda n: n.signal, reverse=True)
    return networks


def scan_wifi_airport(
    interface: str | None = None,
    *,
    runner: CommandRunner | None = None,
) -> list[Network]:
    """Scan for WiFi networks using the macOS airport utility.

    Returns an empty list if airport is unavailable or times out.
    """
    runner = runner or _DEFAULT_RUNNER
    airport_path = _find_airport()
    if not airport_path:
        return []

    # airport -s uses the default WiFi interface; no interface flag
    cmd = [airport_path, "-s"]

    env = _minimal_env()
    try:
        result = runner.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        if result.returncode != 0:
            return []
        return parse_airport_output(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def get_wifi_interface() -> str:
    """Return default WiFi interface on macOS (typically en0)."""
    env = _minimal_env()
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            return "en0"

        current_port = None
        for line in result.stdout.splitlines():
            if "Wi-Fi" in line or "Airport" in line:
                current_port = "Wi-Fi"
                continue
            if current_port and "Device:" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
            current_port = None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "en0"


def connect_wifi_mac(
    ssid: str,
    passphrase: str,
    interface: str | None = None,
    *,
    runner: CommandRunner | None = None,
) -> bool:
    """Connect to a WiFi network using networksetup.

    Args:
        ssid: The network SSID to connect to.
        passphrase: The network passphrase (empty for open networks).
        interface: WiFi interface (e.g. en0). Defaults to auto-detect.
        runner: Optional CommandRunner for testing.
    """
    runner = runner or _DEFAULT_RUNNER
    iface = interface or get_wifi_interface()
    env = _minimal_env()

    cmd = ["networksetup", "-setairportnetwork", iface, ssid]
    if passphrase:
        cmd.append(passphrase)

    try:
        result = runner.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"WiFi Monitor — {get_machine_name()} (macOS)",
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Wireless interface (e.g. en0). Default: auto-detect",
    )
    parser.add_argument(
        "-c", "--credentials",
        metavar="FILE",
        help="CSV file with ssid,passphrase pairs",
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help="Auto-connect to strongest network with known credentials",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Capture and display DNS queries (requires root / tcpdump)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """Run the WiFi monitor TUI loop."""
    args = _parse_args()
    console = Console()
    credentials: dict[str, str] | None = None
    connected = False
    dns_tracker: DnsTracker | None = None

    interface = args.interface or get_wifi_interface()

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

    if args.dns:
        dns_tracker = DnsTracker()
        if dns_tracker.start(interface=interface):
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                "[green]DNS capture started[/green]"
            )
        else:
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                "[yellow]DNS capture failed (tcpdump not found or no permission)[/yellow]"
            )
            dns_tracker = None

    console.print(f"[bold cyan]WiFi Monitor[/bold cyan] — {get_machine_name()} (macOS)")
    console.print(f"Scanning {interface}…\n")

    try:
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                networks = scan_wifi_airport(interface)
                network_table = build_table(networks, credentials=credentials)

                if dns_tracker is not None:
                    dns_table = build_dns_table(dns_tracker.top())
                    live.update(Group(network_table, dns_table))
                else:
                    live.update(network_table)

                if args.connect and credentials and not connected:
                    for net in networks:
                        if net.ssid and net.ssid in credentials:
                            if connect_wifi_mac(
                                net.ssid,
                                credentials[net.ssid],
                                interface=interface,
                            ):
                                connected = True
                            break

                time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        if dns_tracker is not None:
            dns_tracker.stop()
        console.print("\n[bold cyan]WiFi Monitor[/bold cyan] — stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
