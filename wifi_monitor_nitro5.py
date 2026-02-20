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
    sudo python wifi_monitor_nitro5.py --dns          # capture DNS queries
    sudo python wifi_monitor_nitro5.py --dns -c creds.csv --connect
"""

from __future__ import annotations

import sys

MIN_PYTHON = (3, 9)
if sys.version_info < MIN_PYTHON:
    sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (found {sys.version}).")

import argparse
import collections
import csv
import os
import re
import stat
import subprocess
import threading
import time

from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.table import Table

from wifi_common import (
    Network, signal_to_bars, signal_color, security_color, COLOR_TO_RICH,
    CommandRunner, SubprocessRunner, get_machine_name,
)

# -- Defaults --
SCAN_INTERVAL = 10  # seconds between refreshes
_DEFAULT_RUNNER = SubprocessRunner()


def _rich_color(rgb: tuple) -> str:
    """Convert an RGB tuple to a Rich color name."""
    return COLOR_TO_RICH.get(rgb, "white")


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
    *,
    runner: CommandRunner | None = None,
) -> bool:
    """Connect to a WiFi network using nmcli.

    Args:
        ssid: The network SSID to connect to.
        passphrase: The network passphrase (empty string for open networks).
        interface: Optional wireless interface name.
        runner: Optional CommandRunner for subprocess calls (testing seam).

    Returns:
        True if the connection succeeded, False otherwise.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmd = ["nmcli", "device", "wifi", "connect", ssid]

    if passphrase:
        cmd += ["password", passphrase]

    if interface:
        cmd += ["ifname", interface]

    try:
        result = runner.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# DNS query capture (requires root / tcpdump)
# ---------------------------------------------------------------------------

_DNS_QUERY_RE = re.compile(
    r"\b(?:A|AAAA|PTR|MX|CNAME|TXT|SRV|SOA|NS|ANY|HTTPS|SVCB)\?\s+(\S+?)\.?\s"
)


def parse_tcpdump_dns_line(line: str) -> str | None:
    """Extract the queried domain name from a tcpdump output line.

    Only matches DNS *query* lines (those containing ``A?``, ``AAAA?``, etc.).
    Response lines are ignored.  Returns the domain without trailing dot,
    or None if the line is not a DNS query.
    """
    match = _DNS_QUERY_RE.search(line)
    if match:
        return match.group(1).rstrip(".")
    return None


class DnsTracker:
    """Thread-safe DNS query frequency tracker.

    Uses a background thread to read tcpdump output and count queried
    domain names.  Call ``start()`` to begin capture and ``stop()`` to
    terminate.  Use ``top(n)`` to retrieve the *n* most queried domains.

    Args:
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or _DEFAULT_RUNNER
        self._counts: collections.Counter[str] = collections.Counter()
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

    def record(self, domain: str) -> None:
        """Increment the query count for *domain* (thread-safe)."""
        with self._lock:
            self._counts[domain] += 1

    def top(self, n: int = 15) -> list[tuple[str, int]]:
        """Return the *n* most queried domains as ``(domain, count)`` pairs."""
        with self._lock:
            return self._counts.most_common(n)

    def start(self, interface: str | None = None) -> bool:
        """Start capturing DNS queries via tcpdump.

        Returns True if tcpdump was launched successfully, False if
        tcpdump is not installed or cannot be started.
        """
        cmd = ["tcpdump", "-l", "-n", "udp", "port", "53"]
        if interface:
            cmd = ["tcpdump", "-l", "-n", "-i", interface, "udp", "port", "53"]

        env = _minimal_env()
        try:
            self._process = self._runner.popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        except (FileNotFoundError, OSError):
            return False

        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        """Terminate the tcpdump process and wait for the reader thread."""
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _reader_loop(self) -> None:
        """Read DNS queries from tcpdump stdout (runs in background thread)."""
        try:
            assert self._process is not None and self._process.stdout is not None
            for line in self._process.stdout:
                domain = parse_tcpdump_dns_line(line)
                if domain:
                    self.record(domain)
        except (ValueError, OSError):
            pass  # Process was terminated


def scan_wifi_nmcli(
    interface: str | None = None,
    *,
    runner: CommandRunner | None = None,
) -> list[Network]:
    """Scan for WiFi networks using nmcli.

    Triggers a rescan first (needs root), then lists cached results.
    Falls back to cached results if rescan fails (non-root).
    Returns an empty list if nmcli is unavailable or times out.

    Args:
        interface: Optional wireless interface name.
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()

    rescan_cmd = ["nmcli", "device", "wifi", "rescan"]
    if interface:
        rescan_cmd += ["ifname", interface]

    try:
        runner.run(rescan_cmd, capture_output=True, timeout=15, env=env)
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
        result = runner.run(
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
        title=f"WiFi Monitor — {get_machine_name()}",
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
            has_key = (net.ssid in credentials) if (net.ssid and credentials) else False
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
# Main
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"WiFi Monitor — {get_machine_name()}",
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
    parser.add_argument(
        "--dns",
        action="store_true",
        help="capture and display DNS queries (requires root / tcpdump)",
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
    dns_tracker: DnsTracker | None = None

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
        if dns_tracker.start(interface=args.interface):
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

    console.print(f"[bold cyan]WiFi Monitor[/bold cyan] — {get_machine_name()}")
    console.print(
        f"Scanning {'all interfaces' if not args.interface else args.interface}…\n"
    )

    try:
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                networks = scan_wifi_nmcli(args.interface)
                network_table = build_table(networks, credentials=credentials)

                if dns_tracker is not None:
                    dns_table = build_dns_table(dns_tracker.top())
                    live.update(Group(network_table, dns_table))
                else:
                    live.update(network_table)

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
        if dns_tracker is not None:
            dns_tracker.stop()
        console.print("\n[bold cyan]WiFi Monitor[/bold cyan] — stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
