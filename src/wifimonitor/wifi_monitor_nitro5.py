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
    sudo python wifi_monitor_nitro5.py --monitor      # client counts via airodump-ng
    sudo python wifi_monitor_nitro5.py --dns          # capture DNS queries
    sudo python wifi_monitor_nitro5.py --dns -c creds.csv --connect
"""

from __future__ import annotations

import sys

MIN_PYTHON = (3, 9)
if sys.version_info < MIN_PYTHON:
    sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (found {sys.version}).")

import argparse
import atexit
import logging
import os
import select
import termios
import time
import tty
from datetime import datetime

from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table

from wifimonitor.wifi_common import (
    Network, KnownNetwork,
    RogueAlert,  # noqa: F401 — backward-compat re-export
    DeauthEvent,  # noqa: F401 — backward-compat re-export
    DeauthSummary,  # noqa: F401 — backward-compat re-export
    parse_airodump_csv,  # noqa: F401 — backward-compat re-export
    CommandRunner, SubprocessRunner,
    _minimal_env,  # noqa: F401 — backward-compat re-export
)
from wifimonitor.platform_detect import (
    detect_platform,
    list_wifi_interfaces,
    detect_best_interface,
)

# -- Defaults --
SCAN_INTERVAL = 10  # seconds between refreshes
LOG_FILENAME = "wifimonitor.log"
_LOGGER = logging.getLogger("wifi_monitor_nitro5")
_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# Credentials & nmcli connection (canonical: credentials.py)
# ---------------------------------------------------------------------------

from wifimonitor.credentials import (  # noqa: E402
    load_credentials,  # noqa: F401 — backward-compat re-export
    connect_wifi_nmcli,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# Known-good baseline & rogue AP detection (canonical: detection/rogue.py)
# ---------------------------------------------------------------------------

from wifimonitor.detection.rogue import (  # noqa: E402
    load_baseline,  # noqa: F401 — backward-compat re-export
    save_baseline,  # noqa: F401 — backward-compat re-export
    detect_rogue_aps,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# Deauth / disassoc capture & classification (canonical: capture/deauth.py)
# ---------------------------------------------------------------------------

from wifimonitor.capture.deauth import (  # noqa: E402
    parse_tcpdump_deauth_line,  # noqa: F401 — backward-compat re-export
    DeauthTracker,  # noqa: F401 — backward-compat re-export
    classify_deauth_events,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# DNS query capture (canonical: capture/dns.py)
# ---------------------------------------------------------------------------

from wifimonitor.capture.dns import (  # noqa: E402
    parse_tcpdump_dns_line,  # noqa: F401 — backward-compat re-export
    DnsTracker,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# ARP-based client detection (canonical: detection/arp.py)
# ---------------------------------------------------------------------------

from wifimonitor.detection.arp import (  # noqa: E402
    _get_connected_bssid,  # noqa: F401 — backward-compat re-export
    _get_subnet,  # noqa: F401 — backward-compat re-export
    _parse_arp_scan_output,  # noqa: F401 — backward-compat re-export
    _parse_nmap_output,  # noqa: F401 — backward-compat re-export
    ArpScanner,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# Monitor mode + airodump-ng (canonical: scanning/airodump.py)
# ---------------------------------------------------------------------------

from wifimonitor.scanning.airodump import (  # noqa: E402
    AirodumpScanner,  # noqa: F401 — backward-compat re-export
    AIRODUMP_PREFIX,  # noqa: F401 — backward-compat re-export
    AIRODUMP_STDERR_LOG,  # noqa: F401 — backward-compat re-export
    AIRODUMP_MONITOR_LOG,  # noqa: F401 — backward-compat re-export
    AIRODUMP_DEBUG_LOG,  # noqa: F401 — backward-compat re-export
    AIRODUMP_WRITE_INTERVAL,  # noqa: F401 — backward-compat re-export
    AIRODUMP_STARTUP_WAIT,  # noqa: F401 — backward-compat re-export
    _interface_supports_monitor,  # noqa: F401 — backward-compat re-export
    _set_nm_managed,  # noqa: F401 — backward-compat re-export
    _enable_monitor_mode,  # noqa: F401 — backward-compat re-export
    _verify_monitor_mode,  # noqa: F401 — backward-compat re-export
    _disable_monitor_mode,  # noqa: F401 — backward-compat re-export
    _log_airodump_exit,  # noqa: F401 — backward-compat re-export
    _log_monitor_failure,  # noqa: F401 — backward-compat re-export
    _enable_monitor_mode_virtual,  # noqa: F401 — backward-compat re-export
    _disable_monitor_mode_virtual,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# nmcli scanning — canonical implementation in wifimonitor.scanning.nmcli
# Re-exported here for backward compatibility during module decomposition.
# ---------------------------------------------------------------------------

from wifimonitor.scanning.nmcli import (  # noqa: E402
    scan_wifi_nmcli,
    parse_nmcli_output,  # noqa: F401 — backward-compat re-export
    _split_nmcli_line,  # noqa: F401 — backward-compat re-export
    _pct_to_dbm,  # noqa: F401 — backward-compat re-export
    _map_nmcli_security,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# Rich TUI rendering (canonical: display/tables.py)
# ---------------------------------------------------------------------------

from wifimonitor.display.tables import (  # noqa: E402
    _rich_color,  # noqa: F401 — backward-compat re-export
    _bar_string,  # noqa: F401 — backward-compat re-export
    build_interface_header,  # noqa: F401 — backward-compat re-export
    build_table,  # noqa: F401 — backward-compat re-export
    build_dns_table,  # noqa: F401 — backward-compat re-export
    build_rogue_table,  # noqa: F401 — backward-compat re-export
    build_deauth_table,  # noqa: F401 — backward-compat re-export
    build_deauth_summary_table,  # noqa: F401 — backward-compat re-export
)


# ---------------------------------------------------------------------------
# Protocol adapters (ScannerProtocol / RendererProtocol)
# ---------------------------------------------------------------------------

class NmcliScanner:
    """Scanner that uses nmcli to detect WiFi networks.

    Wraps :func:`scan_wifi_nmcli` into a class conforming to
    :class:`~wifimonitor.wifi_common.ScannerProtocol`.
    """

    def __init__(
        self,
        interface: str | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self._interface = interface
        self._runner = runner

    def scan(self) -> list[Network]:
        """Scan for WiFi networks via nmcli."""
        return scan_wifi_nmcli(self._interface, runner=self._runner)


class RichNetworkRenderer:
    """Renderer that builds a Rich Table of WiFi networks.

    Wraps :func:`build_table` into a class conforming to
    :class:`~wifimonitor.wifi_common.RendererProtocol`.
    """

    def render(
        self,
        networks: list[Network],
        *,
        credentials: dict[str, str] | None = None,
        credentials_by_bssid: dict[str, tuple[str, str]] | None = None,
        connected_bssid: str | None = None,
        caption_override: str | None = None,
    ) -> Table:
        """Render *networks* as a Rich Table."""
        return build_table(
            networks,
            credentials=credentials,
            credentials_by_bssid=credentials_by_bssid,
            caption_override=caption_override,
            connected_bssid=connected_bssid,
        )


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
    parser.add_argument(
        "--dns",
        action="store_true",
        help="capture and display DNS queries (requires root / tcpdump)",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="use monitor mode with airodump-ng to detect client counts per BSSID (requires root, compatible WiFi)",
    )
    parser.add_argument(
        "--arp",
        action="store_true",
        help="count clients on the connected network via ARP scanning (works on Intel WiFi, no monitor mode required)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logging for troubleshooting (e.g. client counts in monitor mode)",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="list detected WiFi interfaces and exit",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="JSON file with known-good SSID/BSSID/channel entries for rogue AP detection",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="save current scan results as a known-good baseline and exit",
    )
    return parser.parse_args(argv)


def _get_display_interfaces(
    args: argparse.Namespace,
    airodump_scanner: AirodumpScanner | None,
) -> str:
    """Return a concise label for the interface(s) used for scanning.

    Args:
        args: Parsed CLI args (interface may be set or None).
        airodump_scanner: Active airodump scanner if monitor mode, else None.

    Returns:
        Label such as "Interface: wlan0" or "Interface: all".
    """
    if airodump_scanner is not None:
        return f"Interface: {airodump_scanner.interface}"
    if args.interface:
        return f"Interface: {args.interface}"
    return "Interface: all"


def _select_next_network(
    networks: list[Network],
    credentials: dict[str, str] | None,
    credentials_by_bssid: dict[str, tuple[str, str]] | None,
    connected_bssid: str | None,
) -> Network | None:
    """Select the next available network to connect to.

    Order: (1) networks with credentials by signal descending, (2) open
    networks by signal descending (including open hidden with BSSID creds).
    Excludes the currently connected network.  "Next" = the network after
    current in this list, wrapping to first if at end or not connected.

    Args:
        networks: Scanned networks (any order).
        credentials: SSID -> passphrase dict, or None.
        credentials_by_bssid: BSSID -> (ssid, passphrase) for hidden, or None.
        connected_bssid: BSSID of currently connected network, or None.

    Returns:
        The next network to connect to, or None if none available.
    """
    _connected = connected_bssid.lower() if connected_bssid else None
    with_creds: list[Network] = []
    open_nets: list[Network] = []
    for net in networks:
        if net.ssid:
            if credentials and net.ssid in credentials:
                with_creds.append(net)
            elif net.security == "Open":
                open_nets.append(net)
        elif net.security == "Open" and credentials_by_bssid and net.bssid in credentials_by_bssid:
            open_nets.append(net)
        elif credentials_by_bssid and net.bssid in credentials_by_bssid:
            with_creds.append(net)
    with_creds.sort(key=lambda n: n.signal, reverse=True)
    open_nets.sort(key=lambda n: n.signal, reverse=True)
    ordered = with_creds + open_nets
    if not ordered:
        return None
    current_idx = -1
    for i, net in enumerate(ordered):
        if _connected and net.bssid == _connected:
            current_idx = i
            break
    next_idx = (current_idx + 1) % len(ordered)
    return ordered[next_idx]


def _wait_for_scan_interval_or_key(timeout_secs: float, fd: int) -> str | None:
    """Wait up to timeout_secs, returning the key pressed if any, else None.

    Uses select for non-blocking stdin check. Caller must have put fd
    in cbreak mode and must restore terminal settings on exit.
    """
    elapsed = 0.0
    interval = 0.25
    while elapsed < timeout_secs:
        r, _, _ = select.select([fd], [], [], min(interval, timeout_secs - elapsed))
        if r:
            try:
                key = sys.stdin.read(1)
                return key if key else None
            except (EOFError, OSError):
                return None
        elapsed += interval
    return None


def _setup_log_file(debug: bool) -> None:
    """Configure logging to wifimonitor.log in the current directory.

    Writes a session banner with timestamp at startup. All log output
    (and debug when --debug) goes to the file. When --debug, also
    logs to stderr.

    Args:
        debug: If True, set level to DEBUG and add stderr handler.
    """
    log_path = os.path.join(os.getcwd(), LOG_FILENAME)
    log_format = "%(asctime)s %(name)s: %(levelname)s: %(message)s"
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n=== WiFi Monitor session started {timestamp} ===\n")
        file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        root = logging.getLogger()
        root.addHandler(file_handler)
        root.setLevel(logging.DEBUG if debug else logging.INFO)
        if debug:
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.setFormatter(logging.Formatter(
                "%(name)s: %(levelname)s: %(message)s"
            ))
            stderr_handler.setLevel(logging.DEBUG)
            root.addHandler(stderr_handler)
        logging.getLogger("wifi_common").setLevel(logging.DEBUG if debug else logging.INFO)
        logging.getLogger("wifimonitor").setLevel(logging.DEBUG if debug else logging.INFO)
    except OSError:
        print(
            f"WARNING: Could not create log file {log_path} — continuing without file logging",
            file=sys.stderr,
        )


def _dump_startup_config(
    *,
    args: argparse.Namespace,
    monitor_interface: str | None,
    airodump_ok: bool,
    airodump_failure: str | None,
    dns_ok: bool | None,
    creds_count: int,
) -> None:
    """Log startup configuration to debug log (call only when --debug)."""
    _LOGGER.debug(
        "CLI: interface=%s monitor=%s dns=%s credentials=%s connect=%s debug=%s",
        args.interface,
        args.monitor,
        args.dns,
        args.credentials,
        args.connect,
        args.debug,
    )
    _LOGGER.debug(
        "monitor_interface=%s",
        monitor_interface,
    )
    _LOGGER.debug(
        "settings: SCAN_INTERVAL=%s AIRODUMP_WRITE_INTERVAL=%s AIRODUMP_STARTUP_WAIT=%s",
        SCAN_INTERVAL,
        AIRODUMP_WRITE_INTERVAL,
        AIRODUMP_STARTUP_WAIT,
    )
    _LOGGER.debug(
        "paths: prefix=%s stderr_log=%s monitor_log=%s debug_log=%s",
        AIRODUMP_PREFIX,
        AIRODUMP_STDERR_LOG,
        AIRODUMP_MONITOR_LOG,
        AIRODUMP_DEBUG_LOG,
    )
    _LOGGER.debug(
        "monitor_mode: enabled=%s ok=%s failure=%s",
        args.monitor,
        airodump_ok,
        airodump_failure,
    )
    _LOGGER.debug(
        "dns_capture: enabled=%s started=%s",
        args.dns,
        dns_ok,
    )
    _LOGGER.debug("credentials: loaded=%s", creds_count)
    _LOGGER.debug("auto_connect: enabled=%s", args.connect)


def main() -> None:
    """Run the WiFi monitor TUI loop.

    Handles KeyboardInterrupt (Ctrl+C) gracefully so the terminal is left
    clean when the user exits.
    """
    args = _parse_args()
    _setup_log_file(debug=args.debug)
    console = Console()

    # --list-devices: print detected WiFi interfaces and exit
    if args.list_devices:
        platform_type = detect_platform()
        console.print(f"[bold cyan]Platform:[/bold cyan] {platform_type}")
        devices = list_wifi_interfaces()
        if not devices:
            console.print("[yellow]No WiFi interfaces detected.[/yellow]")
            sys.exit(0)
        for dev in devices:
            monitor_label = "[green]yes[/green]" if dev.supports_monitor else "[red]no[/red]"
            up_label = "[green]up[/green]" if dev.is_up else "[yellow]down[/yellow]"
            console.print(
                f"  {dev.name}  driver={dev.driver}  "
                f"monitor={monitor_label}  state={up_label}"
            )
        best = detect_best_interface(devices, monitor_mode=False)
        if best:
            console.print(f"\n[bold]Recommended interface:[/bold] {best}")
        sys.exit(0)

    # --save-baseline: scan once, save results as baseline, and exit
    if args.save_baseline:
        networks = scan_wifi_nmcli(args.interface)
        count = save_baseline(args.save_baseline, networks)
        if count:
            console.print(
                f"[bold cyan]WiFi Monitor[/bold cyan] — "
                f"saved {count} network(s) to {args.save_baseline}"
            )
        else:
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                "[yellow]no networks saved (scan returned no results)[/yellow]"
            )
        sys.exit(0)

    # Auto-detect interface if not specified via -i
    if not args.interface:
        devices = list_wifi_interfaces()
        detected = detect_best_interface(devices, monitor_mode=args.monitor)
        if detected:
            args.interface = detected
            _LOGGER.debug("auto-detected interface: %s", detected)

    connected = False
    dns_tracker: DnsTracker | None = None
    deauth_tracker: DeauthTracker | None = None
    airodump_scanner: AirodumpScanner | None = None
    airodump_failure_reason: str | None = None
    arp_scanner: ArpScanner | None = None
    nmcli_scanner = NmcliScanner(interface=args.interface)
    renderer = RichNetworkRenderer()
    baseline: list[KnownNetwork] = []
    credentials_by_ssid: dict[str, str] | None = None
    credentials_by_bssid: dict[str, tuple[str, str]] | None = None

    if args.baseline:
        baseline = load_baseline(args.baseline)
        if baseline:
            console.print(
                f"[bold cyan]WiFi Monitor[/bold cyan] — "
                f"loaded {len(baseline)} known network(s) from {args.baseline}"
            )
        else:
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                f"[yellow]no known networks loaded from {args.baseline}[/yellow]"
            )

    if args.arp:
        arp_scanner = ArpScanner(interface=args.interface)
        console.print(
            "[bold cyan]WiFi Monitor[/bold cyan] — "
            "[green]ARP client detection enabled (connected network only)[/green]"
        )

    if args.monitor:
        monitor_interface = args.interface or "wlan0"
        airodump_scanner = AirodumpScanner(
            interface=monitor_interface, debug=args.debug
        )
        ok, failure_reason = airodump_scanner.start()
        if ok:
            atexit.register(airodump_scanner.stop)
            console.print(
                f"[bold cyan]WiFi Monitor[/bold cyan] — "
                f"[green]monitor mode on {monitor_interface}, client counts enabled[/green]"
            )
            # Start deauth frame capture on the monitor interface
            deauth_iface = getattr(
                airodump_scanner, "_monitor_interface", monitor_interface
            )
            deauth_tracker = DeauthTracker()
            if deauth_tracker.start(interface=deauth_iface):
                console.print(
                    "[bold cyan]WiFi Monitor[/bold cyan] — "
                    "[green]deauth frame capture started[/green]"
                )
            else:
                deauth_tracker = None
        else:
            if failure_reason == "monitor_unsupported":
                msg = "interface does not support monitor mode — try a USB WiFi adapter"
            elif failure_reason == "monitor_mode":
                msg = "monitor mode failed at iw/ip step — check /tmp/wifi_monitor_nitro5_monitor.log"
            elif failure_reason == "airodump_exit":
                msg = "airodump-ng exited — check /tmp/wifi_monitor_nitro5_airodump.log"
            else:
                msg = "airodump-ng/iw not found or no permission"
            console.print(
                "[bold cyan]WiFi Monitor[/bold cyan] — "
                f"[yellow]{msg} — falling back to nmcli[/yellow]"
            )
            airodump_failure_reason = failure_reason
            airodump_scanner = None

    if args.credentials:
        credentials_by_ssid, credentials_by_bssid = load_credentials(args.credentials)
        creds_count = len(credentials_by_ssid) + len(credentials_by_bssid)
        if creds_count:
            console.print(
                f"[bold cyan]WiFi Monitor[/bold cyan] — "
                f"loaded {creds_count} credential(s)"
            )
        else:
            credentials_by_ssid = None
            credentials_by_bssid = None
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

    if args.debug:
        _dump_startup_config(
            args=args,
            monitor_interface=args.interface or "wlan0" if args.monitor else None,
            airodump_ok=airodump_scanner is not None,
            airodump_failure=airodump_failure_reason,
            dns_ok=dns_tracker is not None if args.dns else None,
            creds_count=len(credentials_by_ssid or {}) + len(credentials_by_bssid or {}),
        )

    console.print("[bold cyan]WiFi Monitor[/bold cyan] — Acer Nitro 5")
    if airodump_scanner:
        console.print(f"Scanning {airodump_scanner.interface} (monitor mode)…\n")
    elif arp_scanner:
        console.print(
            f"Scanning {'all interfaces' if not args.interface else args.interface} (ARP client detection)…\n"
        )
    else:
        console.print(
            f"Scanning {'all interfaces' if not args.interface else args.interface}…\n"
        )

    prev_connected_bssid: str | None = None
    try:
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                caption_override: str | None = None
                if airodump_scanner is not None:
                    if not airodump_scanner.log_exit_if_dead():
                        _LOGGER.info(
                            "airodump exited during scan — see %s",
                            AIRODUMP_STDERR_LOG,
                        )
                        caption_override = (
                            f"airodump exited — nmcli fallback (check {AIRODUMP_STDERR_LOG})"
                        )
                        networks = nmcli_scanner.scan()
                    else:
                        networks = airodump_scanner.scan()
                else:
                    networks = nmcli_scanner.scan()

                connected_bssid = _get_connected_bssid(
                    args.interface, runner=_DEFAULT_RUNNER
                )
                if connected_bssid != prev_connected_bssid:
                    if dns_tracker is not None:
                        dns_tracker.reset()
                    prev_connected_bssid = connected_bssid

                if arp_scanner is not None:
                    arp_count = arp_scanner.scan()
                    if connected_bssid:
                        for net in networks:
                            if net.bssid == connected_bssid:
                                net.clients = arp_count
                                break

                network_table = renderer.render(
                    networks,
                    credentials=credentials_by_ssid,
                    credentials_by_bssid=credentials_by_bssid,
                    caption_override=caption_override,
                    connected_bssid=connected_bssid,
                )

                right_tables: list[Table] = []
                if baseline:
                    rogue_alerts = detect_rogue_aps(networks, baseline)
                    if rogue_alerts:
                        right_tables.append(build_rogue_table(rogue_alerts))

                if deauth_tracker is not None:
                    deauth_events = deauth_tracker.events()
                    if deauth_events:
                        right_tables.append(build_deauth_table(deauth_events))
                        summaries = classify_deauth_events(
                            deauth_events,
                            baseline=baseline or None,
                        )
                        if summaries:
                            right_tables.append(
                                build_deauth_summary_table(summaries)
                            )

                if dns_tracker is not None:
                    right_tables.append(build_dns_table(dns_tracker.top()))

                interface_header = build_interface_header(
                    _get_display_interfaces(args, airodump_scanner)
                )
                content: Table | Columns
                if right_tables:
                    content = Columns(
                        [network_table, Group(*right_tables)],
                        expand=True,
                        padding=(0, 2),
                    )
                else:
                    content = network_table
                live.update(Group(interface_header, content))

                # Auto-connect on first scan if requested
                # When monitor mode is active, the scan interface is in monitor mode
                # and cannot connect; use interface=None so nmcli picks a managed one.
                connect_iface = None if airodump_scanner else args.interface
                has_creds = bool(credentials_by_ssid or credentials_by_bssid)
                if args.connect and has_creds and not connected:
                    for net in networks:
                        if net.ssid and credentials_by_ssid and net.ssid in credentials_by_ssid:
                            ok = connect_wifi_nmcli(
                                net.ssid,
                                credentials_by_ssid[net.ssid],
                                interface=connect_iface,
                            )
                            if ok:
                                connected = True
                            break
                        elif not net.ssid and credentials_by_bssid and net.bssid in credentials_by_bssid:
                            ssid, passphrase = credentials_by_bssid[net.bssid]
                            ok = connect_wifi_nmcli(
                                ssid,
                                passphrase,
                                interface=connect_iface,
                                hidden=True,
                            )
                            if ok:
                                connected = True
                            break

                # Wait for scan interval, or keypress (e.g. 'n' to connect to next)
                if sys.stdin.isatty():
                    try:
                        fd = sys.stdin.fileno()
                        old_attrs = termios.tcgetattr(fd)
                        try:
                            tty.setcbreak(fd)
                            key = _wait_for_scan_interval_or_key(SCAN_INTERVAL, fd)
                            if key and key.lower() == "n":
                                next_net = _select_next_network(
                                    networks,
                                    credentials_by_ssid,
                                    credentials_by_bssid,
                                    connected_bssid,
                                )
                                if next_net:
                                    if next_net.ssid and credentials_by_ssid:
                                        passphrase = credentials_by_ssid.get(
                                            next_net.ssid, ""
                                        )
                                        connect_wifi_nmcli(
                                            next_net.ssid,
                                            passphrase,
                                            interface=connect_iface,
                                        )
                                    elif not next_net.ssid and credentials_by_bssid and next_net.bssid in credentials_by_bssid:
                                        ssid, passphrase = credentials_by_bssid[
                                            next_net.bssid
                                        ]
                                        connect_wifi_nmcli(
                                            ssid,
                                            passphrase,
                                            interface=connect_iface,
                                            hidden=True,
                                        )
                        finally:
                            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
                    except (termios.error, OSError):
                        time.sleep(SCAN_INTERVAL)
                else:
                    time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        if deauth_tracker is not None:
            deauth_tracker.stop()
        if dns_tracker is not None:
            dns_tracker.stop()
        if airodump_scanner is not None:
            airodump_scanner.stop()
            atexit.unregister(airodump_scanner.stop)
        console.print("\n[bold cyan]WiFi Monitor[/bold cyan] — stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
