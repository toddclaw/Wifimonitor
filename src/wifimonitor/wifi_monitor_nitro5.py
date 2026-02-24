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
import collections
import csv
import io
import json
from datetime import datetime
import glob
import logging
import os
import re
import signal
import stat
import subprocess
import threading
import time

from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.table import Table

from wifimonitor.wifi_common import (
    Network, KnownNetwork, RogueAlert, DeauthEvent, parse_airodump_csv,
    signal_to_bars, signal_color, security_color,
    COLOR_TO_RICH,
    CommandRunner, SubprocessRunner,
)
from wifimonitor.platform_detect import (
    detect_platform,
    list_wifi_interfaces,
    detect_best_interface,
)

# -- Defaults --
SCAN_INTERVAL = 10  # seconds between refreshes
_LOGGER = logging.getLogger("wifi_monitor_nitro5")
AIRODUMP_PREFIX = "/tmp/wifi_monitor_nitro5"
AIRODUMP_STDERR_LOG = "/tmp/wifi_monitor_nitro5_airodump.log"
AIRODUMP_MONITOR_LOG = "/tmp/wifi_monitor_nitro5_monitor.log"
AIRODUMP_DEBUG_LOG = "/tmp/wifi_monitor_nitro5_debug.log"
AIRODUMP_WRITE_INTERVAL = 5
AIRODUMP_STARTUP_WAIT = 6  # wait for first CSV write (airodump --write-interval is 5s)
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
# Known-good baseline (rogue AP detection)
# ---------------------------------------------------------------------------


def load_baseline(filepath: str) -> list[KnownNetwork]:
    """Load a known-good network baseline from a JSON file.

    Args:
        filepath: Path to the JSON baseline file.

    Returns:
        List of :class:`KnownNetwork` objects.  Returns an empty list if the
        file is missing, unreadable, or contains invalid JSON.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        _LOGGER.warning("baseline: failed to load %s: %s", filepath, exc)
        return []

    if not isinstance(data, list):
        _LOGGER.warning("baseline: expected a JSON array in %s", filepath)
        return []

    # Check file permissions (warn if world-writable)
    try:
        mode = os.stat(filepath).st_mode
        if mode & stat.S_IWOTH:
            import sys
            print(
                f"WARNING: baseline file {filepath!r} is world-writable "
                "(chmod 600 recommended)",
                file=sys.stderr,
            )
    except OSError:
        pass

    result: list[KnownNetwork] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            _LOGGER.debug("baseline: skipping non-dict entry at index %d", i)
            continue
        ssid = entry.get("ssid")
        bssid = entry.get("bssid")
        if not ssid or not bssid:
            _LOGGER.debug("baseline: skipping entry at index %d (missing ssid/bssid)", i)
            continue
        channel = entry.get("channel", 0)
        if not isinstance(channel, int):
            channel = 0
        result.append(KnownNetwork(
            ssid=str(ssid),
            bssid=str(bssid).lower(),
            channel=channel,
        ))

    _LOGGER.debug("baseline: loaded %d known networks from %s", len(result), filepath)
    return result


def save_baseline(filepath: str, networks: list[Network]) -> int:
    """Save scanned networks as a known-good baseline JSON file.

    Args:
        filepath: Path to write the JSON baseline file.
        networks: List of scanned networks to save.

    Returns:
        Number of networks written.  Returns 0 if writing fails.
    """
    data = [
        {
            "ssid": net.ssid,
            "bssid": net.bssid.lower(),
            "channel": net.channel,
        }
        for net in networks
        if net.ssid  # skip hidden networks
    ]
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    except OSError as exc:
        _LOGGER.warning("baseline: failed to write %s: %s", filepath, exc)
        return 0

    _LOGGER.debug("baseline: saved %d networks to %s", len(data), filepath)
    return len(data)


# ---------------------------------------------------------------------------
# Rogue AP detection
# ---------------------------------------------------------------------------


def detect_rogue_aps(
    networks: list[Network],
    baseline: list[KnownNetwork],
) -> list[RogueAlert]:
    """Compare scanned networks against a known-good baseline.

    For each scanned network whose SSID appears in the baseline, checks:

    1. **Unknown BSSID** — the SSID is known but this BSSID is not in the
       baseline → ``reason="unknown_bssid"``.
    2. **Unexpected channel** — the BSSID *is* known but the channel does
       not match (and the baseline channel is not 0, which means "any") →
       ``reason="unexpected_channel"``.

    Networks whose SSID is *not* in the baseline (or that have an empty
    SSID) are silently ignored — they are not tracked.

    Args:
        networks: Current scan results.
        baseline: Known-good SSID/BSSID/channel tuples.

    Returns:
        A list of :class:`RogueAlert` objects (may be empty).
    """
    if not networks or not baseline:
        return []

    # Build lookup: ssid -> {bssid: channel, ...}
    ssid_to_bssids: dict[str, dict[str, int]] = {}
    for kn in baseline:
        ssid_to_bssids.setdefault(kn.ssid, {})[kn.bssid.lower()] = kn.channel

    alerts: list[RogueAlert] = []
    for net in networks:
        if not net.ssid:
            continue  # hidden — skip
        known = ssid_to_bssids.get(net.ssid)
        if known is None:
            continue  # SSID not in baseline — not tracked

        expected_bssids = sorted(known.keys())
        expected_channels = sorted(known.values())
        bssid_lower = net.bssid.lower()

        if bssid_lower not in known:
            alerts.append(RogueAlert(
                network=net,
                reason="unknown_bssid",
                expected_bssids=expected_bssids,
                expected_channels=expected_channels,
            ))
        else:
            baseline_channel = known[bssid_lower]
            if (
                baseline_channel != 0
                and net.channel != 0
                and net.channel != baseline_channel
            ):
                alerts.append(RogueAlert(
                    network=net,
                    reason="unexpected_channel",
                    expected_bssids=expected_bssids,
                    expected_channels=expected_channels,
                ))

    return alerts


# ---------------------------------------------------------------------------
# Deauth / disassoc frame parsing (tcpdump -e on monitor interface)
# ---------------------------------------------------------------------------

# Typical tcpdump -e output on a monitor interface:
#   11:04:34.360700 314us BSSID:00:14:6c:7e:40:80 DA:00:0f:b5:46:11:19
#   SA:00:14:6c:7e:40:80 DeAuthentication: Class 3 frame received …
_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_DEAUTH_RE = re.compile(
    rf"BSSID:(?P<bssid>{_MAC})\s+"
    rf"DA:(?P<da>{_MAC})\s+"
    rf"SA:(?P<sa>{_MAC})\s+"
    rf"(?P<type>DeAuthentication|Disassociation):\s*(?P<reason>.*)",
)


def parse_tcpdump_deauth_line(line: str) -> DeauthEvent | None:
    """Extract a deauth/disassoc event from a tcpdump ``-e`` output line.

    Returns a :class:`DeauthEvent` if the line describes a
    DeAuthentication or Disassociation frame, otherwise ``None``.
    """
    match = _DEAUTH_RE.search(line)
    if not match:
        return None
    subtype = "deauth" if match.group("type") == "DeAuthentication" else "disassoc"
    return DeauthEvent(
        bssid=match.group("bssid").lower(),
        source=match.group("sa").lower(),
        destination=match.group("da").lower(),
        reason=match.group("reason").strip(),
        subtype=subtype,
    )


class DeauthTracker:
    """Thread-safe deauthentication/disassociation frame tracker.

    Uses a background thread to read tcpdump output capturing 802.11
    management frames (deauth and disassoc) on a monitor-mode interface.
    Call ``start(interface)`` to begin capture and ``stop()`` to terminate.
    Use ``events(n)`` to retrieve the *n* most recent events.

    Args:
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or _DEFAULT_RUNNER
        self._events: list[DeauthEvent] = []
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

    def record(self, event: DeauthEvent) -> None:
        """Append *event* to the event list (thread-safe)."""
        with self._lock:
            self._events.append(event)

    def events(self, n: int = 20) -> list[DeauthEvent]:
        """Return the *n* most recent events, newest first."""
        with self._lock:
            return list(reversed(self._events[-n:]))

    def start(self, interface: str) -> bool:
        """Start capturing deauth/disassoc frames via tcpdump.

        Args:
            interface: Monitor-mode interface name (e.g. ``mon0``).

        Returns:
            True if tcpdump was launched successfully, False otherwise.
        """
        cmd = [
            "tcpdump", "-l", "-e", "-i", interface,
            "type", "mgt", "subtype", "deauth",
            "or",
            "type", "mgt", "subtype", "disassoc",
        ]
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
        """Read deauth/disassoc frames from tcpdump stdout (background thread)."""
        try:
            assert self._process is not None and self._process.stdout is not None
            for line in self._process.stdout:
                event = parse_tcpdump_deauth_line(line)
                if event:
                    self.record(event)
        except (ValueError, OSError):
            pass  # Process was terminated


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


# ---------------------------------------------------------------------------
# ARP-based client detection (works on any adapter, including Intel)
# ---------------------------------------------------------------------------

def _get_connected_bssid(
    interface: str | None = None,
    *,
    runner: CommandRunner | None = None,
) -> str | None:
    """Return the BSSID of the currently connected WiFi network, or None.

    Uses ``nmcli -t -f ACTIVE,BSSID device wifi list`` to find the active
    entry.  Returns a lowercase BSSID string or None if not connected.

    Args:
        interface: Optional wireless interface name.
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmd = ["nmcli", "-t", "-f", "ACTIVE,BSSID", "device", "wifi", "list"]
    if interface:
        cmd += ["ifname", interface]
    try:
        result = runner.run(cmd, capture_output=True, text=True, timeout=10, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    for line in result.stdout.strip().splitlines():
        fields = _split_nmcli_line(line.strip())
        if len(fields) >= 2 and fields[0].lower() == "yes":
            return fields[1].lower()
    return None


def _get_subnet(
    interface: str | None = None,
    *,
    runner: CommandRunner | None = None,
) -> str | None:
    """Return the local subnet in CIDR notation for the given interface.

    Runs ``ip -4 route show dev <interface>`` and extracts the first
    ``proto kernel scope link`` route, e.g. ``192.168.1.0/24``.
    Returns None if not connected or command fails.

    Args:
        interface: Optional wireless interface name.
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmd = ["ip", "-4", "route"]
    if interface:
        cmd += ["show", "dev", interface]
    try:
        result = runner.run(cmd, capture_output=True, text=True, timeout=5, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    subnet_re = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s')
    for line in result.stdout.strip().splitlines():
        m = subnet_re.match(line.strip())
        if m:
            return m.group(1)
    return None


_ARP_HOST_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\s+[0-9a-f]{2}(?::[0-9a-f]{2}){5}', re.I)


def _parse_arp_scan_output(output: str) -> int:
    """Count unique responding hosts from arp-scan output.

    Args:
        output: Raw stdout from ``arp-scan --localnet``.

    Returns:
        Number of unique IP addresses that responded.
    """
    return sum(1 for line in output.splitlines() if _ARP_HOST_RE.match(line.strip()))


def _parse_nmap_output(output: str) -> int:
    """Count hosts from nmap greppable output (``nmap -sn -oG -``).

    Args:
        output: Raw stdout from ``nmap -sn ... -oG -``.

    Returns:
        Number of hosts with ``Status: Up``.
    """
    return sum(
        1 for line in output.splitlines()
        if line.startswith("Host:") and "Status: Up" in line
    )


class ArpScanner:
    """Detect active clients on the connected subnet via ARP scanning.

    Uses ``arp-scan --localnet`` when available (requires root); falls back
    to ``nmap -sn`` otherwise.  Returns the count of responding hosts so
    the caller can apply it to the connected network's BSSID.

    Args:
        interface: Optional wireless interface name to scan on.
        runner: Optional CommandRunner for subprocess calls (testing seam).
    """

    def __init__(
        self,
        interface: str | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self._interface = interface
        self._runner = runner or _DEFAULT_RUNNER

    def scan(self) -> int:
        """Return the count of active hosts on the connected subnet.

        Tries ``arp-scan`` first, falls back to ``nmap``.  Returns 0 on
        any failure so the caller degrades gracefully.
        """
        count = self._scan_arp()
        if count is not None:
            return count
        count = self._scan_nmap()
        return count if count is not None else 0

    def _scan_arp(self) -> int | None:
        """Run arp-scan and return host count, or None if unavailable."""
        cmd = ["arp-scan", "--localnet", "-q"]
        if self._interface:
            cmd += ["-I", self._interface]
        env = _minimal_env()
        try:
            result = self._runner.run(
                cmd, capture_output=True, text=True, timeout=30, env=env
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        except FileNotFoundError:
            return None  # arp-scan not installed
        if result.returncode not in (0, 1):  # arp-scan exits 1 on partial results
            return None
        return _parse_arp_scan_output(result.stdout)

    def _scan_nmap(self) -> int | None:
        """Run nmap -sn as a fallback and return host count, or None."""
        subnet = _get_subnet(self._interface, runner=self._runner)
        if not subnet:
            return None
        cmd = ["nmap", "-sn", subnet, "-oG", "-"]
        env = _minimal_env()
        try:
            result = self._runner.run(
                cmd, capture_output=True, text=True, timeout=60, env=env
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None
        return _parse_nmap_output(result.stdout)


# ---------------------------------------------------------------------------
# Monitor mode + airodump-ng (client count per BSSID)
# ---------------------------------------------------------------------------

def _interface_supports_monitor(interface: str, runner: CommandRunner | None = None) -> bool:
    """Check if the interface's phy supports monitor mode via iw list.

    Returns True if monitor mode is in supported interface modes, or if
    we cannot determine (e.g. iw not found) — in that case we allow the attempt.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        # Get wiphy index for this interface
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            return True  # Allow attempt; will fail later with diagnostics
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        match = re.search(r"wiphy\s+(\d+)", out)
        if not match:
            return True
        wiphy = match.group(1)
        # Check phy's supported interface modes
        phy_result = runner.run(
            ["iw", "phy", f"phy{wiphy}", "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if phy_result.returncode != 0:
            return True
        phy_out = phy_result.stdout if isinstance(phy_result.stdout, str) else phy_result.stdout.decode("utf-8", errors="replace")
        # Look for "Supported interface modes" section and check for monitor
        in_modes = False
        for line in phy_out.splitlines():
            if "Supported interface modes" in line:
                in_modes = True
                continue
            if in_modes:
                if re.match(r"\s+Band\s+", line) or re.match(r"\s+max #", line):
                    break  # Next section
                if "monitor" in line.lower():
                    return True
        return False  # Found modes section but no monitor
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True  # Allow attempt


def _set_nm_managed(interface: str, managed: bool, runner: CommandRunner | None = None) -> bool:
    """Tell NetworkManager to manage or unmanage the interface.

    Prevents NetworkManager from reclaiming the interface during monitor mode.
    Returns True if nmcli succeeded, False otherwise.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        result = runner.run(
            ["nmcli", "device", "set", interface, "managed", "yes" if managed else "no"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _enable_monitor_mode(interface: str, runner: CommandRunner | None = None) -> bool:
    """Put a WiFi interface into monitor mode using iw.

    Asks NetworkManager to unmanage the interface first so it does not reclaim it.
    Returns True if successful, False otherwise.
    On failure, logs the failing command and its stderr/stdout to AIRODUMP_MONITOR_LOG.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        runner.run(
            ["nmcli", "device", "disconnect", interface],
            capture_output=True,
            timeout=5,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    if not _set_nm_managed(interface, False, runner):
        _log_monitor_failure(
            f"nmcli device set {interface} managed no failed — NetworkManager may reclaim the interface",
            None,
            None,
            None,
        )
        return False
    time.sleep(0.5)
    cmds = [
        ["sudo", "ip", "link", "set", interface, "down"],
        ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
        ["sudo", "ip", "link", "set", interface, "up"],
    ]
    iw_set_type_returncode: int | None = None
    try:
        for cmd in cmds:
            result = runner.run(cmd, capture_output=True, timeout=10, env=env)
            if ["sudo", "iw", "dev", interface, "set", "type", "monitor"] == cmd:
                iw_set_type_returncode = result.returncode
            if result.returncode != 0:
                _log_monitor_failure(
                    f"Command failed: {' '.join(cmd)}",
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
                return False
        if not _verify_monitor_mode(interface, runner, iw_set_type_returncode):
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log_monitor_failure(
            f"Exception running monitor mode command: {e!r}",
            None,
            None,
            None,
        )
        return False


def _verify_monitor_mode(
    interface: str,
    runner: CommandRunner | None = None,
    iw_set_type_returncode: int | None = None,
) -> bool:
    """Verify the interface is actually in monitor mode via iw dev info."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            _log_monitor_failure(
                f"iw dev {interface} info failed",
                result.returncode,
                result.stdout,
                result.stderr,
            )
            return False
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        if "type monitor" not in out:
            hints: list[str] = []
            if iw_set_type_returncode == 0:
                hints.append(
                    "Driver may not actually support monitor mode (common with Intel laptop WiFi). "
                    "Try a USB adapter (Atheros AR9271, Ralink RT3070)."
                )
            hints.append(
                f"For permanent unmanage: add unmanaged-devices=interface-name:{interface} "
                f"to /etc/NetworkManager/conf.d/monitor.conf and reboot."
            )
            msg = (
                f"Interface {interface} is not type monitor (iw output: {out!r}). "
                + " ".join(hints)
            )
            _log_monitor_failure(msg, None, None, None)
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log_monitor_failure(
            f"Exception verifying monitor mode: {e!r}",
            None,
            None,
            None,
        )
        return False


def _log_airodump_exit(
    returncode: int | None,
    cmd: list[str],
    stderr_file: io.TextIOWrapper | None,
) -> None:
    """Append airodump exit diagnosis to the stderr log for debugging."""
    try:
        if stderr_file is not None:
            stderr_file.flush()
        with open(AIRODUMP_STDERR_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n[airodump exited] returncode={returncode}\n")
            f.write(f"[command] {' '.join(cmd)}\n")
    except OSError:
        pass


def _log_monitor_failure(
    msg: str,
    returncode: int | None,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
) -> None:
    """Write monitor mode failure details to AIRODUMP_MONITOR_LOG."""
    def _decode(v: str | bytes | None) -> str:
        if v is None:
            return "(none)"
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="replace")
        return v

    try:
        with open(AIRODUMP_MONITOR_LOG, "a", encoding="utf-8") as f:
            f.write(f"[monitor] {msg}\n")
            if returncode is not None:
                f.write(f"  returncode: {returncode}\n")
            out = _decode(stdout)
            err = _decode(stderr)
            if out.strip():
                f.write(f"  stdout: {out}\n")
            if err.strip():
                f.write(f"  stderr: {err}\n")
            f.write("\n")
    except OSError:
        pass


def _disable_monitor_mode(interface: str, runner: CommandRunner | None = None) -> None:
    """Restore a WiFi interface to managed mode and give it back to NetworkManager."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmds = [
        ["sudo", "ip", "link", "set", interface, "down"],
        ["sudo", "iw", "dev", interface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", interface, "up"],
    ]
    for cmd in cmds:
        try:
            runner.run(cmd, capture_output=True, timeout=10, env=env)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    _set_nm_managed(interface, True, runner)


def _enable_monitor_mode_virtual(
    interface: str, runner: CommandRunner | None = None
) -> str | None:
    """Create a new virtual monitor interface via iw phy interface add.

    Leaves the original interface in managed mode; avoids NetworkManager reclaim.
    Returns the monitor interface name (e.g. 'mon0') on success, None on failure.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    mon_name = "mon0"
    try:
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            return None
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        match = re.search(r"wiphy\s+(\d+)", out)
        if not match:
            return None
        wiphy = match.group(1)
        result = runner.run(
            ["sudo", "iw", "phy", f"phy{wiphy}", "interface", "add", mon_name, "type", "monitor"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            return None
        result = runner.run(
            ["sudo", "ip", "link", "set", mon_name, "up"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            try:
                runner.run(
                    ["sudo", "iw", "dev", mon_name, "del"],
                    capture_output=True,
                    timeout=5,
                    env=env,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            return None
        return mon_name
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _disable_monitor_mode_virtual(
    mon_interface: str, runner: CommandRunner | None = None
) -> None:
    """Remove a virtual monitor interface created by _enable_monitor_mode_virtual."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        runner.run(
            ["sudo", "iw", "dev", mon_interface, "del"],
            capture_output=True,
            timeout=10,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


class AirodumpScanner:
    """Manage an airodump-ng process and parse its CSV for client counts.

    Use start() to enable monitor mode and launch airodump-ng, scan() to read
    the latest CSV and return networks with client counts, and stop() to clean up.
    """

    def __init__(
        self,
        interface: str,
        prefix: str = AIRODUMP_PREFIX,
        runner: CommandRunner | None = None,
        *,
        debug: bool = False,
    ) -> None:
        self.interface = interface
        self.prefix = prefix
        self._runner = runner or _DEFAULT_RUNNER
        self._proc: subprocess.Popen[bytes] | None = None
        self._monitor_enabled = False
        self._monitor_interface = interface
        self._monitor_is_virtual = False
        self._debug = debug
        self._stderr_file: io.TextIOWrapper | None = None
        self._last_cmd: list[str] = []
        self._exit_logged = False
        self._channels: list[int] = []

    def start(self) -> tuple[bool, str | None]:
        """Enable monitor mode and start airodump-ng.

        Tries virtual monitor interface first (iw phy interface add); falls back
        to converting the existing interface (iw dev set type monitor).

        Returns:
            (True, None) if successful.
            (False, reason) on failure. reason is "monitor_mode" if iw/ip failed,
            "airodump_exit" if airodump exited immediately, or "airodump_spawn"
            if airodump could not be started (FileNotFoundError, etc.).
        """
        supports_monitor = _interface_supports_monitor(
            self.interface, self._runner
        )
        if self._debug:
            _LOGGER.debug(
                "_interface_supports_monitor(%s)=%s",
                self.interface,
                supports_monitor,
            )
        if not supports_monitor:
            return False, "monitor_unsupported"

        # Pre-scan while the interface is still in managed mode to discover which
        # channels visible APs are on.  Passing these to airodump-ng via -c keeps it
        # focused on those channels rather than hopping all 40+ channels with --band abg.
        # Staying on the relevant channels dramatically increases the chance of capturing
        # the data/management frames that reveal client associations.
        _pre_networks = scan_wifi_nmcli(interface=self.interface, runner=self._runner)
        self._channels = sorted(set(n.channel for n in _pre_networks if n.channel > 0))
        if self._debug:
            _LOGGER.debug(
                "pre-scan: %d channel(s) discovered: %s",
                len(self._channels),
                self._channels,
            )

        try:
            self._runner.run(
                ["rfkill", "unblock", "wifi"],
                capture_output=True,
                timeout=5,
                env=_minimal_env(),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        mon_iface = _enable_monitor_mode_virtual(self.interface, self._runner)
        if mon_iface is not None:
            self._monitor_interface = mon_iface
            self._monitor_is_virtual = True
            self._monitor_enabled = True
            if self._debug:
                _LOGGER.debug(
                    "virtual monitor: success monitor_interface=%s",
                    self._monitor_interface,
                )
        else:
            if self._debug:
                _LOGGER.debug(
                    "virtual monitor: failed, trying direct monitor on %s",
                    self.interface,
                )
            if not _enable_monitor_mode(self.interface, self._runner):
                return False, "monitor_mode"
            self._monitor_interface = self.interface
            self._monitor_is_virtual = False
            self._monitor_enabled = True
            if self._debug:
                _LOGGER.debug(
                    "direct monitor: success monitor_interface=%s",
                    self._monitor_interface,
                )
        self._cleanup_old_files()
        env = _minimal_env()
        if os.geteuid() == 0:
            airodump_cmd: tuple[str, ...] = ("airodump-ng",)
        else:
            airodump_cmd = ("sudo", "airodump-ng")
        # Use discovered channels for targeted scanning; fall back to all bands if
        # the pre-scan returned nothing (e.g. nmcli not available, root required).
        if self._channels:
            channel_arg = ["-c", ",".join(str(c) for c in self._channels)]
        else:
            channel_arg = ["--band", "abg"]
        cmd = [
            *airodump_cmd,
            self._monitor_interface,
            *channel_arg,
            "--write", self.prefix,
            "--output-format", "csv",
            "--write-interval", str(AIRODUMP_WRITE_INTERVAL),
            "--hoptime", "500",
            "--background", "1",
        ]
        stderr_dest: int | io.TextIOWrapper = subprocess.DEVNULL
        try:
            self._stderr_file = open(AIRODUMP_STDERR_LOG, "w", encoding="utf-8")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._stderr_file.write(
                f"[{ts}] wifi_monitor_nitro5: capturing airodump-ng stderr\n"
            )
            self._stderr_file.write(f"[command] {' '.join(cmd)}\n")
            self._stderr_file.flush()
            stderr_dest = self._stderr_file
            if self._debug:
                _LOGGER.debug(
                    "airodump stderr -> %s | cwd=/tmp | prefix=%s",
                    AIRODUMP_STDERR_LOG,
                    self.prefix,
                )
                _LOGGER.debug("airodump command: %s", " ".join(cmd))
        except OSError:
            pass
        self._last_cmd = cmd
        try:
            self._proc = self._runner.popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_dest,
                stdin=subprocess.DEVNULL,
                env=env,
                cwd="/tmp",
                text=False,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError):
            self.stop()
            return False, "airodump_spawn"
        time.sleep(AIRODUMP_STARTUP_WAIT)
        if self._proc.poll() is not None:
            _log_airodump_exit(self._proc.returncode, cmd, self._stderr_file)
            _LOGGER.debug(
                "airodump exited with code %s (see %s)",
                self._proc.returncode,
                AIRODUMP_STDERR_LOG,
            )
            self.stop()
            return False, "airodump_exit"
        return True, None

    def stop(self) -> None:
        """Stop airodump-ng and restore managed mode."""
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None
        if self._monitor_enabled:
            if self._monitor_is_virtual:
                _disable_monitor_mode_virtual(self._monitor_interface, self._runner)
            else:
                _disable_monitor_mode(self._monitor_interface, self._runner)
            self._monitor_enabled = False
        self._cleanup_old_files()

    def is_alive(self) -> bool:
        """Return True if the airodump process is still running."""
        return self._proc is not None and self._proc.poll() is None

    def log_exit_if_dead(self) -> bool:
        """If the process has exited, append diagnosis to the log (once). Returns False if dead."""
        if self._proc is None or self._proc.poll() is None:
            return True
        if not self._exit_logged:
            _log_airodump_exit(self._proc.returncode, self._last_cmd, self._stderr_file)
            self._exit_logged = True
        return False

    def scan(self) -> list[Network]:
        """Read the latest airodump-ng CSV and return networks with client counts.

        When using a virtual monitor interface (mon0), the original interface
        (e.g. wlp4s0) stays in managed mode. In that case, use nmcli to get the
        full BSSID list and overlay client counts from airodump. This avoids the
        limited AP visibility that monitor mode often has on laptop WiFi.
        """
        csv_path = self._latest_csv()
        client_counts: dict[str, int] = {}
        airodump_networks: list[Network] = []

        if csv_path:
            try:
                with open(csv_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                airodump_networks, client_counts = parse_airodump_csv(content)
            except OSError:
                if self._debug:
                    _LOGGER.debug("scan failed to read %s", csv_path)

        if self._monitor_is_virtual:
            # Original interface is still managed: use nmcli for full BSSID list.
            networks = scan_wifi_nmcli(
                interface=self.interface, runner=self._runner
            )
            for net in networks:
                net.clients = client_counts.get(net.bssid, 0)
            if self._debug:
                _LOGGER.debug(
                    "hybrid scan: nmcli=%d networks, airodump clients for %d BSSIDs",
                    len(networks),
                    len(client_counts),
                )
            return networks

        # Direct monitor mode: airodump-only.
        if not csv_path:
            return []

        if self._debug:
            glob_pattern = f"{self.prefix}-*.csv"
            files = sorted(glob.glob(glob_pattern))
            total_clients = sum(client_counts.values())
            _LOGGER.debug(
                "scan glob pattern=%s files=%s",
                glob_pattern,
                files if files else "none",
            )
            _LOGGER.debug(
                "scan selected_csv=%s",
                csv_path,
            )
            _LOGGER.debug(
                "scan parse: networks=%d clients_total=%d client_counts=%s",
                len(airodump_networks),
                total_clients,
                dict(client_counts),
            )
            for i, net in enumerate(airodump_networks[:10]):
                ssid_display = net.ssid if net.ssid else "<hidden>"
                _LOGGER.debug(
                    "scan network[%d]: bssid=%s ssid=%s ch=%s signal=%s clients=%s",
                    i,
                    net.bssid,
                    ssid_display,
                    net.channel,
                    net.signal,
                    net.clients,
                )
            if len(airodump_networks) > 10:
                _LOGGER.debug(
                    "scan ... and %d more networks (truncated)",
                    len(airodump_networks) - 10,
                )

        return airodump_networks

    def _latest_csv(self) -> str | None:
        files = sorted(glob.glob(f"{self.prefix}-*.csv"))
        return files[-1] if files else None

    def _cleanup_old_files(self) -> None:
        for path in glob.glob(f"{self.prefix}-*"):
            try:
                os.remove(path)
            except OSError:
                pass


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
        connected_bssid: str | None = None,
        caption_override: str | None = None,
    ) -> Table:
        """Render *networks* as a Rich Table."""
        return build_table(
            networks,
            credentials=credentials,
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
    if args.debug:
        log_format = "%(name)s: %(levelname)s: %(message)s"
        logging.basicConfig(
            level=logging.DEBUG,
            format=log_format,
            stream=sys.stderr,
        )
        logging.getLogger("wifi_common").setLevel(logging.DEBUG)
        logging.getLogger("wifi_monitor_nitro5").setLevel(logging.DEBUG)
        try:
            file_handler = logging.FileHandler(
                AIRODUMP_DEBUG_LOG, mode="a", encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
        except OSError:
            pass  # Debug log file optional; stderr still works
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

    credentials: dict[str, str] | None = None
    connected = False
    dns_tracker: DnsTracker | None = None
    airodump_scanner: AirodumpScanner | None = None
    airodump_failure_reason: str | None = None
    arp_scanner: ArpScanner | None = None
    nmcli_scanner = NmcliScanner(interface=args.interface)
    renderer = RichNetworkRenderer()
    baseline: list[KnownNetwork] = []

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

    if args.debug:
        _dump_startup_config(
            args=args,
            monitor_interface=args.interface or "wlan0" if args.monitor else None,
            airodump_ok=airodump_scanner is not None,
            airodump_failure=airodump_failure_reason,
            dns_ok=dns_tracker is not None if args.dns else None,
            creds_count=len(credentials) if credentials else 0,
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

                if arp_scanner is not None:
                    arp_count = arp_scanner.scan()
                    if connected_bssid:
                        for net in networks:
                            if net.bssid == connected_bssid:
                                net.clients = arp_count
                                break

                network_table = renderer.render(
                    networks,
                    credentials=credentials,
                    caption_override=caption_override,
                    connected_bssid=connected_bssid,
                )

                tables: list[Table] = [network_table]

                if baseline:
                    rogue_alerts = detect_rogue_aps(networks, baseline)
                    if rogue_alerts:
                        tables.append(build_rogue_table(rogue_alerts))

                if dns_tracker is not None:
                    tables.append(build_dns_table(dns_tracker.top()))

                live.update(Group(*tables) if len(tables) > 1 else tables[0])

                # Auto-connect on first scan if requested
                # When monitor mode is active, the scan interface is in monitor mode
                # and cannot connect; use interface=None so nmcli picks a managed one.
                if args.connect and credentials and not connected:
                    connect_iface = None if airodump_scanner else args.interface
                    for net in networks:
                        if net.ssid and net.ssid in credentials:
                            ok = connect_wifi_nmcli(
                                net.ssid,
                                credentials[net.ssid],
                                interface=connect_iface,
                            )
                            if ok:
                                connected = True
                            break

                time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        if dns_tracker is not None:
            dns_tracker.stop()
        if airodump_scanner is not None:
            airodump_scanner.stop()
            atexit.unregister(airodump_scanner.stop)
        console.print("\n[bold cyan]WiFi Monitor[/bold cyan] — stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
