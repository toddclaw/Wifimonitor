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

from wifi_common import (
    Network, parse_airodump_csv, signal_to_bars, signal_color, security_color,
    COLOR_TO_RICH,
    CommandRunner, SubprocessRunner,
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
        cmd = [
            *airodump_cmd,
            self._monitor_interface,
            "--band", "abg",
            "--write", self.prefix,
            "--output-format", "csv",
            "--write-interval", str(AIRODUMP_WRITE_INTERVAL),
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
                env=env,
                cwd="/tmp",
                text=False,
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
        """Read the latest airodump-ng CSV and return networks with client counts."""
        glob_pattern = f"{self.prefix}-*.csv"
        files = sorted(glob.glob(glob_pattern))
        csv_path = self._latest_csv()

        if self._debug:
            _LOGGER.debug(
                "scan glob pattern=%s files=%s",
                glob_pattern,
                files if files else "none",
            )
            _LOGGER.debug(
                "scan selected_csv=%s",
                csv_path if csv_path else "none - no CSV",
            )

        if not csv_path:
            return []

        try:
            with open(csv_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            if self._debug:
                _LOGGER.debug("scan failed to read %s", csv_path)
            return []

        networks, client_counts = parse_airodump_csv(content)
        total_clients = sum(client_counts.values())

        if self._debug:
            _LOGGER.debug(
                "scan parse: csv_size=%d bytes networks=%d clients_total=%d client_counts=%s",
                len(content),
                len(networks),
                total_clients,
                dict(client_counts),
            )
            for i, net in enumerate(networks[:10]):
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
            if len(networks) > 10:
                _LOGGER.debug(
                    "scan ... and %d more networks (truncated)",
                    len(networks) - 10,
                )

        return networks

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
) -> Table:
    """Build a Rich Table displaying the scanned networks.

    Args:
        networks: List of scanned networks (already sorted by signal).
        credentials: Optional dict of SSID -> passphrase.  When provided,
            a "Key" column is added showing which networks have known
            passphrases.
        caption_override: Optional caption to use instead of default.
    """
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
            str(net.clients),
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
        "--debug",
        action="store_true",
        help="enable debug logging for troubleshooting (e.g. client counts in monitor mode)",
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
    credentials: dict[str, str] | None = None
    connected = False
    dns_tracker: DnsTracker | None = None
    airodump_scanner: AirodumpScanner | None = None
    airodump_failure_reason: str | None = None

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
                        networks = scan_wifi_nmcli(args.interface)
                    else:
                        networks = airodump_scanner.scan()
                else:
                    networks = scan_wifi_nmcli(args.interface)
                network_table = build_table(
                    networks,
                    credentials=credentials,
                    caption_override=caption_override,
                )

                if dns_tracker is not None:
                    dns_table = build_dns_table(dns_tracker.top())
                    live.update(Group(network_table, dns_table))
                else:
                    live.update(network_table)

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
