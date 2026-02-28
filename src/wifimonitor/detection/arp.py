"""ARP-based client detection for the connected subnet.

Scans the local subnet via ``arp-scan`` (preferred) or ``nmap -sn``
(fallback) to count active hosts.  Works on any WiFi adapter, including
Intel cards that do not support monitor mode.
"""

from __future__ import annotations

import re
import subprocess

from wifimonitor.wifi_common import (
    CommandRunner,
    SubprocessRunner,
    _minimal_env,
)
from wifimonitor.scanning.nmcli import _split_nmcli_line

_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# Connected network helpers
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


# ---------------------------------------------------------------------------
# ARP / nmap output parsing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# ArpScanner — client detection class
# ---------------------------------------------------------------------------

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
