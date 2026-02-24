"""WiFi network scanning via nmcli (NetworkManager CLI).

This module provides the core scanning functions for the laptop/desktop
platform.  It can also be invoked as a standalone tool::

    python -m wifimonitor.scanning.nmcli                  # scan, print table
    python -m wifimonitor.scanning.nmcli -i wlan1         # specific interface
    python -m wifimonitor.scanning.nmcli --json           # JSON output
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

from wifimonitor.wifi_common import (
    CommandRunner,
    Network,
    SubprocessRunner,
    _minimal_env,
)

_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# nmcli output parsing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Live scanning (requires nmcli on the system)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for standalone invocation."""
    parser = argparse.ArgumentParser(
        description="Scan WiFi networks via nmcli and print results.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Wireless interface to scan (default: all)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON instead of a table",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Scan WiFi networks and print results to stdout."""
    args = _parse_args(argv)
    networks = scan_wifi_nmcli(interface=args.interface)

    if args.json_output:
        data = [
            {
                "bssid": n.bssid,
                "ssid": n.ssid,
                "signal": n.signal,
                "channel": n.channel,
                "security": n.security,
            }
            for n in networks
        ]
        print(json.dumps(data, indent=2))
    else:
        if not networks:
            print("No networks found.")
            return
        print(f"{'BSSID':<20} {'SSID':<25} {'Ch':>3} {'dBm':>5} {'Security':<10}")
        print("-" * 68)
        for n in networks:
            print(f"{n.bssid:<20} {n.ssid:<25} {n.channel:>3} {n.signal:>5} {n.security:<10}")
        print(f"\n{len(networks)} network(s) found.")


if __name__ == "__main__":
    main()

