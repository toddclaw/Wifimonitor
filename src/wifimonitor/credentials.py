"""WiFi credentials file loading and nmcli connection.

Loads SSID/passphrase pairs from a CSV file and connects to WiFi
networks via nmcli.  Can be used standalone to test connectivity::

    python -m wifimonitor.credentials -c creds.csv -s MyNetwork
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import stat
import subprocess
import sys

from wifimonitor.wifi_common import (
    CommandRunner,
    SubprocessRunner,
    _minimal_env,
)

_DEFAULT_RUNNER = SubprocessRunner()

_BSSID_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def _is_bssid(s: str) -> bool:
    """Return True if s looks like a MAC address (BSSID)."""
    return bool(_BSSID_RE.match(s.strip()))


# ---------------------------------------------------------------------------
# Credentials file I/O
# ---------------------------------------------------------------------------

def load_credentials(
    filepath: str,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Load SSID/passphrase and BSSID-keyed hidden network credentials.

    File format:
    - Standard: ``ssid,passphrase`` (2 fields per line)
    - Hidden:   ``BSSID,SSID,passphrase`` (3 fields, first is MAC address)

    Lines starting with ``#`` are comments.  Blank lines are ignored.
    Fields may be quoted to include commas.

    Returns:
        (by_ssid, by_bssid) where:
        - by_ssid: SSID -> passphrase for normal networks
        - by_bssid: BSSID (lowercase) -> (ssid, passphrase) for hidden networks
    """
    by_ssid: dict[str, str] = {}
    by_bssid: dict[str, tuple[str, str]] = {}

    if not os.path.isfile(filepath):
        return (by_ssid, by_bssid)

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
                first = row[0].strip()
                if len(row) >= 3 and _is_bssid(first):
                    bssid = first.lower()
                    ssid = row[1].strip()
                    passphrase = row[2].strip()
                    by_bssid[bssid] = (ssid, passphrase)
                else:
                    ssid = first
                    passphrase = row[1].strip()
                    by_ssid[ssid] = passphrase
    except OSError:
        return (by_ssid, by_bssid)

    return (by_ssid, by_bssid)


# ---------------------------------------------------------------------------
# nmcli connection
# ---------------------------------------------------------------------------

def connect_wifi_nmcli(
    ssid: str,
    passphrase: str,
    interface: str | None = None,
    *,
    hidden: bool = False,
    runner: CommandRunner | None = None,
) -> bool:
    """Connect to a WiFi network using nmcli.

    Args:
        ssid: The network SSID to connect to.
        passphrase: The network passphrase (empty string for open networks).
        interface: Optional wireless interface name.
        hidden: If True, append ``hidden yes`` for hidden networks.
        runner: Optional CommandRunner for subprocess calls (testing seam).

    Returns:
        True if the connection succeeded, False otherwise.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmd = ["nmcli", "device", "wifi", "connect", ssid]

    if passphrase:
        cmd += ["password", passphrase]

    if hidden:
        cmd += ["hidden", "yes"]

    if interface:
        cmd += ["ifname", interface]

    try:
        result = runner.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for standalone invocation."""
    parser = argparse.ArgumentParser(
        description="Load WiFi credentials and optionally connect to a network.",
    )
    parser.add_argument(
        "-c", "--credentials", required=True,
        help="Path to CSV credentials file (ssid,passphrase)",
    )
    parser.add_argument(
        "-s", "--ssid",
        help="SSID to connect to (must be in credentials file)",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Wireless interface to connect on",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Load credentials and optionally connect to a network."""
    args = _parse_args(argv)
    by_ssid, by_bssid = load_credentials(args.credentials)
    total = len(by_ssid) + len(by_bssid)
    if not total:
        print(f"ERROR: No credentials loaded from {args.credentials}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {total} credential(s) from {args.credentials}")
    for ssid in by_ssid:
        print(f"  {ssid}")
    for bssid in by_bssid:
        ssid, _ = by_bssid[bssid]
        print(f"  {bssid} -> {ssid or '(hidden)'}")

    if args.ssid:
        if args.ssid not in by_ssid:
            print(f"ERROR: SSID '{args.ssid}' not found in credentials file", file=sys.stderr)
            sys.exit(1)
        ok = connect_wifi_nmcli(args.ssid, by_ssid[args.ssid], interface=args.interface)
        if ok:
            print(f"Connected to {args.ssid}")
        else:
            print(f"Failed to connect to {args.ssid}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
