"""WiFi credentials file loading and nmcli connection.

Loads SSID/passphrase pairs from a CSV file and connects to WiFi
networks via nmcli.  Can be used standalone to test connectivity::

    python -m wifimonitor.credentials -c creds.csv -s MyNetwork
"""

from __future__ import annotations

import argparse
import csv
import os
import stat
import subprocess
import sys

from wifimonitor.wifi_common import (
    CommandRunner,
    SubprocessRunner,
    _minimal_env,
)

_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# Credentials file I/O
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
    creds = load_credentials(args.credentials)
    if not creds:
        print(f"ERROR: No credentials loaded from {args.credentials}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(creds)} credential(s) from {args.credentials}")
    for ssid in creds:
        print(f"  {ssid}")

    if args.ssid:
        if args.ssid not in creds:
            print(f"ERROR: SSID '{args.ssid}' not found in credentials file", file=sys.stderr)
            sys.exit(1)
        ok = connect_wifi_nmcli(args.ssid, creds[args.ssid], interface=args.interface)
        if ok:
            print(f"Connected to {args.ssid}")
        else:
            print(f"Failed to connect to {args.ssid}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
