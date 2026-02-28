"""Rogue AP detection — baseline I/O and comparison logic.

Compares scan results against a known-good baseline file to flag
access points that are new or have moved to unexpected channels.
Can be used standalone for cron-style checks::

    python -m wifimonitor.detection.rogue --baseline known.json
    python -m wifimonitor.detection.rogue --save-baseline known.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import stat
import sys

from wifimonitor.wifi_common import (
    KnownNetwork,
    Network,
    RogueAlert,
)

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Baseline file I/O
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
# Rogue AP detection logic
# ---------------------------------------------------------------------------

def detect_rogue_aps(
    networks: list[Network],
    baseline: list[KnownNetwork],
) -> list[RogueAlert]:
    """Compare scanned networks against a known-good baseline.

    For each scanned network whose SSID appears in the baseline, checks:

    1. **Unknown BSSID** — the SSID is known but this BSSID is not in the
       baseline -> ``reason="unknown_bssid"``.
    2. **Unexpected channel** — the BSSID *is* known but the channel does
       not match (and the baseline channel is not 0, which means "any") ->
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
# Standalone CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for standalone invocation."""
    parser = argparse.ArgumentParser(
        description="Scan WiFi and compare against a known-good baseline.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--baseline",
        help="Path to baseline JSON file to check against",
    )
    group.add_argument(
        "--save-baseline",
        help="Scan and save results as a new baseline JSON file",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Wireless interface to scan (default: all)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Scan WiFi networks and check against a known-good baseline."""
    args = _parse_args(argv)

    # Import here to avoid circular dependency at module level
    from wifimonitor.scanning.nmcli import scan_wifi_nmcli

    networks = scan_wifi_nmcli(interface=args.interface)

    if args.save_baseline:
        count = save_baseline(args.save_baseline, networks)
        print(f"Saved {count} network(s) to {args.save_baseline}")
        return

    baseline = load_baseline(args.baseline)
    if not baseline:
        print(f"ERROR: No networks in baseline {args.baseline}", file=sys.stderr)
        sys.exit(1)

    alerts = detect_rogue_aps(networks, baseline)
    if not alerts:
        print(f"OK: {len(networks)} network(s) scanned, no rogue APs detected.")
    else:
        print(f"ALERT: {len(alerts)} rogue AP(s) detected!")
        for a in alerts:
            print(f"  {a.network.ssid} ({a.network.bssid}) — {a.reason}")
        sys.exit(2)


if __name__ == "__main__":
    main()
