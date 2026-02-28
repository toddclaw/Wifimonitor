"""Deauthentication/disassociation frame capture and severity classification.

Captures 802.11 deauth/disassoc management frames from tcpdump on a
monitor-mode interface, aggregates them per BSSID, and classifies
severity.  Can be used standalone::

    python -m wifimonitor.capture.deauth -i mon0     # capture on monitor iface
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import threading
import time

from wifimonitor.wifi_common import (
    CommandRunner,
    DeauthEvent,
    DeauthSummary,
    KnownNetwork,
    SubprocessRunner,
    _minimal_env,
)

_DEFAULT_RUNNER = SubprocessRunner()

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


# ---------------------------------------------------------------------------
# DeauthTracker — background capture class
# ---------------------------------------------------------------------------

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
# Deauth rate-based severity classification
# ---------------------------------------------------------------------------

_BROADCAST = "ff:ff:ff:ff:ff:ff"


def classify_deauth_events(
    events: list[DeauthEvent],
    baseline: list[KnownNetwork] | None = None,
) -> list[DeauthSummary]:
    """Aggregate deauth/disassoc events by BSSID and classify severity.

    Severity thresholds (frame count per BSSID):
        - **normal**: 1-2 frames (routine roaming/AP restart)
        - **suspicious**: 3-9 frames (may indicate targeted disruption)
        - **attack**: 10+ frames (likely active deauth attack)

    Args:
        events: Raw deauth/disassoc events from :class:`DeauthTracker`.
        baseline: Optional known-good network list.  When provided, only
            BSSIDs found in the baseline are included in the output.  This
            focuses alerts on networks you care about.

    Returns:
        A list of :class:`DeauthSummary` objects sorted by ``total_count``
        descending (highest activity first).
    """
    if not events:
        return []

    # Optional: restrict to known BSSIDs
    known_bssids: set[str] | None = None
    if baseline:
        known_bssids = {kn.bssid.lower() for kn in baseline}

    # Aggregate by BSSID
    by_bssid: dict[str, list[DeauthEvent]] = {}
    for evt in events:
        bssid = evt.bssid.lower()
        if known_bssids is not None and bssid not in known_bssids:
            continue
        by_bssid.setdefault(bssid, []).append(evt)

    summaries: list[DeauthSummary] = []
    for bssid, bssid_events in by_bssid.items():
        total = len(bssid_events)
        broadcast = sum(1 for e in bssid_events if e.destination == _BROADCAST)
        targets = {
            e.destination for e in bssid_events if e.destination != _BROADCAST
        }

        if total >= 10:
            severity = "attack"
        elif total >= 3:
            severity = "suspicious"
        else:
            severity = "normal"

        summaries.append(DeauthSummary(
            bssid=bssid,
            total_count=total,
            broadcast_count=broadcast,
            unique_targets=len(targets),
            severity=severity,
        ))

    summaries.sort(key=lambda s: s.total_count, reverse=True)
    return summaries


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for standalone invocation."""
    parser = argparse.ArgumentParser(
        description="Capture deauth/disassoc frames via tcpdump on a monitor interface.",
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Monitor-mode interface (e.g. mon0)",
    )
    parser.add_argument(
        "-t", "--interval", type=float, default=5.0,
        help="Summary refresh interval in seconds (default: 5)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Capture deauth frames and periodically print a summary."""
    args = _parse_args(argv)
    tracker = DeauthTracker()
    if not tracker.start(interface=args.interface):
        print("ERROR: Could not start tcpdump. Are you root?", file=sys.stderr)
        sys.exit(1)

    try:
        while True:
            time.sleep(args.interval)
            events = tracker.events(50)
            if events:
                summaries = classify_deauth_events(events)
                print(f"\n{'BSSID':<20} {'Frames':>7} {'Bcast':>6} {'Targets':>8} {'Severity':<12}")
                print("-" * 58)
                for s in summaries:
                    print(f"{s.bssid:<20} {s.total_count:>7} {s.broadcast_count:>6} {s.unique_targets:>8} {s.severity:<12}")
            else:
                print("(no deauth frames captured yet)")
    except KeyboardInterrupt:
        pass
    finally:
        tracker.stop()


if __name__ == "__main__":
    main()
