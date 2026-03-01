"""DNS query capture and frequency tracking via tcpdump.

Captures live DNS queries from tcpdump in a background thread and
tallies query frequency per domain.  Can be used standalone::

    python -m wifimonitor.capture.dns               # capture on default iface
    python -m wifimonitor.capture.dns -i wlan0       # specific interface
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
import threading
import time

from wifimonitor.wifi_common import (
    CommandRunner,
    SubprocessRunner,
    _minimal_env,
)

_DEFAULT_RUNNER = SubprocessRunner()

# ---------------------------------------------------------------------------
# DNS line parsing
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


# ---------------------------------------------------------------------------
# DnsTracker — background capture class
# ---------------------------------------------------------------------------

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

    def reset(self) -> None:
        """Clear all recorded DNS query counts (thread-safe)."""
        with self._lock:
            self._counts.clear()

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
# Standalone CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for standalone invocation."""
    parser = argparse.ArgumentParser(
        description="Capture DNS queries via tcpdump and print top domains.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on",
    )
    parser.add_argument(
        "-n", "--count", type=int, default=15,
        help="Number of top domains to show (default: 15)",
    )
    parser.add_argument(
        "-t", "--interval", type=float, default=5.0,
        help="Refresh interval in seconds (default: 5)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Capture DNS queries and periodically print top domains."""
    args = _parse_args(argv)
    tracker = DnsTracker()
    if not tracker.start(interface=args.interface):
        print("ERROR: Could not start tcpdump. Are you root?", file=sys.stderr)
        sys.exit(1)

    try:
        while True:
            time.sleep(args.interval)
            top = tracker.top(args.count)
            if top:
                print(f"\n{'Domain':<50} {'Count':>6}")
                print("-" * 57)
                for domain, count in top:
                    print(f"{domain:<50} {count:>6}")
            else:
                print("(no DNS queries captured yet)")
    except KeyboardInterrupt:
        pass
    finally:
        tracker.stop()


if __name__ == "__main__":
    main()
