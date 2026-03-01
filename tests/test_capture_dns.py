"""Tests for wifimonitor.capture.dns — canonical DNS capture module.

Imports from the canonical location (wifimonitor.capture.dns) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from wifimonitor.capture.dns import (
    DnsTracker,
    main,
    parse_tcpdump_dns_line,
    _parse_args,
)


# ---------------------------------------------------------------------------
# parse_tcpdump_dns_line
# ---------------------------------------------------------------------------

class TestParseTcpdumpDnsLine:
    """parse_tcpdump_dns_line extracts the queried domain from a tcpdump line."""

    def test_a_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? google.com. (28)"
        assert parse_tcpdump_dns_line(line) == "google.com"

    def test_aaaa_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ AAAA? example.org. (32)"
        assert parse_tcpdump_dns_line(line) == "example.org"

    def test_subdomain_preserved(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? cdn.images.example.com. (40)"
        assert parse_tcpdump_dns_line(line) == "cdn.images.example.com"

    def test_ptr_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ PTR? 1.0.168.192.in-addr.arpa. (44)"
        assert parse_tcpdump_dns_line(line) == "1.0.168.192.in-addr.arpa"

    def test_https_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ HTTPS? cloudflare.com. (32)"
        assert parse_tcpdump_dns_line(line) == "cloudflare.com"

    def test_mx_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ MX? mail.example.com. (35)"
        assert parse_tcpdump_dns_line(line) == "mail.example.com"

    def test_response_line_returns_none(self):
        line = "20:15:30.123 IP 8.8.8.8.53 > 192.168.1.100.54321: 65432 1/0/0 A 93.184.216.34 (50)"
        assert parse_tcpdump_dns_line(line) is None

    def test_empty_line_returns_none(self):
        assert parse_tcpdump_dns_line("") is None

    def test_non_dns_line_returns_none(self):
        line = "20:15:30.123 IP 192.168.1.100.80 > 10.0.0.1.12345: Flags [S], seq 12345"
        assert parse_tcpdump_dns_line(line) is None

    def test_trailing_dot_stripped(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? trailing.dot.com. (30)"
        result = parse_tcpdump_dns_line(line)
        assert result == "trailing.dot.com"
        assert not result.endswith(".")

    def test_domain_with_hyphen(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? my-site.example.com. (38)"
        assert parse_tcpdump_dns_line(line) == "my-site.example.com"

    def test_svcb_record_query(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ SVCB? svc.example.com. (32)"
        assert parse_tcpdump_dns_line(line) == "svc.example.com"


# ---------------------------------------------------------------------------
# DnsTracker
# ---------------------------------------------------------------------------

class TestDnsTracker:
    """DnsTracker captures DNS queries in a background thread."""

    def test_record_and_top(self):
        tracker = DnsTracker()
        tracker.record("google.com")
        tracker.record("google.com")
        tracker.record("example.org")
        top = tracker.top(10)
        assert top[0] == ("google.com", 2)
        assert ("example.org", 1) in top

    def test_top_limits_results(self):
        tracker = DnsTracker()
        for i in range(20):
            tracker.record(f"domain{i}.com")
        assert len(tracker.top(5)) == 5

    def test_top_empty_tracker(self):
        tracker = DnsTracker()
        assert tracker.top() == []

    def test_start_returns_false_when_tcpdump_missing(self):
        mock_runner = MagicMock()
        mock_runner.popen.side_effect = FileNotFoundError("tcpdump not found")
        tracker = DnsTracker(runner=mock_runner)
        assert tracker.start() is False

    def test_start_returns_true_on_success(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DnsTracker(runner=mock_runner)
        assert tracker.start() is True
        tracker.stop()

    def test_start_without_interface_no_i_flag(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DnsTracker(runner=mock_runner)
        tracker.start()
        cmd = mock_runner.popen.call_args[0][0]
        assert "-i" not in cmd
        tracker.stop()

    def test_start_with_interface_includes_i_flag(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DnsTracker(runner=mock_runner)
        tracker.start(interface="wlan0")
        cmd = mock_runner.popen.call_args[0][0]
        assert "-i" in cmd
        assert "wlan0" in cmd
        tracker.stop()

    def test_stop_terminates_process(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DnsTracker(runner=mock_runner)
        tracker.start()
        tracker.stop()
        mock_process.terminate.assert_called_once()

    def test_reader_loop_records_valid_lines(self):
        dns_line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? google.com. (28)\n"
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([dns_line])
        mock_runner.popen.return_value = mock_process
        tracker = DnsTracker(runner=mock_runner)
        tracker.start()
        # Wait briefly for the reader thread to process
        import time
        time.sleep(0.1)
        tracker.stop()
        top = tracker.top(10)
        assert ("google.com", 1) in top

    def test_thread_safety_concurrent_records(self):
        tracker = DnsTracker()
        errors = []

        def record_domains():
            try:
                for i in range(100):
                    tracker.record(f"domain{i}.com")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=record_domains) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        # 4 threads x 100 domains each = 400 total records
        total = sum(count for _, count in tracker.top(400))
        assert total == 400

    def test_reset_clears_counts(self):
        tracker = DnsTracker()
        tracker.record("google.com")
        tracker.record("google.com")
        tracker.record("example.org")
        assert len(tracker.top(10)) > 0
        tracker.reset()
        assert tracker.top() == []

    def test_reset_thread_safe(self):
        """reset() while recording from another thread does not corrupt state."""
        tracker = DnsTracker()
        errors = []
        reset_done = threading.Event()

        def record_loop():
            try:
                for i in range(200):
                    tracker.record(f"domain{i}.com")
                    if i == 50:
                        reset_done.set()
            except Exception as exc:
                errors.append(exc)

        def reset_loop():
            reset_done.wait()
            for _ in range(5):
                tracker.reset()

        t1 = threading.Thread(target=record_loop)
        t2 = threading.Thread(target=reset_loop)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert not errors
        # After resets, counts may be empty or have some domains; no crash
        tracker.top()


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

class TestDnsCli:
    """Standalone CLI argument parsing."""

    def test_parse_args_defaults(self):
        args = _parse_args([])
        assert args.interface is None
        assert args.count == 15
        assert args.interval == 5.0

    def test_parse_args_with_interface(self):
        args = _parse_args(["-i", "wlan0"])
        assert args.interface == "wlan0"

    def test_parse_args_with_count(self):
        args = _parse_args(["-n", "25"])
        assert args.count == 25

    def test_parse_args_with_interval(self):
        args = _parse_args(["-t", "2.5"])
        assert args.interval == 2.5

    def test_main_exits_on_tcpdump_failure(self):
        with patch("wifimonitor.capture.dns.DnsTracker") as MockTracker:
            instance = MockTracker.return_value
            instance.start.return_value = False
            with pytest.raises(SystemExit) as exc_info:
                main(["-i", "wlan0"])
            assert exc_info.value.code == 1
