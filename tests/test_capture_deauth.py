"""Tests for wifimonitor.capture.deauth — canonical deauth capture module.

Imports from the canonical location (wifimonitor.capture.deauth) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest

from wifimonitor.capture.deauth import (
    DeauthTracker,
    classify_deauth_events,
    main,
    parse_tcpdump_deauth_line,
    _parse_args,
)
from wifimonitor.wifi_common import DeauthEvent, DeauthSummary, KnownNetwork


# ---------------------------------------------------------------------------
# parse_tcpdump_deauth_line
# ---------------------------------------------------------------------------

DEAUTH_LINE = (
    "11:04:34.360700 314us BSSID:00:14:6c:7e:40:80 "
    "DA:00:0f:b5:46:11:19 SA:00:14:6c:7e:40:80 "
    "DeAuthentication: Class 3 frame received from nonassociated station"
)

DISASSOC_LINE = (
    "12:30:01.123456 200us BSSID:aa:bb:cc:dd:ee:01 "
    "DA:11:22:33:44:55:66 SA:aa:bb:cc:dd:ee:01 "
    "Disassociation: Deauthenticated because sending station is leaving"
)

BROADCAST_DEAUTH = (
    "13:00:00.000000 100us BSSID:00:14:6c:7e:40:80 "
    "DA:ff:ff:ff:ff:ff:ff SA:00:14:6c:7e:40:80 "
    "DeAuthentication: Unspecified"
)


class TestParseTcpdumpDeauthLine:
    """parse_tcpdump_deauth_line extracts deauth/disassoc events from tcpdump -e output."""

    def test_valid_deauth_line_returns_event(self):
        result = parse_tcpdump_deauth_line(DEAUTH_LINE)
        assert result is not None
        assert isinstance(result, DeauthEvent)
        assert result.subtype == "deauth"

    def test_deauth_bssid_lowercased(self):
        result = parse_tcpdump_deauth_line(DEAUTH_LINE)
        assert result is not None
        assert result.bssid == "00:14:6c:7e:40:80"

    def test_deauth_source_and_destination(self):
        result = parse_tcpdump_deauth_line(DEAUTH_LINE)
        assert result is not None
        assert result.source == "00:14:6c:7e:40:80"
        assert result.destination == "00:0f:b5:46:11:19"

    def test_deauth_reason_captured(self):
        result = parse_tcpdump_deauth_line(DEAUTH_LINE)
        assert result is not None
        assert "Class 3 frame" in result.reason

    def test_valid_disassoc_line(self):
        result = parse_tcpdump_deauth_line(DISASSOC_LINE)
        assert result is not None
        assert result.subtype == "disassoc"
        assert result.bssid == "aa:bb:cc:dd:ee:01"

    def test_disassoc_reason_captured(self):
        result = parse_tcpdump_deauth_line(DISASSOC_LINE)
        assert result is not None
        assert "leaving" in result.reason

    def test_broadcast_deauth_destination(self):
        result = parse_tcpdump_deauth_line(BROADCAST_DEAUTH)
        assert result is not None
        assert result.destination == "ff:ff:ff:ff:ff:ff"

    def test_non_deauth_line_returns_none(self):
        line = "11:04:34.360700 BSSID:00:14:6c:7e:40:80 Beacon (MyNetwork) [6.0 Mbit]"
        assert parse_tcpdump_deauth_line(line) is None

    def test_empty_string_returns_none(self):
        assert parse_tcpdump_deauth_line("") is None

    def test_dns_line_returns_none(self):
        line = "20:15:30.123 IP 192.168.1.100.54321 > 8.8.8.8.53: 65432+ A? example.com. (30)"
        assert parse_tcpdump_deauth_line(line) is None

    def test_uppercase_bssid_lowercased(self):
        line = (
            "11:04:34.360700 314us BSSID:AA:BB:CC:DD:EE:FF "
            "DA:11:22:33:44:55:66 SA:AA:BB:CC:DD:EE:FF "
            "DeAuthentication: Unspecified"
        )
        result = parse_tcpdump_deauth_line(line)
        assert result is not None
        assert result.bssid == "aa:bb:cc:dd:ee:ff"
        assert result.source == "aa:bb:cc:dd:ee:ff"

    def test_reason_with_code_number(self):
        line = (
            "14:00:00.000000 100us BSSID:00:14:6c:7e:40:80 "
            "DA:00:0f:b5:46:11:19 SA:00:14:6c:7e:40:80 "
            "DeAuthentication: Deauthenticated (7)"
        )
        result = parse_tcpdump_deauth_line(line)
        assert result is not None
        assert "7" in result.reason


# ---------------------------------------------------------------------------
# DeauthTracker
# ---------------------------------------------------------------------------

class TestDeauthTracker:
    """DeauthTracker captures deauth frames in a background thread."""

    def test_record_and_events(self):
        tracker = DeauthTracker()
        event = DeauthEvent(
            bssid="aa:bb:cc:dd:ee:ff",
            source="aa:bb:cc:dd:ee:ff",
            destination="11:22:33:44:55:66",
            reason="test",
            subtype="deauth",
        )
        tracker.record(event)
        events = tracker.events()
        assert len(events) == 1
        assert events[0].bssid == "aa:bb:cc:dd:ee:ff"

    def test_events_returns_newest_first(self):
        tracker = DeauthTracker()
        for i in range(5):
            tracker.record(DeauthEvent(
                bssid=f"00:00:00:00:00:0{i}",
                source="aa:bb:cc:dd:ee:ff",
                destination="11:22:33:44:55:66",
                reason=f"event{i}",
                subtype="deauth",
            ))
        events = tracker.events(3)
        assert len(events) == 3
        assert events[0].reason == "event4"  # newest first

    def test_start_returns_false_when_tcpdump_missing(self):
        mock_runner = MagicMock()
        mock_runner.popen.side_effect = FileNotFoundError("tcpdump not found")
        tracker = DeauthTracker(runner=mock_runner)
        assert tracker.start("mon0") is False

    def test_start_returns_true_on_success(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DeauthTracker(runner=mock_runner)
        assert tracker.start("mon0") is True
        tracker.stop()

    def test_start_uses_correct_bpf_filter(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DeauthTracker(runner=mock_runner)
        tracker.start("mon0")
        cmd = mock_runner.popen.call_args[0][0]
        assert "deauth" in cmd
        assert "disassoc" in cmd
        assert "-e" in cmd  # extended output needed for BSSID
        tracker.stop()

    def test_stop_terminates_process(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_runner.popen.return_value = mock_process
        tracker = DeauthTracker(runner=mock_runner)
        tracker.start("mon0")
        tracker.stop()
        mock_process.terminate.assert_called_once()

    def test_reader_loop_records_valid_lines(self):
        mock_runner = MagicMock()
        mock_process = MagicMock()
        mock_process.stdout = iter([DEAUTH_LINE + "\n"])
        mock_runner.popen.return_value = mock_process
        tracker = DeauthTracker(runner=mock_runner)
        tracker.start("mon0")
        import time
        time.sleep(0.1)
        tracker.stop()
        events = tracker.events(10)
        assert len(events) >= 1
        assert events[0].bssid == "00:14:6c:7e:40:80"

    def test_thread_safety_concurrent_records(self):
        tracker = DeauthTracker()
        errors = []

        def record_events():
            try:
                for i in range(50):
                    tracker.record(DeauthEvent(
                        bssid="aa:bb:cc:dd:ee:ff",
                        source="aa:bb:cc:dd:ee:ff",
                        destination="11:22:33:44:55:66",
                        reason=f"event{i}",
                        subtype="deauth",
                    ))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=record_events) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(tracker.events(300)) == 200


# ---------------------------------------------------------------------------
# classify_deauth_events
# ---------------------------------------------------------------------------

def _make_event(bssid: str = "aa:bb:cc:dd:ee:ff", dest: str = "11:22:33:44:55:66") -> DeauthEvent:
    return DeauthEvent(
        bssid=bssid, source=bssid, destination=dest,
        reason="test", subtype="deauth",
    )


class TestClassifyDeauthEvents:
    """classify_deauth_events aggregates and classifies severity."""

    def test_empty_events_returns_empty(self):
        assert classify_deauth_events([]) == []

    def test_single_event_is_normal(self):
        events = [_make_event()]
        result = classify_deauth_events(events)
        assert len(result) == 1
        assert result[0].severity == "normal"

    def test_two_events_is_normal(self):
        events = [_make_event() for _ in range(2)]
        result = classify_deauth_events(events)
        assert result[0].severity == "normal"
        assert result[0].total_count == 2

    def test_three_events_is_suspicious(self):
        events = [_make_event() for _ in range(3)]
        result = classify_deauth_events(events)
        assert result[0].severity == "suspicious"

    def test_nine_events_is_suspicious(self):
        events = [_make_event() for _ in range(9)]
        result = classify_deauth_events(events)
        assert result[0].severity == "suspicious"

    def test_ten_events_is_attack(self):
        events = [_make_event() for _ in range(10)]
        result = classify_deauth_events(events)
        assert result[0].severity == "attack"

    def test_broadcast_count(self):
        events = [
            _make_event(dest="ff:ff:ff:ff:ff:ff"),
            _make_event(dest="ff:ff:ff:ff:ff:ff"),
            _make_event(dest="11:22:33:44:55:66"),
        ]
        result = classify_deauth_events(events)
        assert result[0].broadcast_count == 2
        assert result[0].unique_targets == 1

    def test_unique_targets_count(self):
        events = [
            _make_event(dest="11:22:33:44:55:01"),
            _make_event(dest="11:22:33:44:55:02"),
            _make_event(dest="11:22:33:44:55:01"),  # duplicate
        ]
        result = classify_deauth_events(events)
        assert result[0].unique_targets == 2

    def test_multiple_bssids_sorted_by_count(self):
        events = [_make_event(bssid="aa:bb:cc:dd:ee:01") for _ in range(5)]
        events += [_make_event(bssid="aa:bb:cc:dd:ee:02") for _ in range(10)]
        result = classify_deauth_events(events)
        assert result[0].bssid == "aa:bb:cc:dd:ee:02"  # higher count first
        assert result[0].total_count == 10
        assert result[1].bssid == "aa:bb:cc:dd:ee:01"

    def test_baseline_filter_restricts_bssids(self):
        known = [KnownNetwork(ssid="TestNet", bssid="aa:bb:cc:dd:ee:01", channel=6)]
        events = [
            _make_event(bssid="aa:bb:cc:dd:ee:01"),
            _make_event(bssid="ff:ff:ff:ff:ff:00"),  # not in baseline
        ]
        result = classify_deauth_events(events, baseline=known)
        assert len(result) == 1
        assert result[0].bssid == "aa:bb:cc:dd:ee:01"

    def test_baseline_none_includes_all(self):
        events = [
            _make_event(bssid="aa:bb:cc:dd:ee:01"),
            _make_event(bssid="aa:bb:cc:dd:ee:02"),
        ]
        result = classify_deauth_events(events, baseline=None)
        assert len(result) == 2

    def test_returns_deauth_summary_objects(self):
        events = [_make_event()]
        result = classify_deauth_events(events)
        assert isinstance(result[0], DeauthSummary)


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

class TestDeauthCli:
    """Standalone CLI argument parsing."""

    def test_parse_args_requires_interface(self):
        with pytest.raises(SystemExit):
            _parse_args([])

    def test_parse_args_with_interface(self):
        args = _parse_args(["-i", "mon0"])
        assert args.interface == "mon0"

    def test_parse_args_default_interval(self):
        args = _parse_args(["-i", "mon0"])
        assert args.interval == 5.0

    def test_parse_args_custom_interval(self):
        args = _parse_args(["-i", "mon0", "-t", "2.0"])
        assert args.interval == 2.0

    def test_main_exits_on_tcpdump_failure(self):
        with patch("wifimonitor.capture.deauth.DeauthTracker") as MockTracker:
            instance = MockTracker.return_value
            instance.start.return_value = False
            with pytest.raises(SystemExit) as exc_info:
                main(["-i", "mon0"])
            assert exc_info.value.code == 1
