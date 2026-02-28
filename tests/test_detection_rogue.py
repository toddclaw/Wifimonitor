"""Tests for wifimonitor.detection.rogue — canonical rogue AP detection module.

Imports from the canonical location (wifimonitor.detection.rogue) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from wifimonitor.detection.rogue import (
    detect_rogue_aps,
    load_baseline,
    main,
    save_baseline,
    _parse_args,
)
from wifimonitor.wifi_common import KnownNetwork, Network


# ---------------------------------------------------------------------------
# load_baseline
# ---------------------------------------------------------------------------

class TestLoadBaseline:
    """load_baseline reads a JSON file of known SSID/BSSID/channel tuples."""

    def test_loads_valid_json(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"AA:BB:CC:DD:EE:01","channel":6}]')
        result = load_baseline(str(path))
        assert len(result) == 1
        assert result[0].ssid == "Home"
        assert result[0].bssid == "aa:bb:cc:dd:ee:01"
        assert result[0].channel == 6

    def test_loads_multiple_entries(self, tmp_path):
        path = tmp_path / "baseline.json"
        data = [
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:01", "channel": 6},
            {"ssid": "Home", "bssid": "aa:bb:cc:dd:ee:02", "channel": 36},
        ]
        path.write_text(json.dumps(data))
        result = load_baseline(str(path))
        assert len(result) == 2
        assert result[1].channel == 36

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_baseline(str(tmp_path / "nonexistent.json"))
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {{{")
        result = load_baseline(str(path))
        assert result == []

    def test_non_array_json_returns_empty(self, tmp_path):
        path = tmp_path / "obj.json"
        path.write_text('{"ssid":"Home"}')
        result = load_baseline(str(path))
        assert result == []

    def test_skips_entries_without_ssid(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"bssid":"aa:bb:cc:dd:ee:01","channel":6}]')
        result = load_baseline(str(path))
        assert result == []

    def test_skips_entries_without_bssid(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","channel":6}]')
        result = load_baseline(str(path))
        assert result == []

    def test_channel_defaults_to_zero(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01"}]')
        result = load_baseline(str(path))
        assert result[0].channel == 0

    def test_non_int_channel_defaults_to_zero(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01","channel":"bad"}]')
        result = load_baseline(str(path))
        assert result[0].channel == 0

    def test_bssid_lowercased(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('[{"ssid":"Home","bssid":"AA:BB:CC:DD:EE:01"}]')
        result = load_baseline(str(path))
        assert result[0].bssid == "aa:bb:cc:dd:ee:01"

    def test_skips_non_dict_entries(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text('["not a dict", {"ssid":"Home","bssid":"aa:bb:cc:dd:ee:01"}]')
        result = load_baseline(str(path))
        assert len(result) == 1


# ---------------------------------------------------------------------------
# save_baseline
# ---------------------------------------------------------------------------

class TestSaveBaseline:
    """save_baseline writes scanned networks to a JSON file."""

    def test_saves_networks_to_json(self, tmp_path):
        path = tmp_path / "out.json"
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6, signal=-55),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="Office", channel=36, signal=-65),
        ]
        count = save_baseline(str(path), nets)
        assert count == 2
        data = json.loads(path.read_text())
        assert len(data) == 2
        assert data[0]["ssid"] == "Home"

    def test_skips_hidden_networks(self, tmp_path):
        path = tmp_path / "out.json"
        nets = [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6),
            Network(bssid="aa:bb:cc:dd:ee:02", ssid="", channel=1),
        ]
        count = save_baseline(str(path), nets)
        assert count == 1

    def test_empty_networks_writes_empty_array(self, tmp_path):
        path = tmp_path / "out.json"
        count = save_baseline(str(path), [])
        assert count == 0
        assert json.loads(path.read_text()) == []

    def test_write_failure_returns_zero(self):
        count = save_baseline("/nonexistent/dir/out.json", [
            Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home"),
        ])
        assert count == 0

    def test_roundtrip_load_save(self, tmp_path):
        path = tmp_path / "roundtrip.json"
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Home", channel=6, signal=-55)]
        save_baseline(str(path), nets)
        loaded = load_baseline(str(path))
        assert len(loaded) == 1
        assert loaded[0].ssid == "Home"
        assert loaded[0].bssid == "aa:bb:cc:dd:ee:01"
        assert loaded[0].channel == 6


# ---------------------------------------------------------------------------
# detect_rogue_aps
# ---------------------------------------------------------------------------

class TestDetectRogueAps:
    """detect_rogue_aps compares scanned networks against a known-good baseline."""

    def _baseline(self) -> list[KnownNetwork]:
        return [
            KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01", channel=6),
            KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:02", channel=36),
        ]

    def test_no_alert_when_network_matches(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=6, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_unknown_bssid_alert(self):
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="HomeNet", channel=6, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 1
        assert alerts[0].reason == "unknown_bssid"

    def test_unexpected_channel_alert(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=11, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts) == 1
        assert alerts[0].reason == "unexpected_channel"

    def test_ignores_unknown_ssid(self):
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="Unknown", channel=1, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_ignores_hidden_networks(self):
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="", channel=1, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert alerts == []

    def test_empty_networks_returns_empty(self):
        assert detect_rogue_aps([], self._baseline()) == []

    def test_empty_baseline_returns_empty(self):
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=6)]
        assert detect_rogue_aps(nets, []) == []

    def test_baseline_channel_zero_is_wildcard(self):
        baseline = [KnownNetwork(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01", channel=0)]
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="HomeNet", channel=99, signal=-55)]
        alerts = detect_rogue_aps(nets, baseline)
        assert alerts == []

    def test_alert_has_expected_bssids_and_channels(self):
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="HomeNet", channel=6, signal=-55)]
        alerts = detect_rogue_aps(nets, self._baseline())
        assert len(alerts[0].expected_bssids) == 2
        assert len(alerts[0].expected_channels) == 2


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

class TestRogueCli:
    """Standalone CLI argument parsing."""

    def test_parse_args_baseline(self):
        args = _parse_args(["--baseline", "known.json"])
        assert args.baseline == "known.json"
        assert args.save_baseline is None

    def test_parse_args_save_baseline(self):
        args = _parse_args(["--save-baseline", "out.json"])
        assert args.save_baseline == "out.json"
        assert args.baseline is None

    def test_parse_args_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            _parse_args(["--baseline", "a.json", "--save-baseline", "b.json"])

    def test_parse_args_requires_one_flag(self):
        with pytest.raises(SystemExit):
            _parse_args([])

    def test_parse_args_interface(self):
        args = _parse_args(["--baseline", "known.json", "-i", "wlan0"])
        assert args.interface == "wlan0"

    def test_main_save_baseline_writes_file(self, tmp_path):
        out = tmp_path / "out.json"
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-50)]
        with patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=nets):
            main(["--save-baseline", str(out)])
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data) == 1

    def test_main_baseline_check_no_alerts(self, tmp_path, capsys):
        baseline = tmp_path / "known.json"
        baseline.write_text('[{"ssid":"Test","bssid":"aa:bb:cc:dd:ee:01","channel":6}]')
        nets = [Network(bssid="aa:bb:cc:dd:ee:01", ssid="Test", channel=6, signal=-50)]
        with patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=nets):
            main(["--baseline", str(baseline)])
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_main_baseline_check_with_alerts(self, tmp_path):
        baseline = tmp_path / "known.json"
        baseline.write_text('[{"ssid":"Test","bssid":"aa:bb:cc:dd:ee:01","channel":6}]')
        nets = [Network(bssid="ff:ff:ff:ff:ff:ff", ssid="Test", channel=6, signal=-50)]
        with patch("wifimonitor.scanning.nmcli.scan_wifi_nmcli", return_value=nets):
            with pytest.raises(SystemExit) as exc_info:
                main(["--baseline", str(baseline)])
            assert exc_info.value.code == 2
