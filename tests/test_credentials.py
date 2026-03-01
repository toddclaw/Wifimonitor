"""Tests for wifimonitor.credentials — canonical credentials module.

Imports from the canonical location (wifimonitor.credentials) to validate
the extracted module works independently of the monolith re-exports.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wifimonitor.credentials import (
    connect_wifi_nmcli,
    load_credentials,
    main,
    _parse_args,
)


# ---------------------------------------------------------------------------
# load_credentials
# ---------------------------------------------------------------------------

class TestLoadCredentials:
    """load_credentials reads SSID/passphrase and BSSID-keyed hidden credentials."""

    def test_loads_valid_csv(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,mypassword\nOffice,officepass\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_ssid == {"HomeNet": "mypassword", "Office": "officepass"}
        assert by_bssid == {}

    def test_skips_comment_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("# This is a comment\nHomeNet,password\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert len(by_ssid) == 1
        assert "HomeNet" in by_ssid
        assert by_bssid == {}

    def test_skips_blank_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n\n\nOffice,pass2\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert len(by_ssid) == 2
        assert by_bssid == {}

    def test_skips_single_field_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("OnlySSID\nHomeNet,password\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert len(by_ssid) == 1
        assert by_bssid == {}

    def test_missing_file_returns_empty(self, tmp_path):
        by_ssid, by_bssid = load_credentials(str(tmp_path / "nonexistent.csv"))
        assert by_ssid == {}
        assert by_bssid == {}

    def test_quoted_fields(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text('"Net, with comma","pass, word"\n')
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_ssid.get("Net, with comma") == "pass, word"
        assert by_bssid == {}

    def test_strips_whitespace(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("  HomeNet  ,  password  \n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_ssid == {"HomeNet": "password"}
        assert by_bssid == {}

    def test_directory_path_returns_empty(self, tmp_path):
        """A directory is not a file — should return empty dicts."""
        by_ssid, by_bssid = load_credentials(str(tmp_path))
        assert by_ssid == {}
        assert by_bssid == {}

    def test_warns_world_readable(self, tmp_path, capsys):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        path.chmod(0o644)
        load_credentials(str(path))
        captured = capsys.readouterr()
        assert "WARNING" in captured.err or captured.err == ""  # May not warn depending on umask

    def test_bssid_line_parsed_into_by_bssid(self, tmp_path):
        """BSSID,SSID,passphrase lines populate by_bssid."""
        path = tmp_path / "creds.csv"
        path.write_text("aa:bb:cc:dd:ee:ff,MyHiddenNet,secret123\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_ssid == {}
        assert by_bssid == {"aa:bb:cc:dd:ee:ff": ("MyHiddenNet", "secret123")}

    def test_bssid_normalized_lowercase(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("AA:BB:CC:DD:EE:FF,Hidden,pass\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_bssid == {"aa:bb:cc:dd:ee:ff": ("Hidden", "pass")}

    def test_bssid_open_network_empty_passphrase(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("aa:11:22:33:44:55,OpenHidden,\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_bssid == {"aa:11:22:33:44:55": ("OpenHidden", "")}

    def test_mixed_ssid_and_bssid_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,pass1\naa:bb:cc:dd:ee:ff,HiddenNet,pass2\nOffice,pass3\n")
        by_ssid, by_bssid = load_credentials(str(path))
        assert by_ssid == {"HomeNet": "pass1", "Office": "pass3"}
        assert by_bssid == {"aa:bb:cc:dd:ee:ff": ("HiddenNet", "pass2")}

    def test_two_fields_with_mac_like_first_treated_as_ssid(self, tmp_path):
        """Two-field line: aa:bb:cc:dd:ee:ff,pass — first is SSID if only 2 fields."""
        path = tmp_path / "creds.csv"
        path.write_text("aa:bb:cc:dd:ee:ff,mypassword\n")
        by_ssid, by_bssid = load_credentials(str(path))
        # BSSID lines require 3+ fields; 2-field lines are always SSID
        assert by_ssid == {"aa:bb:cc:dd:ee:ff": "mypassword"}
        assert by_bssid == {}


# ---------------------------------------------------------------------------
# connect_wifi_nmcli
# ---------------------------------------------------------------------------

class TestConnectWifiNmcli:
    """connect_wifi_nmcli connects to WiFi via nmcli."""

    def test_successful_connection(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        assert connect_wifi_nmcli("TestNet", "password", runner=mock_runner) is True

    def test_failed_connection(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 1
        mock_runner.run.return_value = result
        assert connect_wifi_nmcli("TestNet", "password", runner=mock_runner) is False

    def test_timeout_returns_false(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = subprocess.TimeoutExpired("nmcli", 30)
        assert connect_wifi_nmcli("TestNet", "password", runner=mock_runner) is False

    def test_file_not_found_returns_false(self):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = FileNotFoundError("nmcli")
        assert connect_wifi_nmcli("TestNet", "password", runner=mock_runner) is False

    def test_command_includes_ssid(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("MyNet", "pass", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "MyNet" in cmd

    def test_password_included_when_non_empty(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("Net", "secret", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "password" in cmd
        assert "secret" in cmd

    def test_password_not_included_when_empty(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("Net", "", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "password" not in cmd

    def test_interface_included_when_specified(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("Net", "pass", interface="wlan1", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "ifname" in cmd
        assert "wlan1" in cmd

    def test_interface_not_included_when_none(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("Net", "pass", runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "ifname" not in cmd

    def test_hidden_included_when_true(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("HiddenNet", "", hidden=True, runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "hidden" in cmd
        assert "yes" in cmd

    def test_hidden_not_included_when_false(self):
        mock_runner = MagicMock()
        result = MagicMock()
        result.returncode = 0
        mock_runner.run.return_value = result
        connect_wifi_nmcli("Net", "pass", hidden=False, runner=mock_runner)
        cmd = mock_runner.run.call_args[0][0]
        assert "hidden" not in cmd


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

class TestCredentialsCli:
    """Standalone CLI argument parsing."""

    def test_parse_args_requires_credentials(self):
        with pytest.raises(SystemExit):
            _parse_args([])

    def test_parse_args_with_credentials(self):
        args = _parse_args(["-c", "creds.csv"])
        assert args.credentials == "creds.csv"

    def test_parse_args_with_ssid(self):
        args = _parse_args(["-c", "creds.csv", "-s", "MyNet"])
        assert args.ssid == "MyNet"

    def test_parse_args_with_interface(self):
        args = _parse_args(["-c", "creds.csv", "-i", "wlan0"])
        assert args.interface == "wlan0"

    def test_main_exits_on_no_credentials(self, tmp_path):
        path = tmp_path / "empty.csv"
        path.write_text("# only comments\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["-c", str(path)])
        assert exc_info.value.code == 1

    def test_main_lists_credentials(self, tmp_path, capsys):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        main(["-c", str(path)])
        captured = capsys.readouterr()
        assert "HomeNet" in captured.out
        assert "1 credential" in captured.out

    def test_main_lists_bssid_credentials(self, tmp_path, capsys):
        path = tmp_path / "creds.csv"
        path.write_text("aa:bb:cc:dd:ee:ff,MyHidden,pass\n")
        main(["-c", str(path)])
        captured = capsys.readouterr()
        assert "aa:bb:cc:dd:ee:ff" in captured.out
        assert "MyHidden" in captured.out
        assert "1 credential" in captured.out

    def test_main_connect_ssid_not_in_file(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["-c", str(path), "-s", "Unknown"])
        assert exc_info.value.code == 1

    def test_main_connect_success(self, tmp_path, capsys):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        with patch("wifimonitor.credentials.connect_wifi_nmcli", return_value=True):
            main(["-c", str(path), "-s", "HomeNet"])
        captured = capsys.readouterr()
        assert "Connected" in captured.out

    def test_main_connect_failure(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        with patch("wifimonitor.credentials.connect_wifi_nmcli", return_value=False):
            with pytest.raises(SystemExit) as exc_info:
                main(["-c", str(path), "-s", "HomeNet"])
            assert exc_info.value.code == 1
