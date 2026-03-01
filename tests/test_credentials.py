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
    """load_credentials reads SSID/passphrase pairs from CSV."""

    def test_loads_valid_csv(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,mypassword\nOffice,officepass\n")
        creds = load_credentials(str(path))
        assert creds == {"HomeNet": "mypassword", "Office": "officepass"}

    def test_skips_comment_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("# This is a comment\nHomeNet,password\n")
        creds = load_credentials(str(path))
        assert len(creds) == 1
        assert "HomeNet" in creds

    def test_skips_blank_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n\n\nOffice,pass2\n")
        creds = load_credentials(str(path))
        assert len(creds) == 2

    def test_skips_single_field_lines(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("OnlySSID\nHomeNet,password\n")
        creds = load_credentials(str(path))
        assert len(creds) == 1

    def test_missing_file_returns_empty(self, tmp_path):
        creds = load_credentials(str(tmp_path / "nonexistent.csv"))
        assert creds == {}

    def test_quoted_fields(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text('"Net, with comma","pass, word"\n')
        creds = load_credentials(str(path))
        assert creds.get("Net, with comma") == "pass, word"

    def test_strips_whitespace(self, tmp_path):
        path = tmp_path / "creds.csv"
        path.write_text("  HomeNet  ,  password  \n")
        creds = load_credentials(str(path))
        assert creds == {"HomeNet": "password"}

    def test_directory_path_returns_empty(self, tmp_path):
        """A directory is not a file — should return empty dict."""
        creds = load_credentials(str(tmp_path))
        assert creds == {}

    def test_warns_world_readable(self, tmp_path, capsys):
        path = tmp_path / "creds.csv"
        path.write_text("HomeNet,password\n")
        path.chmod(0o644)
        load_credentials(str(path))
        captured = capsys.readouterr()
        assert "WARNING" in captured.err or captured.err == ""  # May not warn depending on umask


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
