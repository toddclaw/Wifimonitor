"""Tests for wifimonitor.platform_detect — platform and WiFi device detection.

Follows TDD agent standards:
- test_<what>_<condition>_<expected_outcome> naming
- One concept per test
- @pytest.mark.parametrize for repetitive cases
- Unhappy-path coverage (missing files, empty dirs, bad output)
"""

from __future__ import annotations

import subprocess

from wifimonitor.wifi_common import WifiDevice
from wifimonitor.platform_detect import (
    detect_platform,
    list_wifi_interfaces,
    detect_best_interface,
    _parse_iw_dev_output,
    _read_driver_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _FakeRunner:
    """A fake CommandRunner for injection-based tests."""

    def __init__(self):
        self.run_calls: list[tuple[list[str], dict]] = []
        self._run_results: list = []
        self._run_side_effects: list = []

    def set_run_results(self, *results):
        self._run_results = list(results)

    def set_run_side_effect(self, exc):
        self._run_side_effects = [exc]

    def run(self, cmd, **kwargs):
        self.run_calls.append((cmd, kwargs))
        if self._run_side_effects:
            raise self._run_side_effects.pop(0)
        if self._run_results:
            return self._run_results.pop(0)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def popen(self, cmd, **kwargs):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# detect_platform
# ---------------------------------------------------------------------------

class TestDetectPlatform:
    """detect_platform identifies laptop vs Raspberry Pi."""

    def test_laptop_on_x86_64(self):
        result = detect_platform(uname_machine="x86_64")
        assert result == "laptop"

    def test_pi_on_aarch64_with_raspberry(self):
        cpuinfo = "Hardware\t: BCM2835\nModel\t: Raspberry Pi 4 Model B\n"
        result = detect_platform(uname_machine="aarch64", cpuinfo=cpuinfo)
        assert result == "pi"

    def test_pi_on_armv7l_with_raspberry(self):
        cpuinfo = "Model\t: Raspberry Pi 3 Model B+\n"
        result = detect_platform(uname_machine="armv7l", cpuinfo=cpuinfo)
        assert result == "pi"

    def test_non_pi_aarch64_returns_laptop(self):
        cpuinfo = "Model\t: Some Other ARM Board\n"
        result = detect_platform(uname_machine="aarch64", cpuinfo=cpuinfo)
        assert result == "laptop"

    def test_empty_cpuinfo_returns_laptop(self):
        result = detect_platform(uname_machine="aarch64", cpuinfo="")
        assert result == "laptop"

    def test_none_cpuinfo_returns_laptop(self):
        result = detect_platform(uname_machine="aarch64", cpuinfo=None)
        assert result == "laptop"

    def test_i686_returns_laptop(self):
        result = detect_platform(uname_machine="i686")
        assert result == "laptop"


# ---------------------------------------------------------------------------
# _parse_iw_dev_output
# ---------------------------------------------------------------------------

IW_DEV_TWO_INTERFACES = """\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:01
\t\ttype managed
phy#1
\tInterface wlan1
\t\tifindex 4
\t\twdev 0x100000001
\t\taddr aa:bb:cc:dd:ee:02
\t\ttype managed
"""

IW_DEV_ONE_INTERFACE = """\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:01
\t\ttype managed
"""

IW_DEV_MONITOR_MODE = """\
phy#0
\tInterface wlan0mon
\t\tifindex 5
\t\twdev 0x2
\t\taddr aa:bb:cc:dd:ee:01
\t\ttype monitor
"""


class TestParseIwDevOutput:
    """_parse_iw_dev_output extracts interface names from iw dev output."""

    def test_two_interfaces(self):
        result = _parse_iw_dev_output(IW_DEV_TWO_INTERFACES)
        assert result == [("wlan0", "phy0"), ("wlan1", "phy1")]

    def test_one_interface(self):
        result = _parse_iw_dev_output(IW_DEV_ONE_INTERFACE)
        assert result == [("wlan0", "phy0")]

    def test_empty_string_returns_empty(self):
        result = _parse_iw_dev_output("")
        assert result == []

    def test_no_interfaces_returns_empty(self):
        result = _parse_iw_dev_output("some random text")
        assert result == []

    def test_monitor_interface_detected(self):
        result = _parse_iw_dev_output(IW_DEV_MONITOR_MODE)
        assert result == [("wlan0mon", "phy0")]


# ---------------------------------------------------------------------------
# _read_driver_name
# ---------------------------------------------------------------------------

class TestReadDriverName:
    """_read_driver_name reads the driver name from sysfs."""

    def test_known_driver(self, tmp_path):
        driver_link = tmp_path / "wlan0" / "device" / "driver"
        driver_link.parent.mkdir(parents=True)
        # Simulate a symlink whose basename is the driver name
        (tmp_path / "wlan0" / "device" / "driver").mkdir()
        driver_target = tmp_path / "drivers" / "ath9k"
        driver_target.mkdir(parents=True)
        driver_link.rmdir()
        driver_link.symlink_to(driver_target)
        result = _read_driver_name("wlan0", sysfs_net=str(tmp_path))
        assert result == "ath9k"

    def test_missing_driver_link_returns_unknown(self, tmp_path):
        iface_dir = tmp_path / "wlan0"
        iface_dir.mkdir()
        result = _read_driver_name("wlan0", sysfs_net=str(tmp_path))
        assert result == "unknown"

    def test_missing_interface_returns_unknown(self, tmp_path):
        result = _read_driver_name("wlan99", sysfs_net=str(tmp_path))
        assert result == "unknown"


# ---------------------------------------------------------------------------
# list_wifi_interfaces
# ---------------------------------------------------------------------------

class TestListWifiInterfaces:
    """list_wifi_interfaces enumerates WiFi devices from iw dev + sysfs."""

    def test_returns_wifi_devices_from_iw_dev(self, tmp_path):
        fake = _FakeRunner()
        # iw dev returns two interfaces
        fake.set_run_results(
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=IW_DEV_TWO_INTERFACES, stderr="",
            ),
            # iw phy phy0 info (supports monitor)
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Supported interface modes:\n\t\t * managed\n\t\t * monitor\n",
                stderr="",
            ),
            # iw phy phy1 info (no monitor)
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Supported interface modes:\n\t\t * managed\n",
                stderr="",
            ),
        )
        # Create sysfs dirs with operstate
        for name in ("wlan0", "wlan1"):
            iface = tmp_path / name
            iface.mkdir()
            (iface / "operstate").write_text("up\n")

        devices = list_wifi_interfaces(runner=fake, sysfs_net=str(tmp_path))
        assert len(devices) == 2
        assert devices[0].name == "wlan0"
        assert devices[0].supports_monitor is True
        assert devices[0].is_up is True
        assert devices[1].name == "wlan1"
        assert devices[1].supports_monitor is False

    def test_iw_not_found_returns_empty(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(FileNotFoundError("iw not found"))
        devices = list_wifi_interfaces(runner=fake)
        assert devices == []

    def test_iw_timeout_returns_empty(self):
        fake = _FakeRunner()
        fake.set_run_side_effect(subprocess.TimeoutExpired(cmd=["iw"], timeout=5))
        devices = list_wifi_interfaces(runner=fake)
        assert devices == []

    def test_iw_failure_returns_empty(self):
        fake = _FakeRunner()
        fake.set_run_results(
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error"),
        )
        devices = list_wifi_interfaces(runner=fake)
        assert devices == []

    def test_interface_down_detected(self, tmp_path):
        fake = _FakeRunner()
        fake.set_run_results(
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=IW_DEV_ONE_INTERFACE, stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="Supported interface modes:\n\t\t * managed\n",
                stderr="",
            ),
        )
        iface = tmp_path / "wlan0"
        iface.mkdir()
        (iface / "operstate").write_text("down\n")

        devices = list_wifi_interfaces(runner=fake, sysfs_net=str(tmp_path))
        assert len(devices) == 1
        assert devices[0].is_up is False


# ---------------------------------------------------------------------------
# detect_best_interface
# ---------------------------------------------------------------------------

class TestDetectBestInterface:
    """detect_best_interface picks the best WiFi interface automatically."""

    def test_prefers_monitor_capable_interface(self):
        devices = [
            WifiDevice(name="wlan0", driver="iwlwifi", supports_monitor=False, is_up=True),
            WifiDevice(name="wlan1", driver="ath9k", supports_monitor=True, is_up=True),
        ]
        assert detect_best_interface(devices, monitor_mode=True) == "wlan1"

    def test_prefers_up_interface(self):
        devices = [
            WifiDevice(name="wlan0", driver="iwlwifi", supports_monitor=False, is_up=False),
            WifiDevice(name="wlan1", driver="ath9k", supports_monitor=False, is_up=True),
        ]
        assert detect_best_interface(devices, monitor_mode=False) == "wlan1"

    def test_empty_list_returns_none(self):
        assert detect_best_interface([], monitor_mode=False) is None

    def test_single_device_returned(self):
        devices = [WifiDevice(name="wlan0", driver="iwlwifi", supports_monitor=False, is_up=True)]
        assert detect_best_interface(devices, monitor_mode=False) == "wlan0"

    def test_monitor_mode_no_capable_device_returns_first(self):
        devices = [
            WifiDevice(name="wlan0", driver="iwlwifi", supports_monitor=False, is_up=True),
        ]
        assert detect_best_interface(devices, monitor_mode=True) == "wlan0"

    def test_all_down_returns_first(self):
        devices = [
            WifiDevice(name="wlan0", driver="d1", supports_monitor=False, is_up=False),
            WifiDevice(name="wlan1", driver="d2", supports_monitor=False, is_up=False),
        ]
        assert detect_best_interface(devices, monitor_mode=False) == "wlan0"
