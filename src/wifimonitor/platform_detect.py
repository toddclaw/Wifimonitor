"""Platform and WiFi device detection for Wifimonitor.

Detects whether we're running on a laptop or Raspberry Pi, enumerates
WiFi interfaces via ``iw dev`` and sysfs, and selects the best interface
for the requested operating mode.

All external I/O is injectable for testability:
- ``detect_platform`` accepts ``uname_machine`` and ``cpuinfo`` strings
- ``list_wifi_interfaces`` accepts a ``CommandRunner`` and ``sysfs_net`` path
- ``_read_driver_name`` accepts a ``sysfs_net`` path
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess

from wifimonitor.wifi_common import CommandRunner, SubprocessRunner, WifiDevice

logger = logging.getLogger(__name__)

_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def detect_platform(
    *,
    uname_machine: str | None = None,
    cpuinfo: str | None = None,
) -> str:
    """Detect whether we're on a laptop or Raspberry Pi.

    Args:
        uname_machine: Override for ``platform.machine()`` (for testing).
        cpuinfo: Override for ``/proc/cpuinfo`` contents (for testing).
            Pass ``None`` to read from the real file (default on ARM).

    Returns:
        ``"pi"`` if running on a Raspberry Pi, ``"laptop"`` otherwise.
    """
    machine = uname_machine or platform.machine()

    # x86 / x86_64 is never a Pi
    if machine in ("x86_64", "i686", "i386"):
        return "laptop"

    # ARM-based — check /proc/cpuinfo for Raspberry Pi signature
    if cpuinfo is None:
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
        except OSError:
            cpuinfo = ""

    if cpuinfo and "raspberry pi" in cpuinfo.lower():
        return "pi"

    return "laptop"


# ---------------------------------------------------------------------------
# iw dev output parsing
# ---------------------------------------------------------------------------

# Matches "phy#N" lines
_PHY_RE = re.compile(r"^phy#(\d+)")
# Matches "\tInterface <name>" lines
_IFACE_RE = re.compile(r"^\tInterface\s+(\S+)")


def _parse_iw_dev_output(output: str) -> list[tuple[str, str]]:
    """Parse ``iw dev`` output into ``[(iface_name, phy_name), ...]``.

    Args:
        output: Raw stdout from ``iw dev``.

    Returns:
        List of ``(interface_name, phy_name)`` tuples.  ``phy_name`` uses
        the format ``"phy0"`` (without the ``#``).
    """
    results: list[tuple[str, str]] = []
    current_phy: str | None = None

    for line in output.splitlines():
        phy_match = _PHY_RE.match(line)
        if phy_match:
            current_phy = f"phy{phy_match.group(1)}"
            continue

        iface_match = _IFACE_RE.match(line)
        if iface_match and current_phy is not None:
            results.append((iface_match.group(1), current_phy))

    return results


# ---------------------------------------------------------------------------
# sysfs driver name
# ---------------------------------------------------------------------------

def _read_driver_name(
    iface: str,
    *,
    sysfs_net: str = "/sys/class/net",
) -> str:
    """Read the kernel driver name for *iface* from sysfs.

    The driver is determined by reading the basename of the symlink at
    ``/sys/class/net/<iface>/device/driver``.

    Args:
        iface: Interface name (e.g. ``"wlan0"``).
        sysfs_net: Override for the sysfs net directory (for testing).

    Returns:
        Driver name string, or ``"unknown"`` if it cannot be determined.
    """
    driver_path = os.path.join(sysfs_net, iface, "device", "driver")
    try:
        target = os.readlink(driver_path)
        return os.path.basename(target)
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------

def _check_monitor_support(
    phy_name: str,
    runner: CommandRunner,
) -> bool:
    """Check if *phy_name* supports monitor mode via ``iw phy info``."""
    try:
        result = runner.run(
            ["iw", "phy", phy_name, "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return False
        return "monitor" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _read_operstate(
    iface: str,
    sysfs_net: str,
) -> bool:
    """Return True if the interface operstate is ``"up"``."""
    operstate_path = os.path.join(sysfs_net, iface, "operstate")
    try:
        with open(operstate_path) as f:
            return f.read().strip() == "up"
    except OSError:
        return False


def list_wifi_interfaces(
    *,
    runner: CommandRunner | None = None,
    sysfs_net: str = "/sys/class/net",
) -> list[WifiDevice]:
    """Enumerate WiFi interfaces using ``iw dev`` and sysfs.

    Args:
        runner: Command runner for subprocess calls. Uses default if ``None``.
        sysfs_net: Override for the sysfs net directory (for testing).

    Returns:
        List of :class:`WifiDevice` objects, one per detected interface.
        Returns an empty list if ``iw`` is not available or fails.
    """
    if runner is None:
        runner = _DEFAULT_RUNNER

    # Run iw dev to enumerate interfaces
    try:
        result = runner.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        logger.debug("iw dev failed or not found")
        return []

    if result.returncode != 0:
        logger.debug("iw dev returned non-zero: %d", result.returncode)
        return []

    interfaces = _parse_iw_dev_output(result.stdout)
    if not interfaces:
        return []

    devices: list[WifiDevice] = []
    for iface_name, phy_name in interfaces:
        driver = _read_driver_name(iface_name, sysfs_net=sysfs_net)
        supports_monitor = _check_monitor_support(phy_name, runner)
        is_up = _read_operstate(iface_name, sysfs_net)

        devices.append(WifiDevice(
            name=iface_name,
            driver=driver,
            supports_monitor=supports_monitor,
            is_up=is_up,
        ))

    return devices


# ---------------------------------------------------------------------------
# Best interface selection
# ---------------------------------------------------------------------------

def detect_best_interface(
    devices: list[WifiDevice],
    *,
    monitor_mode: bool = False,
) -> str | None:
    """Pick the best WiFi interface from the detected devices.

    Selection priority:
    1. If *monitor_mode*, prefer an interface that supports monitor mode.
    2. Prefer an interface that is currently up.
    3. Fall back to the first interface in the list.

    Args:
        devices: List of detected WiFi devices.
        monitor_mode: Whether monitor mode support is desired.

    Returns:
        Interface name string, or ``None`` if *devices* is empty.
    """
    if not devices:
        return None

    def _score(device: WifiDevice) -> tuple[int, int]:
        """Higher score = better candidate."""
        monitor_score = 1 if (monitor_mode and device.supports_monitor) else 0
        up_score = 1 if device.is_up else 0
        return (monitor_score, up_score)

    best = max(devices, key=_score)
    return best.name
