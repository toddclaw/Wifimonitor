"""Airodump-ng scanner and monitor-mode helpers.

Manages an airodump-ng process in monitor mode, parses its CSV output
for client counts, and provides helpers for enabling/disabling monitor
mode on WiFi interfaces.

Typical usage::

    scanner = AirodumpScanner(interface="wlan0")
    ok, reason = scanner.start()
    if ok:
        networks = scanner.scan()
        scanner.stop()
"""

from __future__ import annotations

import glob
import io
import logging
import os
import re
import signal
import subprocess
import time
from datetime import datetime

from wifimonitor.wifi_common import (
    CommandRunner,
    Network,
    SubprocessRunner,
    _minimal_env,
    parse_airodump_csv,
)
from wifimonitor.scanning.nmcli import scan_wifi_nmcli

# -- Defaults --
_LOGGER = logging.getLogger("wifi_monitor_nitro5")
AIRODUMP_PREFIX = "/tmp/wifi_monitor_nitro5"
AIRODUMP_STDERR_LOG = "/tmp/wifi_monitor_nitro5_airodump.log"
AIRODUMP_MONITOR_LOG = "/tmp/wifi_monitor_nitro5_monitor.log"
AIRODUMP_DEBUG_LOG = "/tmp/wifi_monitor_nitro5_debug.log"
AIRODUMP_WRITE_INTERVAL = 5
AIRODUMP_STARTUP_WAIT = 6  # wait for first CSV write (airodump --write-interval is 5s)
_DEFAULT_RUNNER = SubprocessRunner()


# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def _interface_supports_monitor(interface: str, runner: CommandRunner | None = None) -> bool:
    """Check if the interface's phy supports monitor mode via iw list.

    Returns True if monitor mode is in supported interface modes, or if
    we cannot determine (e.g. iw not found) — in that case we allow the attempt.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        # Get wiphy index for this interface
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            return True  # Allow attempt; will fail later with diagnostics
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        match = re.search(r"wiphy\s+(\d+)", out)
        if not match:
            return True
        wiphy = match.group(1)
        # Check phy's supported interface modes
        phy_result = runner.run(
            ["iw", "phy", f"phy{wiphy}", "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if phy_result.returncode != 0:
            return True
        phy_out = phy_result.stdout if isinstance(phy_result.stdout, str) else phy_result.stdout.decode("utf-8", errors="replace")
        # Look for "Supported interface modes" section and check for monitor
        in_modes = False
        for line in phy_out.splitlines():
            if "Supported interface modes" in line:
                in_modes = True
                continue
            if in_modes:
                if re.match(r"\s+Band\s+", line) or re.match(r"\s+max #", line):
                    break  # Next section
                if "monitor" in line.lower():
                    return True
        return False  # Found modes section but no monitor
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return True  # Allow attempt


def _set_nm_managed(interface: str, managed: bool, runner: CommandRunner | None = None) -> bool:
    """Tell NetworkManager to manage or unmanage the interface.

    Prevents NetworkManager from reclaiming the interface during monitor mode.
    Returns True if nmcli succeeded, False otherwise.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        result = runner.run(
            ["nmcli", "device", "set", interface, "managed", "yes" if managed else "no"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _enable_monitor_mode(interface: str, runner: CommandRunner | None = None) -> bool:
    """Put a WiFi interface into monitor mode using iw.

    Asks NetworkManager to unmanage the interface first so it does not reclaim it.
    Returns True if successful, False otherwise.
    On failure, logs the failing command and its stderr/stdout to AIRODUMP_MONITOR_LOG.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        runner.run(
            ["nmcli", "device", "disconnect", interface],
            capture_output=True,
            timeout=5,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    if not _set_nm_managed(interface, False, runner):
        _log_monitor_failure(
            f"nmcli device set {interface} managed no failed — NetworkManager may reclaim the interface",
            None,
            None,
            None,
        )
        return False
    time.sleep(0.5)
    cmds = [
        ["sudo", "ip", "link", "set", interface, "down"],
        ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
        ["sudo", "ip", "link", "set", interface, "up"],
    ]
    iw_set_type_returncode: int | None = None
    try:
        for cmd in cmds:
            result = runner.run(cmd, capture_output=True, timeout=10, env=env)
            if ["sudo", "iw", "dev", interface, "set", "type", "monitor"] == cmd:
                iw_set_type_returncode = result.returncode
            if result.returncode != 0:
                _log_monitor_failure(
                    f"Command failed: {' '.join(cmd)}",
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
                return False
        if not _verify_monitor_mode(interface, runner, iw_set_type_returncode):
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log_monitor_failure(
            f"Exception running monitor mode command: {e!r}",
            None,
            None,
            None,
        )
        return False


def _verify_monitor_mode(
    interface: str,
    runner: CommandRunner | None = None,
    iw_set_type_returncode: int | None = None,
) -> bool:
    """Verify the interface is actually in monitor mode via iw dev info."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            _log_monitor_failure(
                f"iw dev {interface} info failed",
                result.returncode,
                result.stdout,
                result.stderr,
            )
            return False
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        if "type monitor" not in out:
            hints: list[str] = []
            if iw_set_type_returncode == 0:
                hints.append(
                    "Driver may not actually support monitor mode (common with Intel laptop WiFi). "
                    "Try a USB adapter (Atheros AR9271, Ralink RT3070)."
                )
            hints.append(
                f"For permanent unmanage: add unmanaged-devices=interface-name:{interface} "
                f"to /etc/NetworkManager/conf.d/monitor.conf and reboot."
            )
            msg = (
                f"Interface {interface} is not type monitor (iw output: {out!r}). "
                + " ".join(hints)
            )
            _log_monitor_failure(msg, None, None, None)
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        _log_monitor_failure(
            f"Exception verifying monitor mode: {e!r}",
            None,
            None,
            None,
        )
        return False


def _log_airodump_exit(
    returncode: int | None,
    cmd: list[str],
    stderr_file: io.TextIOWrapper | None,
) -> None:
    """Append airodump exit diagnosis to the stderr log for debugging."""
    try:
        if stderr_file is not None:
            stderr_file.flush()
        with open(AIRODUMP_STDERR_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n[airodump exited] returncode={returncode}\n")
            f.write(f"[command] {' '.join(cmd)}\n")
    except OSError:
        pass


def _log_monitor_failure(
    msg: str,
    returncode: int | None,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
) -> None:
    """Write monitor mode failure details to AIRODUMP_MONITOR_LOG."""
    def _decode(v: str | bytes | None) -> str:
        if v is None:
            return "(none)"
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="replace")
        return v

    try:
        with open(AIRODUMP_MONITOR_LOG, "a", encoding="utf-8") as f:
            f.write(f"[monitor] {msg}\n")
            if returncode is not None:
                f.write(f"  returncode: {returncode}\n")
            out = _decode(stdout)
            err = _decode(stderr)
            if out.strip():
                f.write(f"  stdout: {out}\n")
            if err.strip():
                f.write(f"  stderr: {err}\n")
            f.write("\n")
    except OSError:
        pass


def _disable_monitor_mode(interface: str, runner: CommandRunner | None = None) -> None:
    """Restore a WiFi interface to managed mode and give it back to NetworkManager."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    cmds = [
        ["sudo", "ip", "link", "set", interface, "down"],
        ["sudo", "iw", "dev", interface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", interface, "up"],
    ]
    for cmd in cmds:
        try:
            runner.run(cmd, capture_output=True, timeout=10, env=env)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    _set_nm_managed(interface, True, runner)


def _enable_monitor_mode_virtual(
    interface: str, runner: CommandRunner | None = None
) -> str | None:
    """Create a new virtual monitor interface via iw phy interface add.

    Leaves the original interface in managed mode; avoids NetworkManager reclaim.
    Returns the monitor interface name (e.g. 'mon0') on success, None on failure.
    """
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    mon_name = "mon0"
    try:
        result = runner.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if result.returncode != 0:
            return None
        out = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
        match = re.search(r"wiphy\s+(\d+)", out)
        if not match:
            return None
        wiphy = match.group(1)
        result = runner.run(
            ["sudo", "iw", "phy", f"phy{wiphy}", "interface", "add", mon_name, "type", "monitor"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            return None
        result = runner.run(
            ["sudo", "ip", "link", "set", mon_name, "up"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            try:
                runner.run(
                    ["sudo", "iw", "dev", mon_name, "del"],
                    capture_output=True,
                    timeout=5,
                    env=env,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            return None
        return mon_name
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _disable_monitor_mode_virtual(
    mon_interface: str, runner: CommandRunner | None = None
) -> None:
    """Remove a virtual monitor interface created by _enable_monitor_mode_virtual."""
    runner = runner or _DEFAULT_RUNNER
    env = _minimal_env()
    try:
        runner.run(
            ["sudo", "iw", "dev", mon_interface, "del"],
            capture_output=True,
            timeout=10,
            env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


# ---------------------------------------------------------------------------
# AirodumpScanner class
# ---------------------------------------------------------------------------

class AirodumpScanner:
    """Manage an airodump-ng process and parse its CSV for client counts.

    Use start() to enable monitor mode and launch airodump-ng, scan() to read
    the latest CSV and return networks with client counts, and stop() to clean up.
    """

    def __init__(
        self,
        interface: str,
        prefix: str = AIRODUMP_PREFIX,
        runner: CommandRunner | None = None,
        *,
        debug: bool = False,
    ) -> None:
        self.interface = interface
        self.prefix = prefix
        self._runner = runner or _DEFAULT_RUNNER
        self._proc: subprocess.Popen[bytes] | None = None
        self._monitor_enabled = False
        self._monitor_interface = interface
        self._monitor_is_virtual = False
        self._debug = debug
        self._stderr_file: io.TextIOWrapper | None = None
        self._last_cmd: list[str] = []
        self._exit_logged = False
        self._channels: list[int] = []

    def start(self) -> tuple[bool, str | None]:
        """Enable monitor mode and start airodump-ng.

        Tries virtual monitor interface first (iw phy interface add); falls back
        to converting the existing interface (iw dev set type monitor).

        Returns:
            (True, None) if successful.
            (False, reason) on failure. reason is "monitor_mode" if iw/ip failed,
            "airodump_exit" if airodump exited immediately, or "airodump_spawn"
            if airodump could not be started (FileNotFoundError, etc.).
        """
        supports_monitor = _interface_supports_monitor(
            self.interface, self._runner
        )
        if self._debug:
            _LOGGER.debug(
                "_interface_supports_monitor(%s)=%s",
                self.interface,
                supports_monitor,
            )
        if not supports_monitor:
            return False, "monitor_unsupported"

        # Pre-scan while the interface is still in managed mode to discover which
        # channels visible APs are on.  Passing these to airodump-ng via -c keeps it
        # focused on those channels rather than hopping all 40+ channels with --band abg.
        # Staying on the relevant channels dramatically increases the chance of capturing
        # the data/management frames that reveal client associations.
        _pre_networks = scan_wifi_nmcli(interface=self.interface, runner=self._runner)
        self._channels = sorted(set(n.channel for n in _pre_networks if n.channel > 0))
        if self._debug:
            _LOGGER.debug(
                "pre-scan: %d channel(s) discovered: %s",
                len(self._channels),
                self._channels,
            )

        try:
            self._runner.run(
                ["rfkill", "unblock", "wifi"],
                capture_output=True,
                timeout=5,
                env=_minimal_env(),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        mon_iface = _enable_monitor_mode_virtual(self.interface, self._runner)
        if mon_iface is not None:
            self._monitor_interface = mon_iface
            self._monitor_is_virtual = True
            self._monitor_enabled = True
            if self._debug:
                _LOGGER.debug(
                    "virtual monitor: success monitor_interface=%s",
                    self._monitor_interface,
                )
        else:
            if self._debug:
                _LOGGER.debug(
                    "virtual monitor: failed, trying direct monitor on %s",
                    self.interface,
                )
            if not _enable_monitor_mode(self.interface, self._runner):
                return False, "monitor_mode"
            self._monitor_interface = self.interface
            self._monitor_is_virtual = False
            self._monitor_enabled = True
            if self._debug:
                _LOGGER.debug(
                    "direct monitor: success monitor_interface=%s",
                    self._monitor_interface,
                )
        self._cleanup_old_files()
        env = _minimal_env()
        if os.geteuid() == 0:
            airodump_cmd: tuple[str, ...] = ("airodump-ng",)
        else:
            airodump_cmd = ("sudo", "airodump-ng")
        # Use discovered channels for targeted scanning; fall back to all bands if
        # the pre-scan returned nothing (e.g. nmcli not available, root required).
        if self._channels:
            channel_arg = ["-c", ",".join(str(c) for c in self._channels)]
        else:
            channel_arg = ["--band", "abg"]
        cmd = [
            *airodump_cmd,
            self._monitor_interface,
            *channel_arg,
            "--write", self.prefix,
            "--output-format", "csv",
            "--write-interval", str(AIRODUMP_WRITE_INTERVAL),
            "--hoptime", "500",
            "--background", "1",
        ]
        stderr_dest: int | io.TextIOWrapper = subprocess.DEVNULL
        try:
            self._stderr_file = open(AIRODUMP_STDERR_LOG, "w", encoding="utf-8")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._stderr_file.write(
                f"[{ts}] wifi_monitor_nitro5: capturing airodump-ng stderr\n"
            )
            self._stderr_file.write(f"[command] {' '.join(cmd)}\n")
            self._stderr_file.flush()
            stderr_dest = self._stderr_file
            if self._debug:
                _LOGGER.debug(
                    "airodump stderr -> %s | cwd=/tmp | prefix=%s",
                    AIRODUMP_STDERR_LOG,
                    self.prefix,
                )
                _LOGGER.debug("airodump command: %s", " ".join(cmd))
        except OSError:
            pass
        self._last_cmd = cmd
        try:
            self._proc = self._runner.popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_dest,
                stdin=subprocess.DEVNULL,
                env=env,
                cwd="/tmp",
                text=False,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError):
            self.stop()
            return False, "airodump_spawn"
        time.sleep(AIRODUMP_STARTUP_WAIT)
        if self._proc.poll() is not None:
            _log_airodump_exit(self._proc.returncode, cmd, self._stderr_file)
            _LOGGER.debug(
                "airodump exited with code %s (see %s)",
                self._proc.returncode,
                AIRODUMP_STDERR_LOG,
            )
            self.stop()
            return False, "airodump_exit"
        return True, None

    def stop(self) -> None:
        """Stop airodump-ng and restore managed mode."""
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None
        if self._monitor_enabled:
            if self._monitor_is_virtual:
                _disable_monitor_mode_virtual(self._monitor_interface, self._runner)
            else:
                _disable_monitor_mode(self._monitor_interface, self._runner)
            self._monitor_enabled = False
        self._cleanup_old_files()

    def is_alive(self) -> bool:
        """Return True if the airodump process is still running."""
        return self._proc is not None and self._proc.poll() is None

    def log_exit_if_dead(self) -> bool:
        """If the process has exited, append diagnosis to the log (once). Returns False if dead."""
        if self._proc is None or self._proc.poll() is None:
            return True
        if not self._exit_logged:
            _log_airodump_exit(self._proc.returncode, self._last_cmd, self._stderr_file)
            self._exit_logged = True
        return False

    def scan(self) -> list[Network]:
        """Read the latest airodump-ng CSV and return networks with client counts.

        When using a virtual monitor interface (mon0), the original interface
        (e.g. wlp4s0) stays in managed mode. In that case, use nmcli to get the
        full BSSID list and overlay client counts from airodump. This avoids the
        limited AP visibility that monitor mode often has on laptop WiFi.
        """
        csv_path = self._latest_csv()
        client_counts: dict[str, int] = {}
        airodump_networks: list[Network] = []

        if csv_path:
            try:
                with open(csv_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                airodump_networks, client_counts = parse_airodump_csv(content)
            except OSError:
                if self._debug:
                    _LOGGER.debug("scan failed to read %s", csv_path)

        if self._monitor_is_virtual:
            # Original interface is still managed: use nmcli for full BSSID list.
            networks = scan_wifi_nmcli(
                interface=self.interface, runner=self._runner
            )
            for net in networks:
                net.clients = client_counts.get(net.bssid, 0)
            if self._debug:
                _LOGGER.debug(
                    "hybrid scan: nmcli=%d networks, airodump clients for %d BSSIDs",
                    len(networks),
                    len(client_counts),
                )
            return networks

        # Direct monitor mode: airodump-only.
        if not csv_path:
            return []

        if self._debug:
            glob_pattern = f"{self.prefix}-*.csv"
            files = sorted(glob.glob(glob_pattern))
            total_clients = sum(client_counts.values())
            _LOGGER.debug(
                "scan glob pattern=%s files=%s",
                glob_pattern,
                files if files else "none",
            )
            _LOGGER.debug(
                "scan selected_csv=%s",
                csv_path,
            )
            _LOGGER.debug(
                "scan parse: networks=%d clients_total=%d client_counts=%s",
                len(airodump_networks),
                total_clients,
                dict(client_counts),
            )
            for i, net in enumerate(airodump_networks[:10]):
                ssid_display = net.ssid if net.ssid else "<hidden>"
                _LOGGER.debug(
                    "scan network[%d]: bssid=%s ssid=%s ch=%s signal=%s clients=%s",
                    i,
                    net.bssid,
                    ssid_display,
                    net.channel,
                    net.signal,
                    net.clients,
                )
            if len(airodump_networks) > 10:
                _LOGGER.debug(
                    "scan ... and %d more networks (truncated)",
                    len(airodump_networks) - 10,
                )

        return airodump_networks

    def _latest_csv(self) -> str | None:
        files = sorted(glob.glob(f"{self.prefix}-*.csv"))
        return files[-1] if files else None

    def _cleanup_old_files(self) -> None:
        for path in glob.glob(f"{self.prefix}-*"):
            try:
                os.remove(path)
            except OSError:
                pass
