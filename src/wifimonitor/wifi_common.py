"""Shared data structures and helpers for WiFi Monitor variants."""

from __future__ import annotations

import csv
import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Any, IO, Protocol

logger = logging.getLogger(__name__)

# -- Colors (RGB tuples for PiTFT; also used as constants by Rich TUI) --
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
YELLOW = (255, 255, 0)
RED = (255, 0, 0)
CYAN = (0, 255, 255)
GRAY = (128, 128, 128)
DIM = (40, 40, 40)
ORANGE = (255, 165, 0)

# Canonical mapping from RGB tuple to Rich color name.
# Kept alongside the RGB constants so they cannot drift apart.
COLOR_TO_RICH: dict[tuple, str] = {
    BLACK: "black",
    WHITE: "white",
    GREEN: "green",
    YELLOW: "yellow",
    RED: "red",
    CYAN: "cyan",
    GRAY: "grey50",
    DIM: "grey15",
    ORANGE: "dark_orange",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Network:
    """A detected WiFi network."""

    bssid: str
    ssid: str
    signal: int = -100       # dBm
    channel: int = 0
    security: str = "Open"
    clients: int = 0


@dataclass
class WifiDevice:
    """A detected WiFi interface on the system."""

    name: str                   # e.g., "wlan0"
    driver: str = "unknown"     # e.g., "ath9k", "iwlwifi"
    supports_monitor: bool = False
    is_up: bool = False


@dataclass
class KnownNetwork:
    """A trusted WiFi network from the known-good baseline.

    Used for rogue AP detection: any scanned network matching the SSID but
    *not* matching a known BSSID (or appearing on an unexpected channel)
    is flagged as potentially rogue.
    """

    ssid: str
    bssid: str          # lowercase MAC, e.g. "aa:bb:cc:dd:ee:01"
    channel: int = 0    # 0 means any channel is acceptable


@dataclass
class RogueAlert:
    """An alert for a potentially rogue access point.

    Generated when a scanned network matches a known SSID but has an
    unrecognised BSSID or appears on an unexpected channel.
    """

    network: Network            # the scanned network that triggered the alert
    reason: str                 # "unknown_bssid" or "unexpected_channel"
    expected_bssids: list[str]  # known BSSIDs for this SSID
    expected_channels: list[int]  # known channels (0 = any)


@dataclass
class DeauthEvent:
    """A single captured deauthentication or disassociation frame.

    Parsed from tcpdump ``-e`` output on a monitor-mode interface.
    """

    bssid: str          # lowercase MAC, e.g. "00:14:6c:7e:40:80"
    source: str         # SA — who sent the frame (lowercase)
    destination: str    # DA — target (lowercase), "ff:ff:ff:ff:ff:ff" for broadcast
    reason: str         # reason text from tcpdump, e.g. "Class 3 frame received…"
    subtype: str        # "deauth" or "disassoc"


# ---------------------------------------------------------------------------
# Scanner / Renderer protocols (composition seams)
# ---------------------------------------------------------------------------

class ScannerProtocol(Protocol):
    """Protocol for WiFi network scanners.

    Any class with a ``scan()`` method returning ``list[Network]`` satisfies
    this protocol.  Enables swapping nmcli, airodump-ng, or mock scanners
    without modifying the caller.
    """

    def scan(self) -> list[Network]:
        """Scan for WiFi networks and return detected networks."""
        ...  # pragma: no cover


class RendererProtocol(Protocol):
    """Protocol for network display renderers.

    Any class with a ``render(networks, **kwargs)`` method satisfies this
    protocol.  Enables swapping Rich TUI, PiTFT, or plain-text renderers
    without modifying the caller.
    """

    def render(self, networks: list[Network], **kwargs: Any) -> Any:
        """Render *networks* into a displayable object."""
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Command runner protocol (subprocess injection seam)
# ---------------------------------------------------------------------------

class CommandRunner(Protocol):
    """Protocol for running external commands.

    Provides an injection seam so callers can substitute a fake runner in
    tests instead of patching ``subprocess`` globally.
    """

    def run(
        self,
        cmd: list[str],
        *,
        capture_output: bool = True,
        text: bool = True,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[Any]:
        """Run *cmd* and return a CompletedProcess."""
        ...  # pragma: no cover

    def popen(
        self,
        cmd: list[str],
        *,
        stdout: int | None = None,
        stderr: int | None | IO[Any] = None,
        stdin: int | None = None,
        text: bool = True,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        start_new_session: bool = False,
    ) -> subprocess.Popen[Any]:
        """Launch *cmd* asynchronously and return a Popen handle."""
        ...  # pragma: no cover


class SubprocessRunner:
    """Default CommandRunner that delegates to the real ``subprocess`` module."""

    def run(
        self,
        cmd: list[str],
        *,
        capture_output: bool = True,
        text: bool = True,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[Any]:
        """Run *cmd* via ``subprocess.run``."""
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            env=env,
        )

    def popen(
        self,
        cmd: list[str],
        *,
        stdout: int | None = None,
        stderr: int | None | IO[Any] = None,
        stdin: int | None = None,
        text: bool = True,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        start_new_session: bool = False,
    ) -> subprocess.Popen[Any]:
        """Launch *cmd* via ``subprocess.Popen``."""
        return subprocess.Popen(
            cmd,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            text=text,
            env=env,
            cwd=cwd,
            start_new_session=start_new_session,
        )


# ---------------------------------------------------------------------------
# Signal / security helpers
# ---------------------------------------------------------------------------

def signal_to_bars(signal_dbm: int) -> int:
    """Convert signal strength in dBm to a bar count (0-4)."""
    if signal_dbm >= -50:
        return 4
    if signal_dbm >= -60:
        return 3
    if signal_dbm >= -70:
        return 2
    if signal_dbm >= -80:
        return 1
    return 0


def signal_color(signal_dbm: int) -> tuple:
    """Return an RGB color tuple based on signal strength."""
    if signal_dbm >= -50:
        return GREEN
    if signal_dbm >= -65:
        return YELLOW
    return RED


def security_color(security: str) -> tuple:
    """Return an RGB color tuple based on security type."""
    if security == "Open":
        return RED
    if security == "WEP":
        return YELLOW
    return GREEN


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_BSSID_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def is_valid_bssid(bssid: str) -> bool:
    """Return True if *bssid* is a valid MAC address (colon-separated hex)."""
    return bool(_BSSID_RE.match(bssid))


def is_valid_channel(channel: int) -> bool:
    """Return True if *channel* is in the valid WiFi range (1-196)."""
    return 1 <= channel <= 196


# ---------------------------------------------------------------------------
# Airodump-ng CSV parsing (used by Pi version)
# ---------------------------------------------------------------------------

def map_airodump_privacy(privacy: str) -> str:
    """Map an airodump-ng Privacy field to a short security label."""
    p = privacy.upper()
    if "WPA3" in p or "SAE" in p:
        return "WPA3"
    if "WPA2" in p:
        return "WPA2"
    if "WPA" in p:
        return "WPA"
    if "WEP" in p:
        return "WEP"
    if "OPN" in p or not p:
        return "Open"
    return privacy[:5]


def parse_airodump_csv(content: str) -> tuple[list[Network], dict[str, int]]:
    """Parse airodump-ng CSV content into (networks, client_counts).

    The CSV has two sections separated by a blank line:
    1. Access points (BSSIDs)
    2. Stations (clients) with their associated BSSID
    """
    networks: list[Network] = []
    client_counts: dict[str, int] = {}

    if not content.strip():
        return networks, client_counts

    # Normalize line endings so we handle both \r\n\r\n and \n\n section separators
    # (airodump-ng on Linux typically uses \n)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    # Use re.split to handle airodump-ng versions that write 3+ blank lines between sections.
    # split("\n\n") would put station data in sections[2] when 4 newlines appear (\n\n\n\n).
    sections = re.split(r"\n{2,}", normalized)

    logger.debug("airodump CSV sections: %d", len(sections))

    # -- AP section --
    ap_lines = sections[0].strip().splitlines()
    logger.debug(
        "airodump CSV section line counts: AP=%d Station=%d",
        len(ap_lines),
        len(sections[1].strip().splitlines()) if len(sections) > 1 else 0,
    )
    if ap_lines:
        reader = csv.reader(ap_lines)
        header = None
        for row in reader:
            row = [c.strip() for c in row]
            if not row or not row[0]:
                continue
            if "BSSID" in row[0]:
                header = row
                continue
            if header is None or len(row) < 14:
                if header is not None:
                    logger.debug("Skipped AP row with %d fields (need 14): %s", len(row), row)
                continue

            bssid = row[0].lower()
            privacy = row[5]
            power = row[8]
            ssid = row[13] if len(row) > 13 else ""

            try:
                signal_dbm = int(power)
            except ValueError:
                signal_dbm = -100
            if signal_dbm == -1:
                signal_dbm = -100

            try:
                channel = int(row[3])
            except ValueError:
                channel = 0

            networks.append(Network(
                bssid=bssid,
                ssid=ssid,
                signal=signal_dbm,
                channel=channel,
                security=map_airodump_privacy(privacy),
            ))

    if networks:
        first_aps = [
            (n.bssid, n.ssid or "<hidden>") for n in networks[:3]
        ]
        logger.debug("airodump CSV first APs parsed: %s", first_aps)

    # -- Station section --
    if len(sections) > 1:
        sta_lines = sections[1].strip().splitlines()
        logger.debug("airodump CSV station section found, %d lines", len(sta_lines))
        if sta_lines:
            reader = csv.reader(sta_lines)
            header = None
            for row in reader:
                row = [c.strip() for c in row]
                if not row or not row[0]:
                    continue
                if "Station MAC" in row[0]:
                    header = row
                    continue
                if header is None or len(row) < 6:
                    if header is not None:
                        logger.debug("Skipped station row with %d fields (need 6): %s", len(row), row)
                    continue

                bssid = row[5].strip().lower()
                if not bssid or "not associated" in bssid:
                    continue
                client_counts[bssid] = client_counts.get(bssid, 0) + 1

        logger.debug("airodump CSV clients: %d BSSIDs, %d total", len(client_counts), sum(client_counts.values()))
    else:
        logger.debug("airodump CSV no station section (sections=%d)", len(sections))

    # Merge client counts into Network objects
    for net in networks:
        net.clients = client_counts.get(net.bssid, 0)

    networks.sort(key=lambda n: n.signal, reverse=True)
    return networks, client_counts
