#!/usr/bin/env python3
"""WiFi Monitor - Displays nearby WiFi networks on an Adafruit Mini PiTFT.

Uses monitor mode with channel hopping on a USB WiFi dongle to passively
detect and count active clients associated with each access point.
The built-in wlan0 interface is used for network scanning (iwlist).
"""

import atexit
import re
import subprocess
import threading
import time

import board
import digitalio
from PIL import Image, ImageDraw, ImageFont
from scapy.all import Dot11, sniff
import adafruit_rgb_display.st7789 as st7789

# -- Display constants --
DISPLAY_WIDTH = 240
DISPLAY_HEIGHT = 135
FONT_SIZE = 10

# -- Interface config --
SCAN_INTERFACE = "wlan0"       # built-in WiFi for iwlist scanning
MONITOR_INTERFACE = "wlan1"    # USB dongle for monitor mode

# -- Timing --
SCAN_INTERVAL = 15             # seconds between iwlist scans
HOP_INTERVAL = 0.25            # seconds per channel hop

# -- Channels to hop through --
CHANNELS_24GHZ = list(range(1, 12))
CHANNELS_5GHZ = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165,
]

# -- Colors --
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
YELLOW = (255, 255, 0)
RED = (255, 0, 0)
CYAN = (0, 255, 255)
GRAY = (128, 128, 128)
DIM = (40, 40, 40)
ORANGE = (255, 165, 0)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def setup_display():
    """Initialize the Adafruit Mini PiTFT 135x240 display."""
    cs_pin = digitalio.DigitalInOut(board.CE0)
    dc_pin = digitalio.DigitalInOut(board.D25)
    reset_pin = digitalio.DigitalInOut(board.D24)

    backlight = digitalio.DigitalInOut(board.D22)
    backlight.switch_to_output()
    backlight.value = True

    spi = board.SPI()
    display = st7789.ST7789(
        spi,
        cs=cs_pin,
        dc=dc_pin,
        rst=reset_pin,
        width=DISPLAY_WIDTH,
        height=DISPLAY_HEIGHT,
        y_offset=53,
        x_offset=40,
        rotation=270,
    )
    return display


def load_fonts():
    """Load display fonts, falling back to defaults if unavailable."""
    try:
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", FONT_SIZE
        )
        font_sm = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", FONT_SIZE - 2
        )
    except OSError:
        font = ImageFont.load_default()
        font_sm = font
    return font, font_sm


# ---------------------------------------------------------------------------
# Monitor mode
# ---------------------------------------------------------------------------

def enable_monitor_mode(interface=MONITOR_INTERFACE):
    """Put a WiFi interface into monitor mode using iw."""
    subprocess.run(
        ["sudo", "ip", "link", "set", interface, "down"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", interface, "up"],
        capture_output=True, check=True,
    )
    print(f"[+] {interface} is now in monitor mode")


def disable_monitor_mode(interface=MONITOR_INTERFACE):
    """Restore a WiFi interface to managed mode."""
    subprocess.run(
        ["sudo", "ip", "link", "set", interface, "down"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "iw", "dev", interface, "set", "type", "managed"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", interface, "up"],
        capture_output=True,
    )
    print(f"[+] {interface} restored to managed mode")


# ---------------------------------------------------------------------------
# Channel hopper
# ---------------------------------------------------------------------------

class ChannelHopper:
    """Cycle through WiFi channels in a background thread."""

    def __init__(self, interface, channels=None):
        self.interface = interface
        self.channels = channels or CHANNELS_24GHZ + CHANNELS_5GHZ
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._hop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _hop(self):
        while not self._stop.is_set():
            for channel in self.channels:
                if self._stop.is_set():
                    break
                try:
                    subprocess.run(
                        ["sudo", "iw", "dev", self.interface,
                         "set", "channel", str(channel)],
                        capture_output=True,
                        timeout=5,
                    )
                except subprocess.SubprocessError:
                    pass
                self._stop.wait(HOP_INTERVAL)


# ---------------------------------------------------------------------------
# Client tracker (passive sniffing)
# ---------------------------------------------------------------------------

def _is_multicast(mac):
    """Return True if a MAC address is broadcast or multicast."""
    if not mac or mac == BROADCAST_MAC:
        return True
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return True


class ClientTracker:
    """Passively sniff 802.11 frames and track unique clients per BSSID."""

    def __init__(self, interface):
        self.interface = interface
        self._clients = {}          # bssid -> set of client MACs
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def get_client_counts(self):
        """Return {bssid: client_count} snapshot."""
        with self._lock:
            return {bssid: len(macs) for bssid, macs in self._clients.items()}

    # -- internal --

    def _sniff(self):
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _process_packet(self, packet):
        if not packet.haslayer(Dot11):
            return

        dot11 = packet[Dot11]
        bssid, client = self._extract_bssid_client(dot11)

        if bssid and client and not _is_multicast(client) and client != bssid:
            with self._lock:
                self._clients.setdefault(bssid, set()).add(client)

    @staticmethod
    def _extract_bssid_client(dot11):
        """Determine the BSSID and client MAC from a Dot11 frame.

        Returns (bssid, client) or (None, None) if not applicable.
        """
        addr1 = dot11.addr1   # receiver
        addr2 = dot11.addr2   # transmitter
        addr3 = dot11.addr3

        frame_type = dot11.type
        subtype = dot11.subtype

        # Data frames (type 2) -- use To-DS / From-DS bits
        if frame_type == 2:
            ds = dot11.FCfield & 0x3
            if ds == 0x1:       # To DS: client -> AP
                return addr1, addr2
            if ds == 0x2:       # From DS: AP -> client
                return addr2, addr1
            return None, None

        # Management frames (type 0)
        if frame_type == 0:
            # Association / reassociation requests (subtypes 0, 2)
            if subtype in (0, 2):
                return (addr3 or addr1), addr2
            # Probe responses (subtype 5) -- AP answering a client
            if subtype == 5:
                return addr2, addr1

        return None, None


# ---------------------------------------------------------------------------
# WiFi scanning (iwlist on managed interface)
# ---------------------------------------------------------------------------

def scan_wifi(interface=SCAN_INTERFACE):
    """Scan for nearby WiFi networks using iwlist on the managed interface."""
    try:
        result = subprocess.run(
            ["sudo", "iwlist", interface, "scan"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return parse_iwlist(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Scan error: {e}")
        return []


def parse_iwlist(output):
    """Parse iwlist scan output into a list of network dicts."""
    networks = []
    current = None

    for line in output.split("\n"):
        line = line.strip()

        if "Cell " in line and "Address:" in line:
            if current:
                networks.append(current)
            current = {
                "bssid": line.split("Address:")[1].strip(),
                "ssid": "",
                "signal": -100,
                "channel": 0,
                "security": "Open",
            }

        if current is None:
            continue

        if "ESSID:" in line:
            match = re.search(r'ESSID:"(.*)"', line)
            if match:
                current["ssid"] = match.group(1)

        elif "Signal level=" in line:
            match = re.search(r"Signal level=(-?\d+)", line)
            if match:
                current["signal"] = int(match.group(1))

        elif "Channel:" in line:
            match = re.search(r"Channel:(\d+)", line)
            if match:
                current["channel"] = int(match.group(1))

        elif "Encryption key:on" in line:
            if current["security"] == "Open":
                current["security"] = "WEP"

        elif "IE: IEEE 802.11i/WPA2" in line:
            current["security"] = "WPA2"

        elif "IE: WPA Version" in line:
            if current["security"] not in ("WPA2", "WPA3"):
                current["security"] = "WPA"

        elif "SAE" in line or "WPA3" in line:
            current["security"] = "WPA3"

    if current:
        networks.append(current)

    networks.sort(key=lambda n: n["signal"], reverse=True)
    return networks


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def signal_to_bars(signal_dbm):
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


def signal_color(signal_dbm):
    """Return a color based on signal strength."""
    if signal_dbm >= -50:
        return GREEN
    if signal_dbm >= -65:
        return YELLOW
    return RED


def security_color(security):
    """Return a color based on security type."""
    if security == "Open":
        return RED
    if security == "WEP":
        return YELLOW
    return GREEN


def render(display, networks, client_counts, font, font_sm):
    """Render the network list with client counts to the display."""
    image = Image.new("RGB", (DISPLAY_WIDTH, DISPLAY_HEIGHT), BLACK)
    draw = ImageDraw.Draw(image)

    # Header
    total_clients = sum(client_counts.values())
    draw.text((2, 2), "WiFi Monitor", font=font, fill=CYAN)
    header_r = f"{len(networks)}net {total_clients}cli"
    draw.text((DISPLAY_WIDTH - 80, 2), header_r, font=font_sm, fill=GRAY)
    draw.line([(0, 14), (DISPLAY_WIDTH, 14)], fill=GRAY, width=1)

    # Column headers
    y = 16
    draw.text((2, y), "SSID", font=font_sm, fill=GRAY)
    draw.text((95, y), "dBm", font=font_sm, fill=GRAY)
    draw.text((130, y), "Sig", font=font_sm, fill=GRAY)
    draw.text((165, y), "Sec", font=font_sm, fill=GRAY)
    draw.text((210, y), "Cli", font=font_sm, fill=GRAY)
    y += 11

    # Network rows
    row_height = 11
    max_rows = (DISPLAY_HEIGHT - y) // row_height

    for network in networks[:max_rows]:
        ssid = network["ssid"] or "<hidden>"
        if len(ssid) > 12:
            ssid = ssid[:11] + "\u2026"

        draw.text((2, y), ssid, font=font_sm, fill=WHITE)

        # Signal dBm
        sig = network["signal"]
        draw.text((95, y), str(sig), font=font_sm, fill=signal_color(sig))

        # Signal bars
        bars = signal_to_bars(sig)
        bar_x = 132
        for i in range(4):
            color = signal_color(sig) if i < bars else DIM
            bar_h = 3 + i * 2
            draw.rectangle(
                [bar_x + i * 5, y + (10 - bar_h), bar_x + i * 5 + 3, y + 10],
                fill=color,
            )

        # Security
        sec = network["security"]
        draw.text((165, y), sec, font=font_sm, fill=security_color(sec))

        # Client count
        bssid = network["bssid"].lower()
        count = client_counts.get(bssid, 0)
        count_color = ORANGE if count > 0 else DIM
        draw.text((215, y), str(count), font=font_sm, fill=count_color)

        y += row_height

    display.image(image)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Main loop: monitor mode + channel hop + scan + display."""
    display = setup_display()
    font, font_sm = load_fonts()

    # Startup splash
    image = Image.new("RGB", (DISPLAY_WIDTH, DISPLAY_HEIGHT), BLACK)
    draw = ImageDraw.Draw(image)
    draw.text((30, 50), "Starting monitor...", font=font, fill=CYAN)
    draw.text((30, 65), "Enabling mon mode", font=font_sm, fill=GRAY)
    display.image(image)

    # Enable monitor mode on USB dongle
    enable_monitor_mode(MONITOR_INTERFACE)
    atexit.register(disable_monitor_mode, MONITOR_INTERFACE)

    # Start channel hopper
    hopper = ChannelHopper(MONITOR_INTERFACE)
    hopper.start()
    atexit.register(hopper.stop)

    # Start passive client tracker
    tracker = ClientTracker(MONITOR_INTERFACE)
    tracker.start()
    atexit.register(tracker.stop)

    print("[+] Monitor mode active — scanning networks")

    while True:
        networks = scan_wifi()
        client_counts = tracker.get_client_counts()
        render(display, networks, client_counts, font, font_sm)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
