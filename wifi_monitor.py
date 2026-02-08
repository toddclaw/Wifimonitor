#!/usr/bin/env python3
"""WiFi Monitor - Displays nearby WiFi networks on an Adafruit Mini PiTFT.

Uses airodump-ng in monitor mode on a USB WiFi dongle to discover networks,
track signal strength, security type, and count associated clients.
"""

import atexit
import csv
import glob
import os
import signal
import subprocess
import time

import board
import digitalio
from PIL import Image, ImageDraw, ImageFont
import adafruit_rgb_display.st7789 as st7789

# -- Display constants --
DISPLAY_WIDTH = 240
DISPLAY_HEIGHT = 135
FONT_SIZE = 10

# -- Interface config --
MONITOR_INTERFACE = "wlan1"    # USB dongle for monitor mode

# -- Timing --
DISPLAY_INTERVAL = 5           # seconds between display refreshes
AIRODUMP_WRITE_INTERVAL = 5   # how often airodump-ng flushes its CSV

# -- Airodump output --
AIRODUMP_PREFIX = "/tmp/wifi_monitor"

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
# Airodump-ng process and CSV parsing
# ---------------------------------------------------------------------------

class AirodumpNG:
    """Manage an airodump-ng process and parse its CSV output.

    airodump-ng handles channel hopping, network discovery, and client
    association tracking — replacing our manual ChannelHopper, ClientTracker,
    and iwlist scanning.
    """

    def __init__(self, interface, prefix=AIRODUMP_PREFIX):
        self.interface = interface
        self.prefix = prefix
        self._proc = None

    def start(self):
        """Start airodump-ng writing CSV output."""
        self._cleanup_old_files()
        self._proc = subprocess.Popen(
            [
                "sudo", "airodump-ng",
                self.interface,
                "--band", "abg",                     # 2.4GHz + 5GHz
                "--write", self.prefix,
                "--output-format", "csv",
                "--write-interval", str(AIRODUMP_WRITE_INTERVAL),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[+] airodump-ng started (PID {self._proc.pid})")

    def stop(self):
        """Stop the airodump-ng process."""
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            print("[+] airodump-ng stopped")
        self._cleanup_old_files()

    def parse(self):
        """Parse the latest airodump-ng CSV and return (networks, client_counts).

        networks: list of dicts with bssid, ssid, signal, channel, security
        client_counts: dict of {bssid: number_of_clients}
        """
        csv_path = self._latest_csv()
        if not csv_path:
            return [], {}

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return [], {}

        return self._parse_csv(content)

    # -- internal --

    def _latest_csv(self):
        """Find the most recent airodump-ng CSV file."""
        files = sorted(glob.glob(f"{self.prefix}-*.csv"))
        return files[-1] if files else None

    def _cleanup_old_files(self):
        """Remove leftover airodump-ng output files."""
        for f in glob.glob(f"{self.prefix}-*"):
            try:
                os.remove(f)
            except OSError:
                pass

    @staticmethod
    def _parse_csv(content):
        """Parse airodump-ng CSV content.

        The CSV has two sections separated by a blank line:
        1. Access points (BSSIDs)
        2. Stations (clients) with their associated BSSID
        """
        networks = []
        client_counts = {}

        # Split into AP section and station section
        sections = content.split("\r\n\r\n")
        if not sections:
            return networks, client_counts

        # -- Parse AP section --
        ap_lines = sections[0].strip().splitlines()
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
                    continue

                bssid = row[0].strip().lower()
                channel_str = row[3].strip()
                privacy = row[5].strip()
                power = row[8].strip()
                ssid = row[13].strip() if len(row) > 13 else ""

                try:
                    signal_dbm = int(power)
                except ValueError:
                    signal_dbm = -100
                # airodump reports -1 when power is unknown
                if signal_dbm == -1:
                    signal_dbm = -100

                try:
                    channel = int(channel_str)
                except ValueError:
                    channel = 0

                security = _map_privacy(privacy)

                networks.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "signal": signal_dbm,
                    "channel": channel,
                    "security": security,
                })

        # -- Parse station (client) section --
        if len(sections) > 1:
            sta_lines = sections[1].strip().splitlines()
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
                        continue

                    bssid = row[5].strip().lower()
                    # "(not associated)" stations don't count
                    if not bssid or "not associated" in bssid:
                        continue

                    client_counts[bssid] = client_counts.get(bssid, 0) + 1

        networks.sort(key=lambda n: n["signal"], reverse=True)
        return networks, client_counts


def _map_privacy(privacy):
    """Map airodump-ng Privacy field to a short security label."""
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
    """Main loop: airodump-ng + display."""
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

    # Start airodump-ng (handles channel hopping + scanning + client tracking)
    airodump = AirodumpNG(MONITOR_INTERFACE)
    airodump.start()
    atexit.register(airodump.stop)

    print("[+] Monitor mode active — airodump-ng scanning")

    while True:
        networks, client_counts = airodump.parse()
        render(display, networks, client_counts, font, font_sm)
        time.sleep(DISPLAY_INTERVAL)


if __name__ == "__main__":
    main()
