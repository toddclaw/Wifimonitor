#!/usr/bin/env python3
"""WiFi Monitor — Raspberry Pi version with Adafruit Mini PiTFT.

Uses airodump-ng in monitor mode on a USB WiFi dongle to discover networks,
track signal strength, security type, and count associated clients.
Results are rendered on the 135x240 PiTFT display.
"""

import atexit
import glob
import os
import signal
import subprocess
import time

import board
import digitalio
from PIL import Image, ImageDraw, ImageFont
import adafruit_rgb_display.st7789 as st7789

from wifi_common import (
    BLACK, WHITE, CYAN, GRAY, DIM, ORANGE,
    signal_to_bars, signal_color, security_color,
    parse_airodump_csv,
)

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
# Airodump-ng process management
# ---------------------------------------------------------------------------

class AirodumpNG:
    """Manage an airodump-ng process and read its CSV output.

    airodump-ng handles channel hopping, network discovery, and client
    association tracking.  CSV parsing is delegated to wifi_common.
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
                "--band", "abg",
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
        """Read the latest CSV and return (networks, client_counts)."""
        csv_path = self._latest_csv()
        if not csv_path:
            return [], {}

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return [], {}

        return parse_airodump_csv(content)

    def _latest_csv(self):
        files = sorted(glob.glob(f"{self.prefix}-*.csv"))
        return files[-1] if files else None

    def _cleanup_old_files(self):
        for f in glob.glob(f"{self.prefix}-*"):
            try:
                os.remove(f)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# PiTFT rendering
# ---------------------------------------------------------------------------

def render(display, networks, client_counts, font, font_sm):
    """Render the network list with client counts to the PiTFT display."""
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

    for net in networks[:max_rows]:
        ssid = net.ssid or "<hidden>"
        if len(ssid) > 12:
            ssid = ssid[:11] + "\u2026"

        draw.text((2, y), ssid, font=font_sm, fill=WHITE)

        sig = net.signal
        draw.text((95, y), str(sig), font=font_sm, fill=signal_color(sig))

        bars = signal_to_bars(sig)
        bar_x = 132
        for i in range(4):
            color = signal_color(sig) if i < bars else DIM
            bar_h = 3 + i * 2
            draw.rectangle(
                [bar_x + i * 5, y + (10 - bar_h), bar_x + i * 5 + 3, y + 10],
                fill=color,
            )

        draw.text((165, y), net.security, font=font_sm, fill=security_color(net.security))

        count = net.clients
        count_color = ORANGE if count > 0 else DIM
        draw.text((215, y), str(count), font=font_sm, fill=count_color)

        y += row_height

    display.image(image)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Main loop: airodump-ng + PiTFT display."""
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

    # Start airodump-ng
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
