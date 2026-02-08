#!/usr/bin/env python3
"""WiFi Monitor - Displays nearby WiFi networks on an Adafruit Mini PiTFT."""

import re
import subprocess
import time

import board
import digitalio
from PIL import Image, ImageDraw, ImageFont
import adafruit_rgb_display.st7789 as st7789

# Display dimensions (landscape orientation)
DISPLAY_WIDTH = 240
DISPLAY_HEIGHT = 135

FONT_SIZE = 10
SCAN_INTERVAL = 15  # seconds between scans

# Colors
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
YELLOW = (255, 255, 0)
RED = (255, 0, 0)
CYAN = (0, 255, 255)
GRAY = (128, 128, 128)
DIM = (40, 40, 40)


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


def scan_wifi(interface="wlan1"):
    """Scan for nearby WiFi networks using iwlist.

    Uses wlan1 by default (USB dongle). The built-in wlan0 can also be used.
    """
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


def render(display, networks, font, font_sm):
    """Render the network list to the display."""
    image = Image.new("RGB", (DISPLAY_WIDTH, DISPLAY_HEIGHT), BLACK)
    draw = ImageDraw.Draw(image)

    # Header
    draw.text((2, 2), "WiFi Monitor", font=font, fill=CYAN)
    count_text = f"{len(networks)} found"
    draw.text((DISPLAY_WIDTH - 62, 2), count_text, font=font_sm, fill=GRAY)
    draw.line([(0, 14), (DISPLAY_WIDTH, 14)], fill=GRAY, width=1)

    # Column headers
    y = 16
    draw.text((2, y), "SSID", font=font_sm, fill=GRAY)
    draw.text((130, y), "dBm", font=font_sm, fill=GRAY)
    draw.text((168, y), "Sig", font=font_sm, fill=GRAY)
    draw.text((200, y), "Sec", font=font_sm, fill=GRAY)
    y += 11

    # Network rows
    row_height = 11
    max_rows = (DISPLAY_HEIGHT - y) // row_height

    for network in networks[:max_rows]:
        ssid = network["ssid"] or "<hidden>"
        if len(ssid) > 16:
            ssid = ssid[:15] + "\u2026"

        draw.text((2, y), ssid, font=font_sm, fill=WHITE)

        sig = network["signal"]
        draw.text((130, y), str(sig), font=font_sm, fill=signal_color(sig))

        # Signal strength bars
        bars = signal_to_bars(sig)
        bar_x = 170
        for i in range(4):
            color = signal_color(sig) if i < bars else DIM
            bar_h = 3 + i * 2
            draw.rectangle(
                [bar_x + i * 5, y + (10 - bar_h), bar_x + i * 5 + 3, y + 10],
                fill=color,
            )

        sec = network["security"]
        draw.text((200, y), sec, font=font_sm, fill=security_color(sec))

        y += row_height

    display.image(image)


def main():
    """Main loop: scan and display WiFi networks."""
    display = setup_display()
    font, font_sm = load_fonts()

    # Startup splash
    image = Image.new("RGB", (DISPLAY_WIDTH, DISPLAY_HEIGHT), BLACK)
    draw = ImageDraw.Draw(image)
    draw.text((50, 55), "Scanning WiFi...", font=font, fill=CYAN)
    display.image(image)

    while True:
        networks = scan_wifi()
        render(display, networks, font, font_sm)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
