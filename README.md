# Wifimonitor

A Python WiFi monitoring tool that scans and displays nearby WiFi networks in a real-time terminal dashboard.

Currently runs on **Linux laptops** using `nmcli` (NetworkManager). Raspberry Pi support with monitor mode is planned for a future phase.

## Features

- **Real-time scanning** -- Continuously scans for nearby WiFi networks and refreshes the display.
- **Signal strength** -- Shows signal in dBm with color-coded bar indicators (green/yellow/red).
- **Security detection** -- Identifies Open, WEP, WPA, WPA2, and WPA3 networks.
- **Hidden networks** -- Detects and displays hidden SSIDs.
- **Credentials file** -- Load SSID/passphrase pairs from a CSV file to identify known networks and optionally auto-connect.
- **Rich TUI** -- Clean terminal interface using the [Rich](https://github.com/Textualize/rich) library.

## Requirements

- Python 3.11+
- Linux with NetworkManager (`nmcli`)
- No root required for cached scan results; `sudo` enables fresh rescans

## Quick Start

```bash
# Install dependencies
pip install -r requirements-laptop.txt

# Run with default interface
python wifi_monitor_nitro5.py

# Specify a wireless interface
python wifi_monitor_nitro5.py -i wlan1

# Load a credentials file (shows Key column for known networks)
python wifi_monitor_nitro5.py -c credentials.csv

# Auto-connect to the strongest known network
python wifi_monitor_nitro5.py -c credentials.csv --connect

# Run with sudo to force fresh rescans
sudo python wifi_monitor_nitro5.py
```

Press `Ctrl+C` to exit cleanly.

## Credentials File

The `-c` / `--credentials` option loads a CSV file containing SSID and passphrase pairs. When loaded, a **Key** column appears in the display marking networks with known passphrases. Combined with `--connect`, the monitor will automatically join the strongest matching network on the first scan.

**File format** -- one `ssid,passphrase` per line:

```csv
# Lines starting with # are comments
HomeNetwork,mysecretpassword
Coffee Shop,cafe2024
"Network, With Commas","pass,word"
OpenCafe,
```

- Fields may be quoted to include commas (standard CSV quoting).
- Empty passphrase (e.g. `OpenCafe,`) connects to open networks.
- Blank lines and comment lines are ignored.

**Security note:** The credentials file contains plaintext passphrases. Restrict its permissions:

```bash
chmod 600 credentials.csv
```

The tool will warn to stderr if the file is world-readable.

## Display Columns

| Column   | Description                                               |
|----------|-----------------------------------------------------------|
| #        | Row number                                                |
| SSID     | Network name (or `<hidden>` for hidden networks)          |
| Key      | `*` if credentials are known (only shown with `-c` flag)  |
| BSSID    | Access point MAC address                                  |
| Ch       | WiFi channel (2.4 GHz and 5 GHz)                         |
| dBm      | Signal strength in dBm (-50 excellent, -100 none)         |
| Sig      | Visual signal bars (0-4)                                  |
| Security | WPA3, WPA2, WPA, WEP, or Open                            |

## Project Structure

```
Wifimonitor/
├── wifi_monitor_nitro5.py     # Laptop entry point (Rich TUI, nmcli)
├── wifi_common.py             # Shared: Network dataclass, signal/color helpers,
│                              #         airodump-ng CSV parser (Pi, future)
├── requirements-laptop.txt    # Laptop dependencies (rich>=13.0,<15)
├── requirements.txt           # Pi dependencies (future)
├── tests/
│   ├── test_wifi_monitor_nitro5.py   # 107 tests — parsing, rendering, scanning, credentials
│   └── test_wifi_common.py           #  34 tests — helpers, airodump CSV parsing
├── CLAUDE.md                  # Agent guide and coding standards
└── .claude/agents/            # Claude agent definitions
    ├── tdd-agent.md           # TDD / Software Craftsmanship
    ├── devsecops-agent.md     # Security review, dependency audit
    ├── red-team-agent.md      # Adversarial review
    └── manager-agent.md       # Orchestrator (coordinates all agents)
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=term-missing
```

140 tests cover parsing, signal helpers, security mapping, Rich table rendering, subprocess error handling, credentials file loading, network connection, and input edge cases.

## Security Hardening

The codebase has been reviewed by DevSecOps and Red Team agents:

- **No shell injection** -- All subprocess calls use list arguments, never `shell=True`.
- **Markup escaping** -- SSIDs and BSSIDs are escaped via `rich.markup.escape()` before display to prevent Rich markup injection from attacker-controlled network names.
- **Minimal subprocess environment** -- Child processes receive only `PATH`, `LC_ALL`, and `HOME`.
- **Graceful error handling** -- Subprocess timeouts and failures return empty results instead of crashing.
- **Input clamping** -- Signal percentage values are clamped to 0-100 before conversion.
- **Credentials safety** -- Credentials file permissions are checked; warns if world-readable. Passphrases are never displayed in the TUI.

## Future Plans

- **Raspberry Pi support** -- Monitor mode scanning via airodump-ng with PiTFT display output. The CSV parser (`parse_airodump_csv`) and shared data structures are already implemented.
- **Package layout** -- Migrate to `src/wifimonitor/` package structure with `pyproject.toml`.
- **Scanner protocol** -- Abstract `ScannerProtocol` interface for pluggable scan backends.

## Hardware (Pi Phase)

- Raspberry Pi (any model with USB support)
- USB WiFi dongle for monitor mode
- Adafruit Mini PiTFT 135x240 color display
