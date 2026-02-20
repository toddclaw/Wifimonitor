# Wifimonitor

A Python WiFi monitoring tool that scans and displays nearby WiFi networks in a real-time terminal dashboard.

Currently runs on **Linux laptops** using `nmcli` (NetworkManager). Raspberry Pi support with monitor mode is planned for a future phase.

## Features

- **Real-time scanning** -- Continuously scans for nearby WiFi networks and refreshes the display.
- **Signal strength** -- Shows signal in dBm with color-coded bar indicators (green/yellow/red).
- **Security detection** -- Identifies Open, WEP, WPA, WPA2, and WPA3 networks.
- **Hidden networks** -- Detects and displays hidden SSIDs.
- **Credentials file** -- Load SSID/passphrase pairs from a CSV file to identify known networks and optionally auto-connect.
- **DNS query capture** -- Live capture and display of DNS queries in a ranked "top" style table (requires root / tcpdump).
- **Rich TUI** -- Clean terminal interface using the [Rich](https://github.com/Textualize/rich) library.

## Requirements

- Python 3.9+
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

# Capture and display DNS queries (requires sudo)
sudo python wifi_monitor_nitro5.py --dns

# Combine all features
sudo python wifi_monitor_nitro5.py --dns -c credentials.csv --connect

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

## DNS Query Capture

The `--dns` flag enables real-time DNS query capture using `tcpdump`. A second table appears below the network list, ranking queried domain names by frequency in a "top" style display.

```bash
# Start with DNS capture (requires root for tcpdump)
sudo python wifi_monitor_nitro5.py --dns

# DNS capture with credentials and auto-connect
sudo python wifi_monitor_nitro5.py --dns -c credentials.csv --connect
```

- Requires root privileges (tcpdump needs raw socket access).
- Uses a background thread to read tcpdump output without blocking the scan loop.
- Domain names are extracted from DNS query packets (A, AAAA, PTR, MX, CNAME, TXT, SRV, HTTPS, etc.).
- The top 15 most-queried domains are displayed, updated every scan cycle.
- If tcpdump is not installed or cannot start, the feature is silently disabled and the normal network table is shown.

## Monitor Mode (Client Count per BSSID)

The `--monitor` flag enables client counting per access point using airodump-ng in monitor mode. A **Cli** column appears in the network table showing the number of associated clients for each BSSID.

```bash
# Monitor mode with default interface (wlan0)
sudo python wifi_monitor_nitro5.py --monitor

# Monitor mode on a specific interface (e.g. USB WiFi dongle)
sudo python wifi_monitor_nitro5.py --monitor -i wlan1
```

- Requires root privileges and a WiFi interface that supports monitor mode.
- Uses airodump-ng and `iw` to put the interface in monitor mode, capture 802.11 frames, and parse client associations from the CSV output.
- No passphrase is required; client counts are derived from passive monitoring of management frames.
- If monitor mode cannot be enabled (missing tools, unsupported hardware, or permission denied), the tool falls back to nmcli scanning with client counts shown as 0.
- When using `--monitor` with `--connect`, nmcli will use a different interface for connecting (the monitor interface cannot connect while in monitor mode).
- The first scan may take up to 10 seconds; airodump-ng writes CSV every 5 seconds.
- airodump-ng stderr is always captured to `/tmp/wifi_monitor_nitro5_airodump.log` for troubleshooting. Use `--debug` for additional verbose logging.

**Hardware note:** Many laptop WiFi chips (including some Intel adapters) do **not** support monitor mode or do so poorly. For reliable client counting, use a USB WiFi adapter that supports monitor mode (e.g. Atheros AR9271, Ralink RT3070).

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
| Cli      | Number of clients connected (when using `--monitor`)      |
| Security | WPA3, WPA2, WPA, WEP, or Open                            |

## Project Structure

```
Wifimonitor/
├── wifi_monitor_nitro5.py     # Laptop entry point (Rich TUI, nmcli)
├── wifi_common.py             # Shared: Network dataclass, signal/color helpers,
│                              #         airodump-ng CSV parser (Pi, future)
├── pyproject.toml             # Tool config (ruff, mypy)
├── requirements-laptop.txt    # Laptop dependencies (rich>=13.0,<15)
├── requirements-dev.txt       # Dev/CI tooling (pytest, ruff, mypy, pip-audit)
├── requirements.txt           # Pi dependencies (future)
├── .github/workflows/ci.yml   # CI pipeline (test, lint, security)
├── tests/
│   ├── test_wifi_monitor_nitro5.py   # 153 tests — parsing, rendering, scanning, credentials, DNS, injection
│   └── test_wifi_common.py           #  69 tests — helpers, airodump CSV, validation, colors, protocol
├── CLAUDE.md                  # Agent guide and coding standards
└── .claude/agents/            # Claude agent definitions
    ├── architect-agent.md     # Architecture research and design
    ├── tdd-agent.md           # TDD / Software Craftsmanship
    ├── devsecops-agent.md     # Security review, dependency audit
    ├── red-team-agent.md      # Adversarial review
    ├── scrum-master-agent.md  # Backlog grooming, prioritization, retros
    └── manager-agent.md       # Orchestrator (coordinates all agents)
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=term-missing
```

222 tests cover parsing, signal helpers, security mapping, Rich table rendering, subprocess error handling, credentials file loading, network connection, DNS query capture, input validation, CommandRunner injection, and edge cases.

## Security Hardening

The codebase has been reviewed by DevSecOps and Red Team agents:

- **No shell injection** -- All subprocess calls use list arguments, never `shell=True`.
- **Markup escaping** -- SSIDs, BSSIDs, and DNS domain names are escaped via `rich.markup.escape()` before display to prevent Rich markup injection from attacker-controlled strings.
- **Minimal subprocess environment** -- Child processes receive only `PATH`, `LC_ALL`, and `HOME`.
- **Graceful error handling** -- Subprocess timeouts and failures return empty results instead of crashing.
- **Input clamping** -- Signal percentage values are clamped to 0-100 before conversion.
- **Credentials safety** -- Credentials file permissions are checked; warns if world-readable. Passphrases are never displayed in the TUI.
- **Input validation** -- BSSID format (MAC regex) and channel range (1-196) validated via `is_valid_bssid()` and `is_valid_channel()`.
- **CI/CD pipeline** -- GitHub Actions workflow runs pytest (3.9 + 3.12 matrix), ruff, mypy, and pip-audit on every push and PR.

## Troubleshooting (Monitor Mode)

If monitor mode shows "client counts enabled" but no networks or client counts appear:

1. **Check the log file** — Inspect `/tmp/wifi_monitor_nitro5_airodump.log` for airodump-ng errors. If airodump exits immediately, the log will show the exit code and command used.
2. **Check monitor mode setup** — Inspect `/tmp/wifi_monitor_nitro5_monitor.log` for failures during `ip`/`iw` commands (e.g. "device does not support monitor mode").
3. **Verify interface type** — Run `iw dev <interface> info` and ensure `type monitor` is shown. Some drivers report success for `iw ... set type monitor` but do not actually support packet capture.
4. **Ensure aircrack-ng is installed** — `sudo apt install aircrack-ng` (or equivalent). airodump-ng must be on your PATH.
5. **Try a USB WiFi adapter** — Built-in laptop WiFi often lacks monitor mode support. USB adapters with Atheros AR9271 or Ralink RT3070 chips are known to work.

## Future Plans

### Refactoring

- **Package layout** (3 pts) -- Migrate to `src/wifimonitor/` package structure with `pyproject.toml`, `__version__`, and console entry point. Unifies the dual requirements files into a single dependency spec.
- **Test coverage for wifi_monitor_nitro5.py** (3 pts) -- Raise coverage from 79% to 90%+. Major gap is `main()` (~70 lines untested). Requires extracting the TUI loop body into a testable function, adding seams for `Console`/`Live`, and covering `DnsTracker._reader_loop` threading edge cases and `load_credentials` error paths.
- **Scanner and Renderer protocols** (3 pts) -- Define `ScannerProtocol` and `RendererProtocol` abstractions. Split `wifi_monitor_nitro5.py` into `NmcliScanner`, `RichRenderer`, and a thin `MonitorApp` coordinator (Single Responsibility).
- **UX agent** (3 pts) -- Create a UX agent that evaluates and suggests improvements for both the CLI/TUI (Rich tables, layout, color, information density) and future GUI surfaces. Integrate into the manager pipeline alongside the existing review agents.

### Features

- **Raspberry Pi support** (8 pts) -- Monitor mode scanning via airodump-ng with PiTFT display output. The CSV parser (`parse_airodump_csv`) and shared data structures are already implemented.
- **Deauth attack detection** (8 pts) -- Detect deauthentication/disassociation frames targeting your own network and alert in the TUI. Requires monitor mode capture and 802.11 management frame parsing.
- **Rogue AP detection** (5 pts) -- Identify rogue access points impersonating known SSIDs with mismatched BSSIDs or unexpected channels. Works with existing nmcli scan data; needs a known-good baseline file.
- **Unusual client behavior monitoring** (13 pts) -- Monitor for anomalous client activity on networks you own (e.g. rapid association/disassociation, probe floods). Requires monitor mode and rate-based anomaly heuristics.

## Hardware (Pi Phase)

- Raspberry Pi (any model with USB support)
- USB WiFi dongle for monitor mode
- Adafruit Mini PiTFT 135x240 color display
