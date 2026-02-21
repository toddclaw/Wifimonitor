# Wifimonitor

A Python WiFi monitoring tool that scans and displays nearby WiFi networks in a real-time terminal dashboard.

Currently runs on **Linux laptops** using `nmcli` (NetworkManager). Raspberry Pi support with monitor mode is planned for a future phase.

## Features

- **Real-time scanning** -- Continuously scans for nearby WiFi networks and refreshes the display.
- **Connected network indicator** -- The network you are currently connected to is highlighted bold with a `●` marker in the **Con** column, always visible.
- **Signal strength** -- Shows signal in dBm with color-coded bar indicators (green/yellow/red).
- **Security detection** -- Identifies Open, WEP, WPA, WPA2, and WPA3 networks.
- **Hidden networks** -- Detects and displays hidden SSIDs.
- **ARP client detection** -- Count active devices on your connected network via ARP scanning (`--arp`). Works on all WiFi adapters including Intel built-in. Requires root.
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

# Count clients on connected network via ARP (works on Intel WiFi)
sudo python wifi_monitor_nitro5.py --arp

# ARP client counts + DNS capture
sudo python wifi_monitor_nitro5.py --arp --dns

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

## ARP Client Detection

The `--arp` flag counts active devices on the network you are currently connected to using ARP scanning. Unlike `--monitor`, this works on **any WiFi adapter including Intel built-in WiFi**.

```bash
# ARP client detection (requires root for raw ARP)
sudo python wifi_monitor_nitro5.py --arp

# With a specific interface
sudo python wifi_monitor_nitro5.py --arp -i wlan0
```

- Uses `arp-scan --localnet` when available; falls back to `nmap -sn` automatically.
- The client count appears in the **Cli** column of the connected network's row.
- Only counts clients on **your connected subnet** — cannot see clients on other networks.
- Returns 0 gracefully if neither tool is installed or if not currently connected.
- Install arp-scan: `sudo apt install arp-scan`

**Intel WiFi note:** The `--monitor` flag (airodump-ng) requires an Atheros/Realtek USB adapter because Intel laptop WiFi drivers do not deliver 802.11 management frames to virtual monitor interfaces — this is a documented driver limitation. Use `--arp` for client detection on Intel hardware.

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
- **Hybrid scan (virtual monitor):** When using a virtual monitor interface (mon0), the original interface (e.g. wlp4s0) stays in managed mode. In that case, the monitor uses nmcli for the full BSSID list and overlays client counts from airodump. This avoids the limited AP visibility that monitor mode often has on laptop WiFi.
- If monitor mode cannot be enabled (missing tools, unsupported hardware, or permission denied), the tool falls back to nmcli scanning with client counts shown as 0.
- When using `--monitor` with `--connect`, nmcli will use a different interface for connecting (the monitor interface cannot connect while in monitor mode).
- The first scan may take up to 10 seconds; airodump-ng writes CSV every 5 seconds.
- airodump-ng stderr is always captured to `/tmp/wifi_monitor_nitro5_airodump.log` (includes a header with the command). Use `--debug` to write Python debug output to `/tmp/wifi_monitor_nitro5_debug.log` (settings, features, monitor setup, per-scan parse details).

**Hardware note:** Many laptop WiFi chips (including some Intel adapters) do **not** support monitor mode or do so poorly. For reliable client counting, use a USB WiFi adapter that supports monitor mode (e.g. Atheros AR9271, Ralink RT3070).

## Display Columns

| Column   | Description                                               |
|----------|-----------------------------------------------------------|
| #        | Row number                                                |
| SSID     | Network name (or `<hidden>` for hidden networks)          |
| Con      | `●` if this is the currently connected network            |
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
│   ├── test_wifi_monitor_nitro5.py   # 274 tests — parsing, rendering, scanning, credentials, DNS, ARP, monitor helpers, main()
│   └── test_wifi_common.py           #  71 tests — helpers, airodump CSV, validation, colors, protocol
├── CLAUDE.md                  # Agent guide and coding standards
├── WORK_IN_PROGRESS.md        # Feature blueprints and running commentary
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

345 tests cover parsing, signal helpers, security mapping, Rich table rendering, subprocess error handling, credentials file loading, network connection, DNS query capture, ARP client detection, connected network indicator, monitor mode helpers, main() integration, input validation, CommandRunner injection, and edge cases.

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

1. **Run with `--debug`** — Use `sudo python wifi_monitor_nitro5.py --monitor -i wlp4s0 --debug` to enable verbose logging. Python debug output is written to `/tmp/wifi_monitor_nitro5_debug.log` (settings, feature flags, monitor setup, per-scan parse results).
2. **Check the airodump log** — Inspect `/tmp/wifi_monitor_nitro5_airodump.log` for airodump-ng stderr. The file is pre-populated with a header and the command used. If airodump exits immediately, the log will show the exit code.
3. **Check monitor mode setup** — Inspect `/tmp/wifi_monitor_nitro5_monitor.log` for failures during `ip`/`iw` commands (e.g. "device does not support monitor mode").
4. **Interface stays managed** — If the log shows "Interface X is not type monitor", NetworkManager may be reclaiming the interface or the driver may not actually support monitor mode. Options:
   - **Permanent unmanage:** Add `unmanaged-devices=interface-name:IFACE` to `/etc/NetworkManager/conf.d/monitor.conf` (create the file if needed), then reboot.
   - **Driver limitation:** Intel laptop WiFi often reports success but does not support monitor mode. Try a USB adapter (Atheros AR9271, Ralink RT3070).
5. **rfkill soft-block** — If WiFi is soft-blocked (`rfkill list` shows "Soft blocked: yes"), run `rfkill unblock wifi` before starting. The monitor attempts this automatically but it may fail without root.
6. **Verify interface type** — Run `iw dev <interface> info` and ensure `type monitor` is shown. Some drivers report success for `iw ... set type monitor` but do not actually support packet capture.
7. **Ensure aircrack-ng is installed** — `sudo apt install aircrack-ng` (or equivalent). airodump-ng must be on your PATH.
8. **Try a USB WiFi adapter** — Built-in laptop WiFi often lacks monitor mode support. USB adapters with Atheros AR9271 or Ralink RT3070 chips are known to work.

## Future Plans

### Refactoring

- **Package layout** (3 pts) -- Migrate to `src/wifimonitor/` package structure with `pyproject.toml`, `__version__`, and console entry point. Unifies the dual requirements files into a single dependency spec.
- ~~**Test coverage for wifi_monitor_nitro5.py** (3 pts)~~ -- **Complete.** Coverage raised to 98% (345 tests).
- **Scanner and Renderer protocols** (3 pts) -- Define `ScannerProtocol` and `RendererProtocol` abstractions. Split `wifi_monitor_nitro5.py` into `NmcliScanner`, `RichRenderer`, and a thin `MonitorApp` coordinator (Single Responsibility).
- **UX agent** (3 pts) -- Create a UX agent that evaluates and suggests improvements for both the CLI/TUI (Rich tables, layout, color, information density) and future GUI surfaces. Integrate into the manager pipeline alongside the existing review agents.
- ~~**Debugging capability**~~ -- **Complete.** `--debug` flag writes Python debug output to `/tmp/wifi_monitor_nitro5_debug.log`; `_dump_startup_config` logs all settings at startup; strategic debug points throughout `AirodumpScanner`.

### Features

- **Auto-detect platform and wifi devices** (5 pts) -- Enable running just `wifi_monitor.py` and auto detect OS and WiFi devices. Enumerate interfaces via `/sys/class/net/` or `nmcli`, detect Raspberry Pi via `/proc/device-tree/model`, pick the right scanner automatically.
- **Display RF band for each BSSID** (3 pts) -- Display in output what RF band each BSSID is currently operating in. Add `FREQ` to the nmcli query, map frequency to band (2.4 GHz / 5 GHz / 6 GHz), add a `band` field to the `Network` dataclass, and render in a new table column.
- **Detect number of clients on each BSSID** (3 pts) -- Per-BSSID client counts already work via `--monitor` on Atheros/Realtek USB adapters. Remaining work: improve UX around Intel WiFi limitation (clear in-TUI message when monitor mode yields zero clients), and add a combined mode that uses `--arp` for the connected BSSID and `--monitor` for others when a compatible adapter is present.
- **Deauth attack detection** (8 pts) -- Detect deauthentication/disassociation frames targeting your own network and alert in the TUI. Requires monitor mode capture and 802.11 management frame parsing.
- **Rogue AP detection** (5 pts) -- Identify rogue access points impersonating known SSIDs with mismatched BSSIDs or unexpected channels. Works with existing nmcli scan data; needs a known-good baseline file.
- **Unusual client behavior monitoring** (13 pts) -- Monitor for anomalous client activity on networks you own (e.g. rapid association/disassociation, probe floods). Requires monitor mode and rate-based anomaly heuristics.
- **Raspberry Pi support** (8 pts) -- Monitor mode scanning via airodump-ng with PiTFT display output. The CSV parser (`parse_airodump_csv`) and shared data structures are already implemented.

## Hardware (Pi Phase)

- Raspberry Pi (any model with USB support)
- USB WiFi dongle for monitor mode
- Adafruit Mini PiTFT 135x240 color display
