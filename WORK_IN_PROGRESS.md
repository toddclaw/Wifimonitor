# Work in Progress: ARP-Based Client Detection

## Problem Statement

After an hour of `--monitor` mode, all client counts remain 0. Root cause: Intel WiFi
adapters (iwlwifi / AX200/AX201 family) **do not deliver 802.11 management/association frames
to virtual monitor interfaces** — a documented driver-level limitation, not a code bug.
airodump-ng shows APs but zero stations on Intel hardware regardless of software tuning.

**The `--monitor` path works on Atheros/Realtek USB adapters and is preserved.**
**For Intel built-in WiFi, ARP scanning is the correct approach.**

## Decision

Add `--arp` flag for ARP-based client detection on the connected network. Works on any
WiFi adapter including Intel. Limitation: only counts clients on YOUR connected subnet.

## Size Estimate

| Component | Est. Lines | Notes |
|-----------|-----------|-------|
| `_get_connected_bssid()` helper | ~20 | nmcli -f ACTIVE,BSSID parsing |
| `_get_subnet()` helper | ~20 | ip -4 route parsing |
| `ArpScanner` class | ~60 | arp-scan + nmap fallback |
| `main()` integration + `--arp` flag | ~20 | CLI arg + scan loop |
| Tests | ~150 | 7+ test cases |
| **Total** | **~270** | **Medium feature ~2-4 hrs** |

## To-Do

- [x] Write WORK_IN_PROGRESS.md
- [x] Add `_get_connected_bssid()` to `wifi_monitor_nitro5.py`
- [x] Add `_get_subnet()` to `wifi_monitor_nitro5.py`
- [x] Add `ArpScanner` class to `wifi_monitor_nitro5.py`
- [x] Add `--arp` CLI flag and main() integration
- [x] Write tests in `tests/test_wifi_monitor_nitro5.py`
- [x] Run full test suite — 269 passed
- [x] Commit

## Implementation Notes

### `_get_connected_bssid(interface, runner)`
- Command: `nmcli -t -f ACTIVE,BSSID device wifi list [ifname <iface>]`
- Parse with existing `_split_nmcli_line()` helper (handles escaped colons)
- Return `fields[1].lower()` where `fields[0] == "yes"`, else None

### `_get_subnet(interface, runner)`
- Command: `ip -4 route show dev <iface>`
- Find line matching `r'^(\d+\.\d+\.\d+\.\d+/\d+)\s'` — that's the network CIDR
- Example line: `192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.100`

### `ArpScanner.scan() -> int`
- Primary: `arp-scan -I <iface> --localnet -q` (requires root, most accurate)
  - Parse lines matching `r'^\d+\.\d+\.\d+\.\d+\s+[0-9a-f:]{17}'` — each is a host
- Fallback (if arp-scan not found or fails): `nmap -sn <subnet> -oG -`
  - Count lines matching `Status: Up`
- Returns 0 on any failure (graceful degradation)

### main() integration
- `ArpScanner` created once if `--arp` flag is set (not per-scan)
- Each scan loop iteration:
  1. `client_count = arp_scanner.scan()`
  2. `connected_bssid = _get_connected_bssid(interface, runner)`
  3. Apply `net.clients = client_count` where `net.bssid == connected_bssid`

## Running Commentary

### 2026-02-20
- Root cause confirmed via web research: Intel iwlwifi driver limitation is documented
  on the aircrack-ng forums and Intel community. Not fixable in userspace.
- Decision made to add ARP scanning as a parallel track (`--arp` flag)
- `--monitor` preserved and still works on Atheros/Realtek USB adapters
- Starting implementation...
- Implemented `_get_connected_bssid()`, `_get_subnet()`, `_parse_arp_scan_output()`,
  `_parse_nmap_output()`, and `ArpScanner` class
- Added `--arp` flag to `_parse_args()` and wired into `main()` scan loop
- 29 new tests; full suite: 269 passed, 0 failed
- **COMPLETE — ready for manual smoke test**

### Manual smoke test
```bash
# Install arp-scan if not present
which arp-scan || sudo apt install arp-scan

# Run with ARP client detection (root needed for raw ARP)
sudo python wifi_monitor_nitro5.py --arp

# Expected: connected network's Cli column shows > 0 within first scan cycle
```
