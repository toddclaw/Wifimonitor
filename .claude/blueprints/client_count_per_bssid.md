=== ARCHITECTURAL BLUEPRINT ===
Feature: Client count per BSSID
Date: 2025-02-20

## Research Summary

- **Approaches considered:**
  1. nmcli — Does not provide client counts; NetworkManager API does not expose associated stations.
  2. airodump-ng + monitor mode — Passive capture of 802.11 frames; CSV output includes Stations section with BSSID association. No passphrase required. Already used by Pi wifi_monitor.py.
- **Recommended approach:** Add `--monitor` flag to laptop; when used, enable monitor mode and run airodump-ng; parse CSV via existing `parse_airodump_csv()`; display clients in Rich table.
- **Rationale:** Reuse `parse_airodump_csv()`, `Network.clients`; mirror Pi pattern (wifi_monitor.py AirodumpNG) for consistency.
- **Dependencies:** None new; airodump-ng and iw are system tools (same as Pi).

## Module Design

- **Modified modules:** `wifi_monitor_nitro5.py`
  - Add `--monitor` CLI flag; add `-i/--interface` as monitor interface when `--monitor` used.
  - Add `AirodumpScanner` class (or inline logic) to: enable monitor mode, spawn airodump-ng, read latest CSV, parse with `parse_airodump_csv`.
  - Add `scan_wifi_airodump()` that returns `list[Network]` (or re-export from a helper).
  - Modify `build_table()` to add "Clients" column; always show (0 for nmcli, populated for airodump).
  - Main loop: if `--monitor`, use airodump path; else use nmcli. Cleanup atexit for monitor mode and airodump process.
- **Reused from wifi_common:** `parse_airodump_csv`, `Network`, `CommandRunner` (for test injection).
- **Data contracts:** Same `Network` dataclass; `clients` already exists. No new types.

## Integration Plan

- **Entry point:** `--monitor` flag. Requires root; requires interface with monitor-mode support.
- **Lifecycle:** On start with `--monitor`: enable monitor mode → start airodump-ng → in loop: read CSV, parse, render, sleep. On exit: stop airodump, disable monitor mode (atexit).
- **Error handling:** If monitor mode fails or airodump not found: print warning, fall back to nmcli (clients=0) or exit with clear message. CSV read OSError → return empty list. Timeouts on subprocess.
- **Display:** Add "Cli" column to `build_table()`; value from `net.clients`. Escape not needed (integer).

## Testability Plan

- **Pure functions:** None new; `parse_airodump_csv` already pure.
- **Injection seams:** `CommandRunner` for subprocess; optional file-read seam for CSV path (or mock `glob.glob` and `open`).
- **Contract tests:** `scan_wifi_airodump` returns `list[Network]` sorted by signal; `Network.clients` populated. `build_table` with clients column renders correctly.
- **Integration tests:** Mock subprocess/fs; no live hardware required.

## Sign-off

Architect: APPROVED
Blocking concerns: none
================================
