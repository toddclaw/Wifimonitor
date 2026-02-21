# Work in Progress: Display Currently Connected WiFi Network

## Feature Request

**"Update the display with the current WiFi network the tool is currently connected to."**

The Rich TUI already lists all visible networks, but the one the machine is actively
connected to is indistinguishable from any other. This feature adds a visual indicator
so the user immediately sees which network they are on.

---

## Phase 1 — ARCHITECTURAL BLUEPRINT (Architect Agent)

### Research Summary

**Approaches considered:**

1. **Row highlight via `rich.style.Style`** — pass a per-row `style=` argument to
   `table.add_row()`. Rich supports this natively: rows can have a custom style applied
   that overrides column styles. No new dependencies; already using Rich.

2. **Dedicated "Connected" column** — add a boolean column (e.g. "Con") showing a
   checkmark for the connected row. Clean, explicit, scannable at a glance. Works inside
   the existing `build_table()` pattern (mirrors the "Key" column approach already used).

3. **SSID prefix/suffix decoration** — prepend a unicode symbol (e.g. ▶ or ★) to the
   SSID cell of the connected network. Simple but pollutes the SSID column and may
   misalign when SSIDs are short.

4. **Caption text only** — show "Connected: SSID (BSSID)" in the table caption.
   Informative but not scannable when viewing 20+ networks.

**Recommended approach:** Combine approaches 1 and 2:
- Add a narrow "Con" column (column approach) — always visible, scannable
- Apply a `bold` row style to the connected row (row highlight) — draws the eye
- Use a distinct symbol `[green]●[/green]` in the "Con" column for the connected row

**Rationale:**
- No new dependencies. Rich already supports per-row styles and column cells.
- Consistent with the "Key" column pattern already in `build_table()`.
- Pure data flow: `build_table()` receives `connected_bssid: str | None` as a new
  optional parameter, matching the `credentials` parameter pattern.
- Testable without subprocess: `build_table()` is a pure renderer; the BSSID is passed
  in. The caller (`main()`) already knows the connected BSSID via `_get_connected_bssid()`.
- Pi-compatible: the same `build_table()` signature works for any scanning backend.

**Dependencies:** None new. Rich >= 13.0 already in requirements-laptop.txt.

---

### Module Design

**Modified modules:**
- `wifi_monitor_nitro5.py` — `build_table()` signature extended with `connected_bssid`
- `wifi_monitor_nitro5.py` — `main()` scan loop: call `_get_connected_bssid()` on each
  iteration and pass result to `build_table()`

**No new modules needed.** The BSSID detection function `_get_connected_bssid()` already
exists. No changes to `wifi_common.py` — the `Network` dataclass is unchanged.

**Public API change:**

```python
def build_table(
    networks: list[Network],
    credentials: dict[str, str] | None = None,
    caption_override: str | None = None,
    connected_bssid: str | None = None,   # NEW optional parameter
) -> Table:
    """Build a Rich Table displaying the scanned networks.

    Args:
        networks: List of scanned networks (already sorted by signal).
        credentials: Optional dict of SSID -> passphrase.
        caption_override: Optional caption to use instead of default.
        connected_bssid: Optional BSSID of the currently connected network.
            When provided, the matching row is highlighted bold and shows
            a filled-circle indicator in the 'Con' column.
    """
```

**Data contracts:**
- `connected_bssid` is compared against `net.bssid` (both lowercase) — pure string equality
- `None` means "not connected" or "could not determine" — no "Con" column indicator shown,
  no row highlight applied; column is always rendered (with empty cell for non-connected rows)
- The "Con" column is always present (unlike "Key" which is hidden when no credentials).
  Always visible keeps layout stable — the table doesn't shift columns between scans.

**Dependency direction:** `main()` → `build_table()` ← `_get_connected_bssid()`
No circular dependencies. `build_table()` does not call any subprocess functions.

---

### Integration Plan

**Entry point:** Always-on. No new CLI flag needed. The connected BSSID is cheap to
detect (one `nmcli` call, same as the ACTIVE BSSID lookup already used in `--arp` mode).
The detection runs every scan cycle and is silently skipped if nmcli fails.

**Lifecycle in main() scan loop:**
```
while True:
    ...
    networks = scan_wifi_nmcli(args.interface)   # existing
    connected_bssid = _get_connected_bssid(      # NEW per-cycle call
        args.interface, runner=_DEFAULT_RUNNER
    )
    network_table = build_table(
        networks,
        credentials=credentials,
        caption_override=caption_override,
        connected_bssid=connected_bssid,          # NEW arg
    )
    ...
```

Note: when `--arp` mode is active, `_get_connected_bssid()` is already called. The same
result should be reused rather than calling twice. The implementation will refactor the
`--arp` branch to share the single BSSID lookup.

Note: when `--monitor` mode is active (airodump path), the main interface is still
managed (virtual monitor is on a separate mon0). `_get_connected_bssid()` still works.

**Error handling:** `_get_connected_bssid()` already returns `None` on any failure
(timeout, FileNotFoundError, OSError). `build_table()` handles `None` by rendering no
indicator — graceful degradation with no user-visible error.

**Display composition:**
- "Con" column: width=3, justify="center", no column style override
  - Connected row cell: `"[green]●[/green]"`
  - All other rows: `""`
- Row style: connected row gets `style="bold"` passed to `table.add_row()`
- No changes to any other column

---

### Testability Plan

**Pure functions (no I/O):**
- `build_table(networks, connected_bssid=...)` — pure renderer, fully testable
  without subprocess

**Injection seams (already exist):**
- `_get_connected_bssid(runner=...)` — uses `CommandRunner` protocol; no new seams needed

**Contract tests (TDD agent must write):**
1. `build_table` with `connected_bssid` matching a network → row count correct,
   "Con" column present, no crash
2. `build_table` with `connected_bssid=None` → "Con" column present, cells empty
3. `build_table` with `connected_bssid` matching no network in list → no crash,
   all "Con" cells empty
4. `build_table` with connected SSID containing Rich markup → no crash (escape check)
5. `build_table` with connected BSSID of a hidden network (ssid="") → indicator appears
6. `build_table` with `connected_bssid` uppercase vs lowercase → case-insensitive match
7. `build_table` single network, is connected → row count 1, "Con" column present
8. `build_table` empty network list, `connected_bssid` set → no crash

**Integration tests:** None needed beyond existing unit tests; the `main()` wiring is
covered by the fact that `_get_connected_bssid()` is already well-tested.

---

### Sign-off
```
=== ARCHITECTURAL BLUEPRINT ===
Feature: Display currently connected WiFi network
Date: 2026-02-20

Architect: APPROVED
Blocking concerns: none
================================
```

---

## Story Point Estimate

| Component | Complexity | Est. Points |
|-----------|-----------|-------------|
| `build_table()` signature + "Con" column + row highlight | Low | 1 |
| `main()` wiring (pass connected_bssid every scan cycle) | Low | 0.5 |
| Refactor `--arp` branch to reuse single BSSID lookup | Low | 0.5 |
| Tests (8+ cases, including edge cases) | Low | 1 |
| **Total** | **Low-Medium** | **3 story points** |

Rationale: Well-understood change, no new dependencies, existing helper function,
clean injection seam. Lower bound 2 pts (pure rendering change), upper bound 5 pts
(if table layout changes trigger existing test breakage). Estimate: **3 points**.

---

## Phase 2 — TDD DRAFT (TDD/Craftsmanship Agent)

### Tests to write (RED phase — failing first):

1. `test_build_table_always_has_con_column` — "Con" column always present
2. `test_build_table_connected_bssid_none_con_cells_empty` — None → empty cells
3. `test_build_table_connected_bssid_matching_network_shows_indicator` — shows ●
4. `test_build_table_connected_bssid_no_match_all_cells_empty` — no match → empty
5. `test_build_table_connected_bssid_case_insensitive` — uppercase BSSID matched
6. `test_build_table_connected_hidden_network_shows_indicator` — hidden SSID ok
7. `test_build_table_connected_bssid_markup_safe` — rich markup in BSSID safe
8. `test_build_table_empty_networks_with_connected_bssid_no_crash` — empty list ok

### Production code changes:
- `build_table()`: add `connected_bssid: str | None = None` parameter
- Always add "Con" column (no conditional)
- In row loop: compare `net.bssid.lower()` to `connected_bssid.lower()` (if not None)
- Matching row: cell=`"[green]●[/green]"`, style="bold"
- Non-matching: cell=`""`, no style override
- `main()`: call `_get_connected_bssid()` every iteration; pass to `build_table()`
- `--arp` branch: reuse the same BSSID result; do not call `_get_connected_bssid()` twice

---

## Phase 3 — DEVSECOPS REVIEW

### Checklist:
- [x] No `shell=True` with external data — build_table is pure Python, no subprocess
- [x] BSSID escaped before display: `escape(net.bssid.upper())` already in place
- [x] SSID escaped: `escape(net.ssid)` already in place
- [x] `_get_connected_bssid()` already has timeouts and exception handling
- [x] No hardcoded credentials or paths — indicator is a unicode char constant
- [x] No unnecessary env inheritance — `_minimal_env()` already used
- [x] Input validation: BSSID comparison is `.lower()` equality — safe
- [x] No new dependencies — Rich already present

### Finding: BSSID comparison must be case-insensitive

- The `connected_bssid` from `_get_connected_bssid()` is already lowercased (the function
  returns `fields[1].lower()`). `Network.bssid` is also lowercased at parse time in
  `parse_nmcli_output()`. So `net.bssid == connected_bssid` is already safe.
- **But:** the caller must never pass a mixed-case BSSID directly. The implementation
  should normalize `connected_bssid.lower()` inside `build_table()` as a defensive measure.

### Finding: "●" is a literal unicode char — no escape needed

The indicator `"[green]●[/green]"` is Rich markup, not external data.
The `●` character (U+25CF) is a fixed constant, not from user input. Safe.

**DEVSECOPS: APPROVED with one hardening recommendation (P1):**
- P1: Normalize `connected_bssid` to lowercase inside `build_table()` as defense-in-depth,
  even though the current callers already provide lowercase. Prevents future callers from
  passing uppercase.

---

## Phase 4 — RED TEAM REVIEW

### Input boundary checks:

1. `connected_bssid = ""` (empty string) — must not match any network; empty string
   should be treated as "not connected". **Add: treat `""` same as `None`.**
2. `connected_bssid = "not:a:valid:bssid"` — won't match any network (normal string
   equality); no crash. OK.
3. `connected_bssid` with Rich markup chars e.g. `"[bold]aa:bb:cc:dd:ee:ff[/bold]"` —
   this is only compared to `net.bssid` (equality), never rendered directly.
   The indicator cell is a fixed string, not the BSSID. OK.
4. `networks = []` with `connected_bssid` set — loop never executes; no crash. OK.
5. `connected_bssid` very long (1000 chars) — equality comparison with bssid strings
   that are at most 17 chars; will never match. No crash. OK.

### Failure mode checks:

- `_get_connected_bssid()` returns `None` on every failure path → `build_table()` receives
  `None` → no indicator, no crash. Verified. OK.
- Both `--arp` and non-`--arp` paths call `_get_connected_bssid()` every scan cycle
  (after refactor). If nmcli fails, returns None silently. OK.

### Test quality check:

- Need unhappy path for `connected_bssid = ""` — **add this test**.
- Need test that `build_table` does not call any subprocess (pure function property).
  This is implicit (the test runs without mocking anything) but worth verifying.

### SOLID regression:

- `build_table()` gains a new optional parameter. Single Responsibility maintained:
  it's still a renderer. Open/Closed: existing callers (no `connected_bssid` arg)
  are unaffected.
- No new class instantiated inside `build_table()`. DI rules respected.
- Pi support: no change; `build_table()` is display-only, works with any scanner.

**RED TEAM: APPROVED with two additional tests required (P1):**
- P1: `test_build_table_connected_bssid_empty_string_no_indicator` — empty string treated as None
- P1: (Covered by architecture) — normalize `connected_bssid.lower()` inside `build_table()`

---

## Phase 5 — MANAGER CONSOLIDATION

**Iteration 1:** No P0 issues. Two P1 findings from reviews:

1. Normalize `connected_bssid.lower()` inside `build_table()` (defense-in-depth)
2. Add test for `connected_bssid = ""` (empty string treated as no-connection)

Both are small implementation details, handled in the single TDD iteration below.
Returning to TDD phase with these constraints added.

---

## To-Do

- [x] Write WORK_IN_PROGRESS.md with blueprint
- [x] Write failing tests (RED) — 13 failing as expected
- [x] Implement production code (GREEN)
- [x] Refactor — `_get_connected_bssid()` call consolidated to single call per scan cycle
- [x] Run full test suite — 282 passed (13 new + 269 existing)
- [x] Commit

## Running Commentary

### 2026-02-20

- Feature: show currently connected WiFi network in Rich TUI display
- `_get_connected_bssid()` already exists and is well-tested
- Design decision: "Con" column + bold row highlight; no new CLI flag; always-on
- Story points: 3 (low-medium complexity)
- Architecture approved; proceeding to TDD implementation
- RED: 13 tests written, all failing as expected (TypeError: unexpected keyword argument)
- GREEN: `build_table()` updated with `connected_bssid` param, "Con" column, bold row highlight
- REFACTOR: `_get_connected_bssid()` pulled out of `--arp` block; called once per cycle, shared
- 282 passed, 0 failed — **COMPLETE**
