# Wifimonitor — Claude Agent Guide

## Project Overview

A WiFi monitoring tool written in Python. Currently targets the **Acer Nitro 5 laptop**
using `nmcli` for scanning. Raspberry Pi support (airodump-ng, monitor mode, PiTFT display)
is planned for a future phase.

## Current File Structure

```
Wifimonitor/
├── CLAUDE.md
├── README.md
├── WORK_IN_PROGRESS.md        # Feature blueprints and running commentary
├── src/wifimonitor/
│   ├── __init__.py            # Package metadata/version
│   ├── __main__.py            # Supports: python -m wifimonitor
│   ├── wifi_monitor_nitro5.py # Laptop entry point (Rich TUI, nmcli)
│   └── wifi_common.py         # Shared: Network dataclass, signal/color helpers,
│                              #         airodump-ng CSV parser (Pi, future)
├── wifi_monitor.py            # Raspberry Pi entry point (legacy script)
├── pyproject.toml             # Packaging + tool config (ruff, mypy)
├── requirements.txt           # Pi requirements
├── requirements-laptop.txt    # Laptop requirements (rich>=13.0,<15)
├── requirements-dev.txt       # Dev/CI tooling (pytest, ruff, mypy, pip-audit)
├── .github/workflows/ci.yml   # CI pipeline (test, lint, security)
├── tests/
│   ├── test_wifi_monitor_nitro5.py   # 274 tests — parsing, rendering, scanning, credentials, DNS, ARP, monitor helpers, main()
│   └── test_wifi_common.py           #  71 tests — helpers, airodump CSV, validation, colors, protocol
├── .claude/
│   └── agents/
│       ├── architect-agent.md
│       ├── tdd-agent.md
│       ├── devsecops-agent.md
│       ├── red-team-agent.md
│       ├── reviewer-agent.md
│       ├── scrum-master-agent.md
│       └── manager-agent.md
└── .gitignore
```

## Target Architecture (evolving toward)

```
Wifimonitor/
├── src/wifimonitor/
│   ├── domain/
│   │   └── network.py          # Network dataclass, value objects
│   ├── scanning/
│   │   ├── scanner_protocol.py # Abstract scanner interface
│   │   ├── nmcli_scanner.py    # Nitro5/laptop implementation
│   │   └── airodump_scanner.py # Pi implementation (future)
│   ├── display/
│   │   ├── renderer_protocol.py
│   │   └── rich_renderer.py
│   └── helpers/
│       └── signal.py           # signal_to_bars, signal_color, security_color
├── tests/
│   ├── unit/
│   └── integration/
```

## Language & Platform

- **Language:** Python 3.9+ (enforced at runtime in `src/wifimonitor/wifi_monitor_nitro5.py`)
- **Primary target:** Linux laptop (Acer Nitro 5), `nmcli` for scanning
- **Future target:** Raspberry Pi, airodump-ng/monitor mode
- **Display:** Rich terminal TUI (`rich` library)
- **Testing:** pytest + pytest-cov
- **Linting:** ruff, mypy (strict mode)

## Coding Standards

- **Methodology:** Software Craftsmanship — TDD, SOLID, clean code
- **Test-first:** No production code without a failing test first
- **Coverage target:** 90%+ overall; 100% on pure functions (parsers, helpers)
- **Type hints:** Required on all public interfaces
- **Docstrings:** Google style on all public classes and functions
- **Commits:** Conventional commits (`feat:`, `fix:`, `test:`, `refactor:`, `chore:`)
- **Branching:** Feature branches off `main`; PRs required — no direct pushes to `main`

## Key Domain Knowledge

- **BSSID:** MAC address of the access point (always lowercase in this codebase)
- **SSID:** Human-readable network name (may be empty for hidden networks)
- **Signal:** dBm — higher is better (-50 excellent, -80 poor, -100 no signal)
- **nmcli signal %:** NetworkManager reports 0-100%; convert via `dBm = (pct // 2) - 100`
- **Bars:** 0-4 scale derived from dBm thresholds in `signal_to_bars()`
- **Security labels:** "Open", "WEP", "WPA", "WPA2", "WPA3"

## Agent Invocation

Reference the agent at the start of a session to set its role:

> "Using `.claude/agents/tdd-agent.md`, add tests for `parse_nmcli_output`."

|Agent              |File                 |Use When                                |
|-------------------|---------------------|----------------------------------------|
|Architect          |`architect-agent.md`      |Research approaches, define APIs/modules     |
|TDD / Lead Coder   |`tdd-agent.md`            |Writing any production or test code          |
|DevSecOps          |`devsecops-agent.md`      |Security review, dependency audit, CI/CD     |
|Red Team           |`red-team-agent.md`       |Adversarial review before merging            |
|Reviewer           |`reviewer-agent.md`       |Final audit gate — PASS/FAIL before merge    |
|Scrum Master       |`scrum-master-agent.md`   |Backlog grooming, prioritization, retros     |
|Manager            |`manager-agent.md`        |Orchestrate all agents end-to-end            |

## Test Commands

```bash
# Install package and dev tooling
python3 -m pip install -e .
python3 -m pip install -r requirements-dev.txt

# Run all tests
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ -v --cov=src/ --cov-report=term-missing

# Linting
python3 -m ruff check src/ tests/
python3 -m mypy src/
python3 -m pip_audit -r requirements-laptop.txt
```
