# Wifimonitor — Cursor Agent Guide

Reference agents at the start of a session, e.g.:

> "Using the tdd agent, add tests for `parse_nmcli_output`."

| Agent | Use When |
|-------|----------|
| **architect** | Research approaches, define APIs/modules |
| **tdd** | Writing production or test code |
| **devsecops** | Security review, dependency audit, CI/CD |
| **red-team** | Adversarial review before merge |
| **scrum-master** | Backlog grooming, prioritization, retros |
| **manager** | Orchestrate all agents end-to-end |

Project rules in `.cursor/rules/` and agents in `.cursor/agents/` provide persistent context.
