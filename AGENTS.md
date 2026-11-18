# Project Instructions

This repository automates first-time hardening of a fresh Ubuntu 24.04 VPS before Docker or applications are installed. No provider network firewall is assumed.

## Repository Overview

- [README.md](README.md) is the operator guide for setup, recovery, and acceptance checks.
- [scripts/phase1.py](scripts/phase1.py) implements `plan`, `apply`, `verify`, `commit`, and `rollback`. It configures SSH, the IPv4 and IPv6 ingress guard, Fail2ban, and automatic security updates.
- [tests/test_phase1.py](tests/test_phase1.py) covers script behavior with mocked system commands. [GitHub Actions](.github/workflows/checks.yml) runs the offline checks on Ubuntu 24.04.

Use [$vps-hardening-validation](.agents/skills/vps-hardening-validation/SKILL.md) to collect the operator's inputs and run the requested Phase 1 command on a VPS.

## Implementation

- Keep `plan` and `verify` free of configuration changes.
- Preserve staged SSH migration, a persistent rollback deadline, and the fresh-session commit requirement.
- Own only the documented configuration files and `inet vps_edge` table. UFW migration may disable UFW after backing up its configuration and activating the guard; rollback must restore UFW before removing the guard. Never flush the whole nftables ruleset.
- Preserve IPv4 and IPv6 coverage and Docker's normal firewall management.
- Do not execute apply, commit, rollback, package operations, or host service changes in a development environment. Use mocked tests or a deliberately provisioned disposable VM.
- Run `python3 -m unittest discover -s tests -v` and `python3 -m py_compile scripts/phase1.py tests/test_phase1.py` after code changes.
- Describe mocked checks and live acceptance tests separately. Never claim production validation without recorded live evidence.

## Writing

Apply [The Elements of Agent Style](https://github.com/yzhao062/agent-style/blob/main/RULES.md) when writing documentation. Use these project-specific defaults:

- Write for an administrator who understands SSH and sudo but is new to Linux firewalls.
- State the purpose before commands, identify the execution location, and explain expected output and failure handling.
- Use plain active sentences, consistent terms, title-case headings, and full forms rather than contractions.
- Use bullets for parallel checks and options. Explain connected reasoning in paragraphs.
- Cite primary documentation beside technical claims and explain each control's rationale.
- Keep security claims within the implemented and tested scope.
- Keep diagrams consistent with the actual execution order.
