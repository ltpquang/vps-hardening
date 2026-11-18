---
name: vps-hardening-validation
description: Collect operator inputs and run the repository's Phase 1 VPS hardening script. Use for a setup preview, staged apply, verification, commit, or rollback on Ubuntu 24.04.
---

# Run Phase 1

Use [README.md](../../../README.md) for the supported procedure. Run the requested `phase1.py` command on the VPS and use its output to decide what information or action is needed next.

## Ask for Missing Inputs

Reuse values and approvals already given. Ask only for inputs needed for the requested command.

- For a new setup, get the VPS address, current SSH user and port, trusted host-key fingerprint, and administrator username. Ask whether to keep the current SSH port or use a custom one if the operator has not chosen. Use the script defaults for other options unless the operator specifies them or `plan` shows a decision is needed.
- Get the operator's public key or its SHA256 fingerprint for `plan` and `apply`. If the operator needs to generate or install a key, guide them through [key setup](../../../README.md#provision-and-test-a-key). Keep the private key on the operator's client.
- For `verify`, `commit`, or `rollback`, reuse the run ID and saved runner path from `apply`. Ask for the run ID if it is missing.

## Call the Script

1. **Plan a new setup.** Verify the VPS host key, use the operator-approved SSH access, and run the reviewed script as root from a root-owned location on the VPS. Run `plan --admin <user> --operator-key-fingerprint <fingerprint>`. Add `--ssh-port <port>` for a custom target. Let `plan` check the operator key in both accounts. If it reports missing key material, ask the operator to install their public key for the named account, or do it with authorization, then rerun `plan`.
2. **Apply when authorized.** Before running `apply`, have the operator confirm a fresh key-only login and sudo as the administrator using their own key. Confirm recovery access. Reuse the reviewed plan options and report the run ID and rollback deadline. For a request to preview only, return the plan results.
3. **Use the saved runner for follow-up commands.** Call `verify`, `commit`, or `rollback` with `--run-id`. Before `commit`, confirm fresh operator-key SSH and sudo on the target port and successful external checks from the README. Pass `--external-checks-passed` only once those checks pass. Use the operator's fresh SSH session for commit. If only a temporary agent login is available, give the operator the exact command to run from their session.

Report the command result, the current run state if available, and any required input or approval. Follow the operator's approval instructions before each action that requires approval. Use the [extended scenarios](references/scenarios.md) when the operator specifically requests a live validation campaign.
