---
name: vps-hardening-validation
description: Collect operator inputs and run the repository's Phase 1 VPS hardening script. Use for a setup preview, staged apply, verification, commit, or rollback on Ubuntu 24.04.
---

# Run Phase 1

Use [README.md](../../../README.md) for the supported procedure. Run the requested `phase1.py` command on the VPS and use its output to decide what information or action is needed next.

## Explain the Plan First

Before collecting inputs or connecting, give the operator a short overview of the requested work. For a new setup, show the order: collect access details and choose the SSH port, run `plan`, prove the operator's SSH and sudo access, stage with automatic rollback, verify the new login and external ingress, then commit. Identify which steps the agent runs and which require the operator. For a preview or an existing run, point out where the request ends or resumes. Ask for the first missing input after giving the overview.

## Ask for Missing Inputs

Reuse values and approvals already given. Ask only for inputs needed for the requested command.

- For a new setup, get the VPS address, current SSH user and port, trusted host-key fingerprint, and administrator username. Ask whether to keep the current SSH port or use a custom one if the operator has not chosen. Use the script defaults for other options unless the operator specifies them or `plan` shows a decision is needed.
- Get the operator's public key or its SHA256 fingerprint for `plan` and `apply`. If the operator needs to generate or install a key, guide them through [key setup](../../../README.md#provision-and-test-a-key). Keep the private key on the operator's client.
- For `verify`, `commit`, or `rollback`, reuse the run ID and saved runner path from `apply`. Ask for the run ID if it is missing.

### Give the Operator One-Line Commands

When the operator needs to do something, say where to run the command and give one copy-paste command for that action. Fill in known values and label any remaining placeholders. Say what success looks like or which output to share. Keep passwords and private-key passphrases in the operator's own terminal.

If the operator lacks the VPS host fingerprint, have them run this in the provider console and share the `SHA256:...` value.

```bash
ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub
```

To get the operator key fingerprint, have them run this on their computer using their actual public key path.

```bash
ssh-keygen -E sha256 -lf ~/.ssh/id_ed25519.pub
```

To prove operator SSH and sudo access, give this command with the actual address, administrator, port, and private key path. Use the current port before staging and the target port afterward. The new shell confirms SSH and sudo worked. Before commit, ask the operator to keep that shell open.

```bash
ssh -F /dev/null -t -p 22 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ControlMaster=no -o ControlPath=none ubuntu@VPS_IP 'sudo -v && exec "$SHELL" -l'
```

## Call the Script

1. **Plan a new setup.** Verify the VPS host key, use the operator-approved SSH access, and run the reviewed script as root from a root-owned location on the VPS. Run `plan --admin <user> --operator-key-fingerprint <fingerprint>`. Add `--ssh-port <port>` for a custom target. Let `plan` check the operator key in both accounts. If it reports missing key material, ask the operator to install their public key for the named account, or do it with authorization, then rerun `plan`.
2. **Apply when authorized.** Before running `apply`, have the operator confirm a fresh key-only login and sudo as the administrator using their own key. Confirm recovery access. Reuse the reviewed plan options and report the run ID and rollback deadline. For a request to preview only, return the plan results.
3. **Use the saved runner for follow-up commands.** Call `verify`, `commit`, or `rollback` with `--run-id`. Before `commit`, confirm fresh operator-key SSH and sudo on the target port and successful external checks from the README. Pass `--external-checks-passed` only once those checks pass. Use the operator's fresh SSH session for commit. If only a temporary agent login is available, give the operator the exact command to run from their session.

## Update the Operator Along the Way

- Report a useful result at each completed phase, such as verified access, a plan decision, staging, verification, commit, or rollback. Include the next action or approval needed.
- After staging, include the run ID and rollback deadline in the operator's time zone when known. If a blocker appears while the timer is active, report what failed and the time remaining.
- During longer operations, report meaningful changes, such as package upgrades finishing or the VPS returning after reboot. Keep routine command output out of progress updates.

Follow the operator's approval instructions before each action that requires approval. Use the [extended scenarios](references/scenarios.md) when the operator specifically requests a live validation campaign.
