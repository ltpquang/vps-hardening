---
name: vps-hardening-validation
description: Guide an operator through preparing SSH access and running scripts/phase1.py to harden an Ubuntu 24.04 VPS, verify it, or recover a staged run.
---

# Harden an Ubuntu VPS

When the operator invokes this skill, outline the sequence before asking for inputs. Establish trusted SSH access, prepare a non-root administrator, run and verify Phase 1, then report the outcome. Resume at the relevant checkpoint for an existing run.

For a new VPS, ask for its IP address and current SSH username together. Accept the operator's public key in the same reply or ask for it during key setup. State the defaults up front. Assume only `root` is available, connect on port `22`, and keep the current SSH port. Invite the operator to supply a different current port, an existing or preferred administrator username, or a custom target port. Reuse information they already provided.

Report each checkpoint and the next step. When the operator needs to act, give one copy-paste command at a time with known values filled in. Say where to run it and what result to confirm. Keep passwords, passphrases, and private keys on their respective systems. Follow the operator's approval requirements before taking action.

## Establish Trusted SSH Access

1. Have the operator open a trusted VPS session. Give the normal SSH command for an already trusted server, or use the provider console for the first connection, an unfamiliar host key, or missing SSH access. In that session, have them print and share the SSH host key fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Use the actual host key type if it differs. Pin the matching host key in a separate known-hosts file for the agent's connection and use strict host key checking. Stop on a mismatch and resolve it through the provider console.
2. Generate a dedicated temporary agent SSH key in a private local directory. Give the operator its public key. Have them [install both public keys](../../../README.md#provision-and-test-a-key) for the initial SSH account, preserving existing entries. If they need to find their public key, give `cat ~/.ssh/id_ed25519.pub` on their computer, adjusted to their actual path. Wait for explicit confirmation that both keys are installed before testing agent access.
3. Connect with the temporary key and pinned host key. Report the initial access checkpoint only after a fresh login succeeds.

## Prepare the Non-Root Administrator

1. Find the current account and check whether an existing non-root account is suitable for sudo administration. Reuse a suitable account chosen by the operator. With approval, [create one](../../../README.md#identify-the-account) if needed, using `ubuntu` by default, and add it to the `sudo` group. When creating it on the operator's behalf, use `adduser --disabled-password ADMIN` before adding the group. Have the operator set the password privately with `passwd ADMIN` in their root session or `sudo passwd ADMIN` through an existing administrator.
2. Ask the operator to install both public keys for the chosen administrator and explicitly confirm installation. The script also requires the operator's public key in root's `authorized_keys`, even when the initial login is non-root. Have the operator install or confirm it there while respecting the existing root SSH policy. Preserve existing key entries.
3. Verify a fresh agent login to the administrator with the temporary key. Have the operator independently prove a fresh key-only login with their own key and run `sudo -v` in that session. Report the administrator access checkpoint once both logins and the operator's sudo check succeed.

## Run and Verify Phase 1

Use the authorized session that can run each command. If the agent needs a password for sudo, give the operator that command to run in their own session. Keep the provider console available and leave a working SSH session open during staging.

1. [Review and install the script](../../../README.md#2-review-and-copy-the-script) from a known repository revision. Run `plan` with `--admin` and `--operator-key-fingerprint` for the operator's key. Add `--ssh-port` only for a change. Review `PLAN ONLY` with the operator and resolve any failures. Prepare the external checks before starting the rollback timer.
2. Get approval to run `apply` with the reviewed options. Report the staged run ID and rollback deadline as soon as the script prints them.
3. On the selected port, verify a fresh agent login and have the operator open a fresh SSH session with their own key and run `sudo -v`. Use the run's saved script at `/var/lib/vps-phase1/RUN_ID/phase1.py` with `verify --run-id RUN_ID`. Complete the applicable [external port checks](../../../README.md#6-test-public-port-blocking).
4. Once the checks pass and the operator approves, give them the [commit command](../../../README.md#7-commit-reconnect-and-reboot) to run in their fresh administrator session. Substitute the actual run ID and include `--external-checks-passed` only after the external checks succeed. If a check fails, report the time remaining and resolve the failure or [roll back the uncommitted run](../../../README.md#restore-an-uncommitted-run).

## Close Out

After `COMMITTED`, verify access on the final port and run the saved script's `verify` again. With approval, remove only the temporary agent key from each account where it was installed. Use an authorized session or have the operator remove it in their terminal. Confirm the operator can still reconnect with their own key. Report the administrator, final SSH port, run ID, verification results, and any pending recovery or key cleanup.
