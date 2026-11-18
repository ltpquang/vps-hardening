---
name: vps-hardening-validation
description: Walk a VPS operator through using scripts/phase1.py to preview, apply, verify, commit, or roll back hardening on Ubuntu 24.04.
---

# Walk Through Phase 1

Start with a short overview of the requested steps. For a new setup, say that the operator will prepare SSH access, preview the changes, stage them with automatic rollback, verify from a fresh login, and commit. Start at the relevant step if they already have a plan or staged run.

Guide the operator in chat. The operator runs the commands in their terminal. Give one copy-paste command at a time, say where to run it, and explain what success looks like. Wait for the result before giving the next command. Fill in values already known and ask for missing details only when needed. Use ordinary SSH commands for routine access and add options only for a custom port, a non-default identity, or a specific check. Keep passwords and private-key passphrases in the operator's terminal.

1. **Prepare SSH access.** Make sure the operator can access the provider console and sign in with their own key as a non-root administrator with sudo. The same public key must be installed for root and the administrator. Walk through [key setup](../../../README.md#provision-and-test-a-key) if needed. If SSH shows an unfamiliar host key, have the operator check its fingerprint in the provider console with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` and compare it with the prompt before accepting it. Use the actual host key type if SSH shows a different one.
2. **Copy and preview the script.** Help the operator [review and copy the script](../../../README.md#2-review-and-copy-the-script) if needed. Ask whether to keep the current SSH port or use a custom port. For the operator key fingerprint, have them run `ssh-keygen -lf ~/.ssh/id_ed25519.pub` on their computer, using their actual public key path. On the VPS, give the command below with their values. Add `--ssh-port PORT` only if they chose a new port. Review the `PLAN ONLY` output with them and resolve any failures before continuing.

   ```bash
   sudo /usr/bin/python3 /root/bootstrap/phase1.py plan --admin ADMIN --operator-key-fingerprint SHA256:FINGERPRINT
   ```

3. **Stage the changes.** Once the operator has successfully tested a fresh key-only administrator login and `sudo -v` on the current port, give the same command with `apply` in place of `plan` and the same options. Ask for the staged run ID and rollback deadline from the output. Have the operator keep their current SSH session open.
4. **Verify from a fresh login.** Have the operator open a new SSH connection with their own key on the selected port and run `sudo -v`. If their SSH client reuses connections, add `-S none`. In that new session, use the saved script below. After `verify` passes, guide the operator through the applicable [public port tests](../../../README.md#6-test-public-port-blocking) from outside the VPS.

   ```bash
   sudo /usr/bin/python3 /var/lib/vps-phase1/RUN_ID/phase1.py verify --run-id RUN_ID
   ```

5. **Commit.** Once the checks pass and the operator is ready, give the command below for the same new SSH session. Look for `COMMITTED`, then have the operator reconnect on the selected port.

   ```bash
   sudo /usr/bin/python3 /var/lib/vps-phase1/RUN_ID/phase1.py commit --run-id RUN_ID --external-checks-passed
   ```

For a failed check, explain what failed and how much time remains before automatic rollback if the deadline is known. Help the operator resolve it or [restore the uncommitted run](../../../README.md#restore-an-uncommitted-run) with the saved script's `rollback --run-id RUN_ID` command. At each completed step, confirm the result briefly and give the next action.
