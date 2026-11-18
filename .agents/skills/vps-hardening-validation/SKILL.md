---
name: vps-hardening-validation
description: Orchestrate live validation of this repository's Phase 1 hardening script on a disposable Ubuntu 24.04 VPS. Use for first installs, SSH port migrations, timed rollback exercises, or Docker port-publishing acceptance tests.
---

# Validate VPS Hardening

Use the repository's [AGENTS.md](../../../AGENTS.md) for implementation constraints and [README.md](../../../README.md) for operator commands and expected results. Read [the scenario matrix](references/scenarios.md) when the user requests extended coverage or a full validation campaign. For an individual request, run the relevant checks.

## Establish the Test Baseline

- Confirm the authorized target, recovery console access, administrator, and approval instructions. Verify the VPS host key against a trusted fingerprint, including after a reinstall.
- Identify the current SSH port. If the operator has not chosen a target port, ask whether to keep the current port or use a custom one. Record the chosen value and use it consistently in the plan, staged checks, and commit. During a migration, keep access through the old port until commit.
- Record the exact script revision or candidate checksum. Inspect the host read-only before mutation. Capture the Ubuntu release, kernel, OpenSSH and firewall package versions, SSH activation mode, listening ports, relevant firewall state, and public interfaces and routes. Check external reachability over each configured IP family before starting the timer.

### Require the Operator's Key

1. Identify the operator who will retain access. Ask them to supply the public key or its SHA256 fingerprint. If they need a key, guide them through local key generation and fingerprint extraction in the [README](../../../README.md#provision-and-test-a-key). Keep the private key on the operator's client.
2. Inspect the authorized keys for root and the selected administrator over an independently verified connection or through the provider console. If either account or key is missing, instruct the operator to create the administrator or install their public key in the missing account. Perform setup for them when authorized. Installing the key in root's file requires no change to the root SSH policy.
3. Verify the same operator fingerprint in both accounts. Require the operator to prove a fresh key-only administrator login and sudo using that key. If root SSH is already available, also verify the operator's root key login before staging. An agent's temporary access key cannot satisfy the operator check. Hold staging until the operator's access checks pass.

## Execute and Verify

1. **Preview.** Upload the reviewed script to a root-owned path, verify its checksum, and run `plan`. Pass `--operator-key-fingerprint` to both `plan` and `apply`. Review the selected uplinks, old and target ports, package options, UFW findings, and rollback duration. Investigate unexpected UFW findings before seeking authorization to replace the policy.
2. **Stage.** Run `apply` on the VPS with the reviewed options. Keep a recovery path available. Package operations precede the rollback timer and persist through rollback. Record the run ID, deadline, staging options, and saved runner path.
3. **Verify from a new transport.** Disable multiplexing with `ControlMaster=no` and `ControlPath=none`. Require the operator to prove fresh SSH and sudo on the target port using the key supplied to `apply`. Run `verify` with the saved runner and confirm the timer deadline. Hold commit until the operator's access and external checks pass. During a port migration, verify both old and target ports while staged.
4. **Prove external ingress behavior.** Start temporary listeners on the ports under test and confirm they respond locally. Probe the same ports from outside the VPS over IPv4 and configured IPv6, corroborate with the host firewall, and remove the listeners. Record an unreachable test network as pending.
5. **Finalize.** Use `--external-checks-passed` only when the applicable external checks pass. Run `commit` from the operator's fresh administrator SSH transport on the target port before the deadline and within authorization. Confirm fresh access and a disabled rollback timer. After migration, confirm the old listener is gone and external probes to the old port are blocked. Reboot after commit when authorized, then repeat the audit, SSH, and external tests.

## Recover and Close Out

- On interruption, inspect the saved run and timer before issuing another mutation. If checks are incomplete or staging fails, follow the README recovery procedure. Use the authorized manual rollback or allow the timer to recover the host. Verify actual state and fresh access after recovery. Use the provider console if SSH is unavailable.
- Diagnose failures from host evidence. For fixes, run the repository's offline checks and repeat the affected live scenario. Use a clean image when prior tests would invalidate the baseline.
- Report the revision, scenario, versions, expected behavior, observed results, and pending checks. Keep raw logs and access material private. Publish sanitized evidence when authorized. Report remaining test resources and clean them up within scope. Confirm replacement access before removing temporary administrator access on a retained VPS.
