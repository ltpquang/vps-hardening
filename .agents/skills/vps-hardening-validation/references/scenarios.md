# Extended Validation Scenarios

Use the README for commands and expected output. Select separate disposable baselines where a previous run changes the result. Ask the operator to reinstall when a clean image is needed. Keep provider console recovery available during deliberate failure tests.

| Scenario | Evidence to Capture |
| --- | --- |
| Operator access | Verify that a temporary key alone fails preflight for either root or the administrator. Prove login and sudo with the operator's own key before staging and before commit. Verify the timer remains armed if the operator key is removed from the administrator before commit. |
| Default Ubuntu image | Use the full package path. Record pre- and post-upgrade OpenSSH versions and activation mode. Confirm staging, a fresh key login, external blocking, commit, and persistence after reboot. |
| SSH migration and session enforcement | Test both socket-activated and service-based SSH on suitable baselines. During migration, check fresh logins on both ports. Verify that an old-port commit attempt fails. Use a same-port run to exercise the distinct stale-session check with a connection opened before staging. Confirm the final port works and the old port is retired after commit. Include commit-attempt tests in the authorized scope. |
| Manual and timed rollback | Test manual rollback, timer expiry after the staging session disconnects, and expiry across a controlled reboot. Verify restored settings and fresh access. Introduce a narrow, reversible conflict and inspect recovery behavior. Confirm rollback of a committed run reports a no-op. |
| UFW migration | Exercise inactive but enabled UFW, active SSH-only UFW, and a custom saved rule. Verify detection, guard activation before UFW is disabled, and rollback of runtime behavior and saved configuration. Verify refusal of unrecognized firewall objects. |
| Fail2ban and automatic updates | Inspect the journal backend, loaded ban-action ports, IPv4 and IPv6 ban and unban behavior, and APT timers and upgrade origins. Use a recoverable client distinct from the sole administration source for authentication-failure testing. |
| Docker handoff | Install Docker after Phase 1 commit using its official Ubuntu procedure. Record the version and firewall backend. Publish a harmless HTTP container on port `3000` using ordinary Docker port publishing. Verify local HTTP and blocked public IPv4 and IPv6 access. Reboot and verify the guard starts before Docker and protection persists. Remove the test container afterward. Use a fresh pre-Docker image for further Phase 1 apply tests. |

Record each result as passed, failed, pending, or inapplicable with the observation that supports it. Distinguish offline mocks from live evidence. Update the README validation status only for covered behavior.
