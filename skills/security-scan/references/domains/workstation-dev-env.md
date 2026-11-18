# Domain: Workstation and developer environment

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** The machine the scan runs on and its toolchain: local credentials, shell and editor configuration, AI assistant configuration, local services.

**Read with:** the local filesystem and shell (metadata only for credential files)

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- local services listening on all interfaces
- tunnels that expose localhost to the internet

## Stage 2: Initial compromise

- credential files, tokens in dotfiles and environment (names and metadata only)
- SSH keys without passphrase
- `.env*` files in working copies

## Stage 3: Foothold

- for each local credential: hand it to its domain playbook to read what it allows

## Stage 4: Privilege escalation

- passwordless sudo, membership of the container runtime group, local admin rights

## Stage 5: Internal reconnaissance

- mounted shares, cloud CLI profiles, cluster contexts, password-manager CLIs signed in

## Stage 6: Lateral movement

- SSH config hosts and agent forwarding
- VPN profiles
- direct production access from the laptop

## Stage 7: Persistence and control

- AI assistant configuration: hooks, connector definitions, instruction files
- shell startup files, git hooks, login items

## Stage 8: Mission

- local copies of production data: dumps, exports, backups

## Detection sources

- endpoint telemetry on the workstation; shell history is not a log source

## Collector

`scripts/collectors/workstation_dev_env.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
