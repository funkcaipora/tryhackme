# Domain: Active Directory

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** On-premises directory services: domains, forests, trusts, certificate services, group policy.

**Read with:** directory queries with the user's own account, read-only; exported collection data if the user provides it

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- directory-integrated services reachable from outside: VPN, mail, remote desktop gateways, federation

## Stage 2: Initial compromise

- password and lockout policy
- accounts without pre-authentication
- stale enabled accounts, passwords that never expire

## Stage 3: Foothold

- what an ordinary domain user can read and do
- logon rights on servers

## Stage 4: Privilege escalation

- service accounts with weak encryption or old passwords
- replication rights, certificate templates, delegation
- local administrator password readers, privileged group membership, known escalation patches

## Stage 5: Internal reconnaissance

- enumeration by any user
- credentials in group policy and shares
- endpoint sensor coverage

## Stage 6: Lateral movement

- local administrator reuse, admin logons on lower-tier hosts
- signing and channel binding, legacy authentication
- trusts and cloud synchronization

## Stage 7: Persistence and control

- who can create accounts, policies, scheduled tasks
- protected-object settings
- age of the ticket-granting key

## Stage 8: Mission

- access paths to the directory database
- domain controller backups
- file servers
- group policy as a deployment channel

## Detection sources

- domain controller security logs, certificate services logs, endpoint telemetry

## Collector

`scripts/collectors/active_directory.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
