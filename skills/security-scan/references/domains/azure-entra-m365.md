# Domain: Azure, Entra ID and Microsoft 365

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Subscriptions and resources in Azure, the Entra ID tenant, and Microsoft 365 workloads.

**Read with:** the Azure CLI, Graph read calls or a connector; role and sign-in data read-only

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- public endpoints, app deployment endpoints, storage public access, management ports

## Stage 2: Initial compromise

- service principals with secrets: age
- signed URLs and storage shared keys
- strong authentication and conditional access coverage, legacy protocols, guests, multi-tenant consents

## Stage 3: Foothold

- role assignments per identity, in Azure and in Entra
- publishing credentials, run-command, automation accounts

## Stage 4: Privilege escalation

- who can add credentials to applications and service principals
- role-assignment write, application owners, managed identities
- just-in-time elevation gaps

## Stage 5: Internal reconnaissance

- breadth of key-vault read access
- directory read through Graph
- diagnostic and Defender coverage

## Stage 6: Lateral movement

- directory synchronization accounts
- cross-tenant access and delegated administration
- network peering

## Stage 7: Persistence and control

- who can create applications, credentials, users, machines, public addresses
- alerts on application credential additions and role assignments

## Stage 8: Mission

- mailbox, file and chat access by applications
- storage bulk read and logging
- backup immutability
- AI service spend

## Detection sources

- Entra sign-in and audit logs, Azure activity log, resource diagnostic settings, Defender alerts, unified audit log

## Collector

`scripts/collectors/azure_entra_m365.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
