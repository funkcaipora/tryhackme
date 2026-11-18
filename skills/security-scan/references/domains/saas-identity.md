# Domain: SaaS and identity providers

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** The identity provider and the SaaS tenants in scope: directory, single sign-on, mail, files, chat, ticketing.

**Read with:** admin connectors and APIs, read-only

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- sign-in pages, public sign-up, tenant discovery
- publicly shared links and files

## Stage 2: Initial compromise

- strong authentication coverage, legacy protocols, lockout
- recovery flows
- API tokens, application grants, provisioning tokens

## Stage 3: Foothold

- admin roles per identity
- scopes of integrations
- delegated administration

## Stage 4: Privilege escalation

- who can assign roles
- help-desk reset paths
- application owners
- number of super administrators

## Stage 5: Internal reconnaissance

- directory readable by any user
- shared drives and channels holding secrets
- audit log availability

## Stage 6: Lateral movement

- federation and its signing keys
- cross-tenant collaboration
- mapping from single sign-on to cloud roles

## Stage 7: Persistence and control

- who can create users, tokens, applications, mail forwarding rules
- alerts on new admins, new applications, forwarding

## Stage 8: Mission

- bulk export of mail, files and chat
- external sharing settings
- retention and backup
- abuse of notifications

## Detection sources

- identity provider system log, SaaS audit logs (availability depends on plan)

## Collector

`scripts/collectors/saas_identity.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
