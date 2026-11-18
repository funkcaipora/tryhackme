# Domain: Edge and platform services

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** CDN and edge compute, application hosting platforms, backend-as-a-service: DNS, workers and functions, key-value and object storage, managed databases with client access.

**Read with:** the platform's CLI or connector (list and describe only)

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- public routes, preview deployments, default subdomains
- storage and its access rules
- DNS records and what they point to

## Stage 2: Initial compromise

- API tokens: scope and age
- public client keys versus service keys in client code
- dashboard authentication and team members

## Stage 3: Foothold

- what a platform token can do: deploy, read environment, edit DNS

## Stage 4: Privilege escalation

- row-level or document rules that are off or permissive
- functions running with a service role
- tokens that allow account-level changes

## Stage 5: Internal reconnaissance

- environment variables and secrets readable by team roles or builds
- logs containing secrets

## Stage 6: Lateral movement

- integrations linking the platform to repositories, cloud accounts and databases
- environment shared between production and preview

## Stage 7: Persistence and control

- who can add deploy hooks, tokens, DNS records, functions, domains

## Stage 8: Mission

- database and storage bulk read through public keys
- impact of DNS takeover
- usage and billing abuse

## Detection sources

- platform audit log, request logs, usage and billing data

## Collector

`scripts/collectors/edge_paas.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
