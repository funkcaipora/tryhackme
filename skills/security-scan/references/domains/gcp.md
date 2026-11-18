# Domain: Google Cloud

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Organizations, folders, projects, identity, network, compute, storage, data and AI services in Google Cloud.

**Read with:** the gcloud CLI or a connector, read-only calls; policy analysis where available

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- external addresses, firewall rules open to anywhere
- public buckets
- serverless services that allow unauthenticated calls

## Stage 2: Initial compromise

- service-account keys: age
- default service accounts with broad roles
- organization policy on key creation, two-step verification, domain-wide delegation

## Stage 3: Foothold

- bindings per principal
- remote login and tunnelling access
- serverless deploy rights

## Stage 4: Privilege escalation

- acting as a service account, token creation, policy setting, custom role editing
- metadata server exposure

## Stage 5: Internal reconnaissance

- breadth of secret access
- organization-level viewers
- data-access log configuration

## Stage 6: Lateral movement

- shared networks
- cross-project service accounts
- workload identity pool conditions

## Stage 7: Persistence and control

- who can create keys, service accounts, instances, firewall rules
- organization policies and alerting

## Stage 8: Mission

- bulk read of warehouses and buckets; data-access logs
- snapshot and image sharing
- AI quotas and billing alerts

## Detection sources

- Cloud Audit Logs (admin activity and data access), Security Command Center, VPC flow logs, billing alerts

## Collector

`scripts/collectors/gcp.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
