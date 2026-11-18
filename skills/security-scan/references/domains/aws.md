# Domain: AWS

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Accounts, organizations, identity, network, compute, storage, databases and AI services in AWS.

**Read with:** the AWS CLI or an AWS connector, read-only calls; policy simulation and access analysis where available

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- public addresses, security groups open to anywhere
- public buckets, databases, snapshots and images
- API gateways and function URLs

## Stage 2: Initial compromise

- users with access keys: age and last use
- root usage, strong authentication, identity-center setup
- cross-account roles and external identifiers

## Stage 3: Foothold

- effective permissions per principal
- remote-command and exec features

## Stage 4: Privilege escalation

- pass-role with compute launch
- policy and role editing, key creation for others, assume-role chains
- instance metadata without session tokens

## Stage 5: Internal reconnaissance

- breadth of secret and parameter read access
- organization-wide read
- logging coverage gaps

## Stage 6: Lateral movement

- network peering and transit
- cross-account trust, roles shared between development and production
- pipeline trust conditions

## Stage 7: Persistence and control

- who can create users, keys, roles, instances, addresses, rules
- organization policies
- alerting on those events

## Stage 8: Mission

- bulk read of object storage and databases; data-event logging
- snapshot sharing, backup vault protection
- model access, quotas and budgets

## Detection sources

- CloudTrail (management and data events), GuardDuty, Config, VPC flow logs, billing alerts

## Collector

`scripts/collectors/aws.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
