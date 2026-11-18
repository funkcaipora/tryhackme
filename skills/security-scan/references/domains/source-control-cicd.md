# Domain: Source control and CI/CD

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Repositories, pipelines, runners, package and container registries.

**Read with:** the source-control CLI or connector, repository files, pipeline definitions

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- public repositories, packages and images
- exposed pipeline servers and pages sites

## Stage 2: Initial compromise

- secrets in code, history, pipeline variables and logs
- personal tokens and deploy keys: scope and age
- single sign-on and strong authentication enforcement; outside collaborators

## Stage 3: Foothold

- who can trigger workflows that receive secrets
- triggers that run untrusted code with secrets
- default token permissions

## Stage 4: Privilege escalation

- branch protection gaps
- who can edit pipeline definitions or protected environments
- self-hosted runners

## Stage 5: Internal reconnaissance

- organization-wide read on internal repositories
- secrets readable by workflows
- registry contents

## Stage 6: Lateral movement

- pipeline-to-cloud trust conditions
- runners shared between projects
- deploy keys reused across repositories

## Stage 7: Persistence and control

- who can add deploy keys, webhooks, applications, runners, workflow files
- unreviewed application grants

## Stage 8: Mission

- source code and build artifacts as crown jewels
- package publishing rights
- release signing keys

## Detection sources

- organization audit log, pipeline run logs, secret-scanning alerts

## Collector

`scripts/collectors/source_control_cicd.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
