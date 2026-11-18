# Domain: AI and LLM infrastructure

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Model gateways and proxies, AI application builders, self-hosted inference, provider keys, agents and their tools, assistant configuration.

**Read with:** gateway and platform configuration (read-only), repository files, provider usage data

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- gateways, proxies and builders reachable from the internet
- model endpoints without authentication
- self-hosted inference ports

## Stage 2: Initial compromise

- default or master keys, installs never initialised
- provider keys in code, client bundles, notebooks
- scope of virtual keys

## Stage 3: Foothold

- what a provider or gateway key can do: models, spend, admin API
- tool permissions of agents

## Stage 4: Privilege escalation

- routes from a limited key to gateway administration
- agent tools holding broad credentials
- tools reachable through prompt injection

## Stage 5: Internal reconnaissance

- provider keys readable through gateway configuration
- conversation logs containing secrets
- retrieval stores with sensitive documents

## Stage 6: Lateral movement

- agent connectors that bridge to cloud, repositories and SaaS
- keys shared across environments

## Stage 7: Persistence and control

- assistant configuration in repositories: hooks, connector definitions
- who can add tools, skills or plugins
- unpinned plugin sources

## Stage 8: Mission

- model enablement and quotas, GPU capacity
- budgets and spend alerts
- what data is sent to providers

## Detection sources

- gateway request logs, provider usage and billing, cloud audit logs for model access

## Collector

`scripts/collectors/ai_llm_infrastructure.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
