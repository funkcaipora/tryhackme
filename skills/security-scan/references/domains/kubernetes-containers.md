# Domain: Kubernetes and containers

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Clusters, workloads, service accounts, network policy, registries and images.

**Read with:** kubectl read verbs and `auth can-i`, manifests and charts in the repository, registry metadata

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- API server exposure
- ingress, load-balancer and node-port services
- dashboards

## Stage 2: Initial compromise

- anonymous access
- long-lived service-account tokens and static kubeconfigs
- pull secrets, secrets baked into image layers

## Stage 3: Foothold

- permissions per service account
- exec, attach and port-forward rights
- who can create workloads

## Stage 4: Privilege escalation

- privileged pods, host mounts and host namespaces
- escalate, bind and impersonate rights
- workload-to-cloud identity mapping

## Stage 5: Internal reconnaissance

- secret listing across namespaces
- configuration maps holding credentials
- audit logging and admission coverage

## Stage 6: Lateral movement

- network policies, default allow
- nodes shared across tenants
- cross-cluster trust

## Stage 7: Persistence and control

- who can create scheduled jobs, daemon sets, webhooks, service accounts
- mutable tags and unsigned images

## Stage 8: Mission

- persistent volumes and backups
- encryption and access to the cluster store
- registry write access

## Detection sources

- cluster audit log, admission controller logs, runtime security alerts

## Collector

`scripts/collectors/kubernetes_containers.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
