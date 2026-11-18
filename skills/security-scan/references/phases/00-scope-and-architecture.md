# Stage 0: Scope and architecture

**Question:** What are we scanning, and what is in it?

An attacker is handed a target. The scan has to work out its own, from what the session already has. This is the only stage that asks the user anything, and it asks once.

## Step 1: Read the context

Takes seconds and asks nothing. Collect only what is needed to suggest a scope:

- **Working directory.** Is it a repository? Its name, git remotes (host, organization, repository) and shape: one service, a monorepo, an infrastructure repository.
- **Ownership hints.** CODEOWNERS, team or service-catalog files, owner tags in infrastructure code, namespaces.
- **Identities behind the session's access.** For each authenticated CLI and each connector: which account, organization, tenant or project it is logged into. Identity calls only ("who am I"), not inventory ("what exists").
- **What the user said**, in this request and in anything remembered from earlier sessions.

`scripts/discover_access.py --identities-only` and `scripts/discover_workspace.py --summary` produce this.

## Step 2: Ask the scope

This is the first question of the run. Offer the three kinds of scope, each filled in with what step 1 found, and recommend one.

| Scope | Offer it as | Recommend when |
|---|---|---|
| Repository or project | "this repository (`org/name`) and everything it deploys to" | the session is inside one repository |
| Team and its services | "team X and the services it owns: A, B, C" | ownership files or tags name a team, or the user spoke of their team |
| Company | "everything my access reaches in organization Y: these accounts, these organizations" | the session has organization-wide access and no single repository, or the user asked about the company |

How to ask:

- Use the harness's question tool when there is one; otherwise ask in plain text. One question, concrete options, the recommended one first.
- If the request already names the scope ("scan this repo"), do not ask. State the scope in one line and go on.
- In the same message say two things. First, the scan is read-only and uses only the access the user already has. Second, when an artifact tool exists, the report will be published as a private artifact unless the user prefers to keep everything local.
- Record the answer in `engagement.yaml`: the scope kind, what is included, what is explicitly excluded, the report channel.

A narrow scope is not a weaker scan. Whatever the scoped assets depend on (the identity provider, the pipeline, a shared secret store) is followed as far as it affects them. It is just not scanned for its own sake.

## Step 3: Map the architecture inside the scope

No more questions. Read three sources, in this order.

**Access.** What the machine and session can reach:

- CLIs installed and authenticated (cloud providers, Kubernetes, source control, containers, infrastructure-as-code, platform CLIs), with the identity, profiles, contexts, projects and subscriptions of each
- credential files: type, age and location only, never the value
- names of environment variables that look like credentials (names only)
- SSH configuration: hosts and key files (metadata only)

**Connectors.** The tools and connectors in the session. A script cannot see these; list them yourself and write them to `connectors.json`. On each, use only list and describe operations: accounts, zones, repositories, databases, buckets, projects.

**Context.** The repository and the conversation:

- infrastructure code, CI/CD definitions, container and orchestration manifests, dependency manifests
- configuration and `.env*` files (key names only)
- AI agent configuration: settings, hooks, connector definitions, instruction files
- documentation: READMEs, architecture notes, runbooks
- what the user said about the system

`scripts/discover_access.py` and `scripts/discover_workspace.py` cover access and context. Then run the collectors for the domains that turned up.

## Step 4: Build the graph

Record the map on the blackboard with `scripts/blackboard.py`: `add-node` for each thing, `add-fact` for what was observed about it, `link` for each relation.

- **nodes**: identities, credentials, compute, data stores, networks, control planes, pipelines, repositories, SaaS tenants, AI services
- **relations**: `authenticates-as`, `can-assume`, `can-read`, `can-write`, `can-deploy-to`, `reaches`, `stores-secret-for`, `trusts`

The inventories in the run folder are already redacted, so they serve as the evidence for stage 0 facts.

Then mark:

- **Environments.** Production, non-production or unknown, for every node. Say what the classification is based on (account name, tag, branch, namespace).
- **Crown jewels.** Candidates: stores of customer, personal or financial data; secret stores; the identity system; anything with the right to deploy to production; signing keys; backups; AI provider keys and billing.
- **Coverage.** For each part of the architecture: seen, partly seen, or not seen (`blackboard.py coverage`). For what was not seen, say why and which access or connector would show it.

Then `scripts/render_report.py --architecture` writes `architecture.json` and `architecture.md`, with a diagram of the graph.

## Detection lens

Note which log sources exist for the scope (cloud audit logs, data-plane logs, identity sign-in logs, endpoint telemetry, DNS or proxy logs) and whether they are sent somewhere that alerts. Later stages need this to answer "would it be logged and alerted?".

## Exit criteria

- `engagement.yaml` holds a confirmed scope and a report channel
- every in-scope technology has a domain assigned
- crown-jewel candidates are listed, with at least one, or the report says none could be identified and why
- the coverage table names every gap

## Stage report

- **What was found:** the scope, the architecture summary and diagram, crown-jewel candidates, the coverage table. Findings already visible at this point, such as long-lived credentials on the workstation.
- **What must be fixed:** fixes for those early findings, and the access or connectors worth adding to close coverage gaps.
- **What could be exploited:** the starting points for the next stages: every internet-facing asset and every credential found, as intents.

In the `artifact` channel, this report is the first publication of the run's artifact.
