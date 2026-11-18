# Stage 6: Lateral movement

**Question:** Where can it jump next?

This stage closes the inner loop. Whatever it reaches goes back to stage 3.

## What an automated attacker does here

It reuses what it has everywhere it might work. Credentials harvested on one system are tried against every other: remote administration, databases, internal APIs, registries. Password hashes and tickets are replayed without ever being cracked. It relays authentication between systems that do not require signing. It follows trust: from a vendor's application into every customer tenant that consented to it, from a development account into production through a shared role, from the cloud into the on-premises directory through the synchronization account, from a pipeline into everything the pipeline can deploy to. When one protocol is blocked it switches to another.

## What to check, from the inside

**Network segmentation**

- can internet-facing systems reach the identity system, management networks or data stores directly?
- can non-production reach production: routes, peering, shared networks, firewall rules?
- flat internal networks: rules that allow everything from inside
- for containers: network policies, or everything-talks-to-everything
- which remote-administration protocols are open between segments

**Credential reuse**

- the same credential (by fingerprint) in more than one environment or system
- shared local administrator passwords
- one service account used by many applications
- production credentials present in non-production systems, pipelines or developer machines

**Trust relationships**

- cross-account, cross-subscription and cross-tenant roles: who may assume them, under which conditions
- vendor and partner access into the environment, and the user's organization's access into others
- federation between identity systems

**Bridges between worlds**

- cloud to on-premises: synchronization accounts, federation servers, hybrid agents, and what compromising them yields
- pipeline to runtime: runners with production credentials, self-hosted runners shared between projects, workload-identity trust conditions that are too broad
- workload to cloud: service accounts mapped to cloud roles
- SaaS to SaaS: integrations and tokens that connect one tenant to another

**Protocol hardening**

- signing and channel binding on file-sharing and directory protocols
- legacy authentication protocols still enabled
- remote administration limited to administrative hosts

## Facts to record

- one fact per bridge: from where, to where, by what (network path, shared credential, trust)
- relations: `reaches` for network paths, `trusts` for trust relationships, `authenticates-as` for reused credentials
- intents: one per newly reachable identity or asset, pointing to stage 3

## Detection lens

- One credential used on many hosts within minutes: alerted?
- Sign-ins that use a hash or ticket from a host where that user never logged on: alerted?
- New connections from an internet-facing system toward the identity system: alerted?
- Any access from non-production into production: alerted?
- A service identity signing in to many tenants in a short window: alerted?

## Typical findings

| Finding | Usual priority |
|---|---|
| Production credential present in a non-production system or pipeline | P1 |
| Internet-facing system can reach the identity system or data stores directly | P1 |
| Pipeline trust condition lets any repository or branch assume the production role | P1 or P0 |
| Synchronization account compromise would yield directory-wide control | P1 |
| Shared local administrator password across servers | P1 |
| Signing not required on file-sharing or directory protocols | P1 or P2 |
| Vendor application can act in every tenant with one credential | P1 |

## Exit criteria

- every bridge between environments, tenants and networks in scope is recorded
- every newly reachable identity or asset has an intent for stage 3
- the planner has decided whether another pass of the inner loop is due, and why

## Stage report

Three parts, as in `reporting.md`. State how many passes of the inner loop ran and what ended it.
