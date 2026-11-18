# Stage 1: Initial reconnaissance

**Question:** What does an attacker see first?

## What an automated attacker does here

It enumerates broadly before going deep. Starting from a domain name or an address range, it maps every reachable host and endpoint, downloads whatever the application serves to anyone (script bundles, source maps, configuration and environment files, API descriptions), and calls the routes those files reveal minutes later. It fuzzes paths and reads error messages for versions and internal names. It prefers the edges of an estate: partner and supplier portals, mobile backends, internal tools exposed by accident, legacy services, things built by another business unit. Those get less attention than the main product and are where it usually gets in.

## What to check, from the inside

Read configuration instead of scanning. The inside view gives the complete list an attacker has to guess at.

**Everything reachable from the internet**

- DNS zones and records in scope, and what each points to
- public addresses, load balancers, API gateways, CDN origins
- firewall and security-group rules that allow traffic from anywhere, and to which ports
- storage with public or anonymous access
- databases, caches, queues and admin ports reachable from outside
- for every exposed thing: who owns it, is it production, is it meant to be public

**Exposed control planes.** These matter most, because whoever reaches one controls what sits behind it:

- cloud consoles and management APIs without network restriction
- application deployment and publishing endpoints
- the Kubernetes API, CI/CD servers, artifact registries
- hypervisor, backup, VPN and firewall management interfaces
- AI gateways, model proxies and AI application builders

**Information the application gives away**

- source maps, environment or configuration files, and API descriptions served publicly
- detailed errors returned to unauthenticated users: stack traces, SQL errors, internal paths, framework versions
- default pages, banners and version headers

**Patch latency of what is exposed**

- software versions of internet-facing systems, from manifests, images and inventory
- how long known fixes take to reach production here
- anything exposed that runs a version with a vulnerability known to be exploited

**The forgotten edge**

- assets in the inventory with no owner, no recent deploy, or no mention in the documentation
- environments that were meant to be temporary

## Facts to record

- one fact per internet-reachable asset: what, where, exposed how, owner, environment
- one fact per exposed control plane, with its authentication method
- one fact per information leak, with what it reveals
- relations: `reaches` from "internet" to each exposed asset

## Detection lens

- Are requests to these assets logged (load balancer, gateway, firewall)?
- Would a burst of sequential path requests, or many "not found" answers from one source, raise an alert?
- Is there an alert when a new public address, DNS record or open rule appears?

## Typical findings

| Finding | Usual priority |
|---|---|
| Control plane or admin interface reachable from the internet with weak or default authentication | P0 |
| Internet-facing system on a version with a known exploited vulnerability | P0 |
| Database or admin port open to the internet | P0 or P1, by what it holds |
| Public source maps, environment files or API descriptions | P1 if they reveal routes or keys, else P2 |
| Detailed errors shown to unauthenticated users | P2 |
| Unowned or forgotten internet-facing asset | P1 |

## Exit criteria

- the list of internet-reachable assets is complete for the scope, or its gaps are named
- every exposed control plane has its authentication method recorded
- each exposed asset is linked to a node in the architecture graph

## Stage report

Three parts, as in `reporting.md`. The "what could be exploited" part lists each exposed asset and leak as an entry point for stage 2.
