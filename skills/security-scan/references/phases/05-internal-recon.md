# Stage 5: Internal reconnaissance

**Question:** What else can be discovered from inside?

## What an automated attacker does here

With a foothold, it maps the inside the way it mapped the outside: everything, fast. It enumerates the whole directory (every user, group, computer, service account and trust), walks the cloud's services and resources, and reads secret stores in bulk. It hunts for credentials wherever people leave them: internal repositories, container registries and image layers, configuration stores, wikis, tickets, shared drives, logs. It also maps the defender: which machines have no endpoint sensor, where logging is thin. It then works where it is least likely to be seen. Each new credential and system it finds is a new starting point.

## What to check, from the inside

For each identity that reached this stage, ask what it can enumerate and what it can read.

**Enumeration**

- can an ordinary identity list the whole directory: users, groups, service accounts, trusts, policies?
- can it list cloud resources across accounts, subscriptions or projects?
- can it list other tenants, customers or organizations?

**Secrets within reach**

- which secret stores, parameter stores and key vaults the identity can read, and how many secrets in each
- whether reading is scoped to what the workload needs, or to everything in the store
- secrets readable in internal repositories, registries, configuration stores, pipeline settings and logs

**Knowledge stores**

- wikis, tickets, shared drives and chat reachable through the connectors: do they hold credentials, network diagrams, runbooks with passwords?
- password managers and vaults: who can read which collections

**Blind spots an attacker would look for**

- hosts and workloads with no endpoint sensor
- accounts, regions or clusters with audit logging off
- data stores without data-plane logging
- log retention too short to investigate with

**New starting points**

- every identity, credential and system found here that is not yet on the blackboard

## Facts to record

- one fact per identity: what it can enumerate
- one fact per secret store: which identities can read it, and how broadly
- one fact per credential found in a knowledge store: location, type, fingerprint
- one fact per blind spot
- intents: one per new identity or asset, pointing back to stage 3

## Detection lens

- Thousands of directory objects read by one account in minutes: alerted?
- Many secrets read from several stores in a short window: alerted?
- A workload identity reading secrets it never read before: alerted?
- Does anyone review sensor and logging coverage, and how often?

## Typical findings

| Finding | Usual priority |
|---|---|
| Workload identity can read every secret in the store | P1 |
| Credentials in a wiki, ticket or shared drive that many people can read | P1, P0 for a privileged credential |
| Any authenticated user can list other tenants' or customers' data | P0 |
| Production hosts without endpoint sensor | P1 |
| Audit or data-plane logging off for a crown jewel | P1 |
| Whole directory readable by any account | P2, the usual default; note it for the paths it enables |

## Exit criteria

- every identity that reached this stage has its enumeration and secret-reading reach recorded
- blind spots are listed for the scope
- every new identity or asset has an intent that sends it to stage 3

## Stage report

Three parts, as in `reporting.md`. "What could be exploited" lists the new starting points and which pass of the inner loop will take them.
