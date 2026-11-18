# Stage 3: Foothold

**Question:** With one credential, what can be done in the first minute?

This stage starts the inner loop. Run it once for every identity and credential on the blackboard, and again for each new one that stages 5 and 6 turn up.

## What an automated attacker does here

The moment it holds a credential, it finds out what the credential is worth. It asks the platform who it is, then sweeps permissions without changing anything: dry-run flags, validation-only deployments, a test object written and deleted within a second, dozens of read calls across every service. The sweep takes seconds and tells it which doors are open. Then it looks for a way to run code: a deployment or publishing interface that accepts commands, a remote-execution feature of the platform, a pipeline it can trigger, a database feature that writes files where a web server will execute them.

## What to check, from the inside

Do the attacker's permission sweep without making a single call on the target identity's behalf: read its policies instead.

**Effective permissions of each identity**

- attached and inherited policies, role assignments, group memberships, resource-based policies that name it
- the result of the platform's policy simulation or access analysis, where one exists
- the conditions that narrow it: network, time, device, tags
- what it can reach in the first minute: secret stores, storage, compute, the identity system, pipelines, infrastructure state

**Ways to execute code through the management plane**

- deployment and publishing interfaces that run commands, and who holds their credentials
- remote-command features (run-command, serial console, exec into containers) and who may use them
- CI/CD: who can trigger a pipeline that runs with production credentials; who can change what the pipeline runs
- serverless functions and scheduled jobs an identity can create or modify
- infrastructure-as-code state and who can write to it

**Database accounts that reach beyond data**

- application runtime accounts with rights to write files, run operating-system commands, or change server settings
- shared or default database administrator accounts

**Session and token handling**

- how long tokens for this identity live, and whether they can be revoked
- whether the identity can mint further credentials for itself

## Facts to record

- one fact per identity: its effective permissions, summarized by what they allow (read secrets, launch compute, write policy, deploy)
- one fact per code-execution route, with who can use it
- relations: `can-read`, `can-write`, `can-deploy-to`, `can-assume` from each identity to what it reaches

## Detection lens

- A burst of permission-denied answers from one identity: alerted?
- Identity lookups ("who am I") from a network the identity never used: alerted?
- Dry-run and validation calls across many resource types in seconds: visible anywhere?
- An object written and deleted within a second in storage: is data-plane logging on?
- Use of deployment credentials or remote-command features from an unexpected place: alerted?

## Typical findings

| Finding | Usual priority |
|---|---|
| Low-privilege identity can read the secret store or the infrastructure state | P1, P0 when the credential is already exposed |
| Deployment or publishing interface runs commands with widely held credentials | P1 |
| Anyone who can open a pull request can run a pipeline with production credentials | P1 or P0 |
| Application database account can write files or run commands | P1 |
| Tokens that never expire and cannot be revoked | P1 |
| Identity far broader than its job needs | P2, higher when it reaches a crown jewel |

## Exit criteria

- every identity on the blackboard has an effective-permissions fact, or a gap saying why it could not be read
- every code-execution route in scope lists who can use it

## Stage report

Three parts, as in `reporting.md`. When this stage repeats, add to the same report under a heading for the pass.
