# The Security Scan framework

This file defines the method the skill follows. It was distilled from studying how autonomous offensive agents run real intrusions, and it is written as our own method: what we do, in what order, and why.

## Contents

1. Why this method
2. Vocabulary
3. The loop
4. The blackboard
5. Roles
6. Stages
7. Three questions for every check
8. Evidence and grading
9. The inner loop and when to stop
10. Defense layers
11. What the method deliberately does not do

## 1. Why this method

Automated attackers did not invent new techniques. They use valid credentials, unpatched systems, weak identity hygiene and misconfigured applications, as attackers always have. What changed is the pace. An agent enumerates broadly before it goes deep, tests every permission it holds, chains each finding into the next step, retries after every error, and does all of it in minutes, across many targets at once.

Two consequences shape this method:

- **Single weaknesses matter less than chains.** A leaked key is a problem; a leaked key that reads a secret store that holds a deploy credential for production is an incident. The scan must follow chains, not list issues.
- **Time is part of the finding.** If an attacker needs ten minutes and detection needs a day, the control does not exist in practice. Every check asks whether the activity would be seen and stopped in time.

So the scan walks the stages an attacker's agent walks, in the same order, but from the inside and read-only. The inside view is an advantage: the user's own access shows policies, configurations and code an outsider has to guess at, so a weakness can be proven from its configuration instead of by exploiting it.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Run** | One execution of the scan, with its own folder under `.security-scan/runs/`. |
| **Scope** | What this run covers: a repository or project, a team and its services, or the company. Chosen in stage 0. |
| **Asset** | Anything in scope that can be attacked or used: compute, data stores, networks, pipelines, repositories, SaaS tenants, AI services, control planes. |
| **Identity** | Anything that can authenticate: users, service accounts, roles, applications, workloads. |
| **Credential** | The material an identity authenticates with: keys, tokens, secrets, certificates, passwords. |
| **Crown jewel** | An asset whose loss is the business impact: customer data, signing keys, the identity system, production deploy rights, backups. |
| **Fact** | Something observed and backed by evidence, for example "role X can read secret Y". Facts never change once confirmed; a correction supersedes the old fact. |
| **Intent** | A question worth answering next, for example "what can the deploy token found in CI do?". Intents are how one stage feeds the next. |
| **Finding** | A fact, or a set of facts, that is a weakness. It has a priority (P0, P1, P2), an evidence status, a fix and an exploitability note. |
| **Attack path** | An ordered chain of facts from an entry point to a crown jewel. |
| **Choke point** | The finding whose fix breaks the most attack paths. |
| **Evidence** | The redacted output, policy, rule or code excerpt that proves a fact. |

## 3. The loop

Everything in a run is one loop, repeated:

1. **Reason.** Review the blackboard. Pick the next intent: the one that most extends a path toward a crown jewel, or that covers a part of the scope not yet looked at.
2. **Explore.** Take one read-only action that answers it.
3. **Record.** Write the fact with its evidence. Add the intents it opens. If it is a weakness, add a finding.

One action per turn of the loop keeps the trail honest: each fact points to the action that produced it. Breadth comes before depth, because the widest map finds the shortest path.

## 4. The blackboard

`blackboard.json` is the run's shared memory, written only through `scripts/blackboard.py`:

- **facts**: id, statement, stage, domain, evidence reference, confidence
- **intents**: id, question, origin (which fact raised it), status (open, answered, dropped)
- **relations**: typed edges between assets, identities and credentials: `authenticates-as`, `can-assume`, `can-read`, `can-write`, `can-deploy-to`, `reaches` (network), `stores-secret-for`, `trusts`
- **findings**: id, title, stage, priority, evidence status, facts it rests on, fix, exploitability

A blackboard on disk is what makes a run resumable, lets several analysts work without repeating each other, and lets the path planner search for chains mechanically instead of from memory.

## 5. Roles

One planner and six specialists. With subagents they run in parallel; without them, the same agent plays each in turn.

| Role | Responsibility |
|---|---|
| Planner (`SKILL.md`) | Owns the loop, the stage order and the stop conditions. |
| Cartographer | Stage 0. Turns access, connectors and context into the architecture graph. |
| Domain analyst | Stages 1 to 8 inside one technology. Produces facts and candidate findings. |
| Detection analyst | For every exploitable step: would it be logged, alerted and contained in time? |
| Path planner | Stage 9. Chains facts into attack paths and finds choke points. |
| Validator | Tries to refute each finding. Confirms it, or marks it to-validate. |
| Reporter | Writes the stage reports and the consolidated report. |

The validator exists because an agent that looks for weaknesses tends to overstate them: a connectivity check is taken for access, a public value for a secret. A separate, sceptical pass catches that before the user reads it.

## 6. Stages

| # | Stage | Question | Main output |
|---|---|---|---|
| 0 | Scope and architecture | What are we scanning, and what is in it? | Scope, architecture graph, crown jewels |
| 1 | Initial reconnaissance | What does an attacker see first? | Exposed surface, exposed control planes |
| 2 | Initial compromise | Where does an attacker get in? | Exposed credentials, weak entry points |
| 3 | Foothold | What does one credential allow in the first minute? | Effective permissions per identity |
| 4 | Privilege escalation | How does it become admin? | Escalation paths |
| 5 | Internal reconnaissance | What else can be discovered from inside? | What each identity can enumerate and read |
| 6 | Lateral movement | Where can it jump next? | Bridges between environments, tenants, networks |
| 7 | Persistence and control | Where would it hide, and who would notice? | Persistence opportunities, egress and tunnel exposure |
| 8 | Mission | What leaves, and how much damage? | Bulk-read, exfiltration and destruction capability |
| 9 | Attack paths | How do the facts chain? | Ranked attack paths, choke points, validated findings |
| 10 | Consolidated report | What do we fix first? | Report, remediation plan |

Stages 1 and 2 look from the outside in. Stages 3 to 8 assume the attacker already holds something, because in practice they usually do.

## 7. Three questions for every check

1. **Is it possible?** Does configuration allow it? (prevention)
2. **Would it be logged and alerted?** Is there a record, and does anyone get told? (detection)
3. **Could it be contained in time?** Given how fast an automated attacker moves, is there a response that beats it: an automatic revocation, a pre-approved isolation? (response)

A weakness that is possible, silent and uncontained is worse than the same weakness behind an alert that pages someone. The grading reflects that.

## 8. Evidence and grading

Every finding carries two independent labels:

- **Priority**: P0, P1 or P2, from the criteria in `grading.md`. It says how soon the fix is needed.
- **Evidence status**: `confirmed` (configuration, policy or code proves it) or `to-validate` (a strong indication that the scan could not prove read-only).

Priority describes the impact if the finding is true. A to-validate P0 means "validate today", and it is never presented as confirmed.

## 9. The inner loop and when to stop

Stages 3 to 6 repeat. Each new identity or asset found in stage 5 or 6 is a new starting point for stage 3, because that is how an intrusion grows: foothold, escalate, look around, move, and again.

Stop the inner loop when one of these is true, and say which:

- a full pass added no new facts
- the iteration limit in `engagement.yaml` was reached (default 3)
- the user stopped the run

## 10. Defense layers

Fixes are grouped into five layers, from the one that removes the most attack paths to the one that only makes them visible. `defense-layers.md` maps findings to concrete fixes.

1. **Control planes.** Keep management interfaces off the open internet and behind strong authentication.
2. **Identities and keys.** Replace long-lived secrets with short-lived, workload-bound credentials. Least privilege.
3. **Configuration and paths.** Patch, segment, harden. Remove the edges attack paths use.
4. **Application protections.** Server-side authorization, and limits on functions that can be abused at volume.
5. **Detection and response.** See behaviour and sequences, not single events, and respond at machine speed.

## 11. What the method deliberately does not do

- It does not exploit. Proof comes from configuration, policy and code.
- It does not test passwords, spray, crack or phish.
- It does not create, change or delete anything in the user's environment.
- It does not move data out of the environment. Evidence stays in the run folder, redacted.
- It does not try to evade or disable monitoring. Its own activity is tagged so the security team can attribute it, and the timeline of that activity is part of the report.

These limits are what make the scan safe to run against production and safe to hand to other people.
