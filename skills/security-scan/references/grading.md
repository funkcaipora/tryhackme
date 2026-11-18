# Grading: P0, P1, P2

Every finding gets a priority. The priority says how soon the fix is needed, and it comes from what an attacker needs to start, how far the weakness takes them, what is at the end, and whether anyone would notice.

`scripts/grade.py` applies these criteria to structured answers so the same facts always grade the same. When grading by hand, answer the four questions below and write the answers into the finding.

## The four questions

| Question | Answers |
|---|---|
| **Entry**: what must the attacker already have? | `none` (unauthenticated, from the internet) · `exposed-credential` (a credential that is already readable by outsiders or by every employee) · `low-privilege` (any valid low-privilege identity, or a position on one internal system) · `high-privilege` (an admin identity, or several unlikely conditions together) |
| **Reach**: how many steps from here to impact? | `direct` (this weakness is the impact) · `1-2 steps` · `3+ steps` · `no path shown` |
| **Impact**: what is at the end? | `critical` (bulk sensitive data, admin control of identity, cloud or CI/CD, code execution in production, movement of money, destruction of backups) · `significant` (partial privilege, limited internal data, unnoticed persistence, a bridge between environments) · `limited` (information exposure, a hardening gap) |
| **Visibility**: would exploitation be logged and alerted? | `alerted` · `logged-only` · `silent` |

## The criteria

### P0: fix now

Start immediately. Mitigate within 48 hours, even if the full fix takes longer.

A finding is P0 when **any one** of these is true:

1. A valid credential or secret is readable by outsiders or by every employee (a public repository, a client-side bundle, a public bucket, a shared channel) and it grants more than read access to non-sensitive data.
2. A control plane or admin interface is reachable from the internet with weak, default or no authentication.
3. An internet-facing system runs software with a vulnerability known to be exploited in the wild, and no compensating control is in front of it.
4. There is a confirmed path of at most two steps from entry `none` or `exposed-credential` to a `critical` impact.
5. An identity outside the admin group can give itself administrative control in one step.

### P1: fix this cycle

Fix within 14 days.

A finding is P1 when it needs a realistic precondition (entry `low-privilege`) and then **any one** of these is true:

1. It shortens the way to a crown jewel or to admin control: an escalation path of two or more steps, credential reuse across environments, a bridge from non-production to production.
2. It allows persistence nobody would notice: creating users, keys, applications or instances with no alert.
3. It allows bulk reading or moving out of sensitive data with no data-plane logging or egress control.
4. A privileged identity has no strong authentication, or a high-privilege credential is long-lived and not rotated.
5. It is a step of a P0 path, without being the choke point of that path.

### P2: harden

Fix within 90 days, as planned work.

A finding is P2 when:

1. It leads to no impact by itself: defense in depth, hygiene, a low-privilege stale key, verbose errors, missing logs on a non-critical asset.
2. It needs entry `high-privilege`, or several unlikely conditions together.

## Modifiers

Apply after the criteria, in this order:

| Modifier | Effect |
|---|---|
| **Silent.** Visibility is `silent`: exploitation would leave no log, or a log nobody is alerted on. | Raise one level (P2 → P1, P1 → P0). |
| **Isolated.** The affected asset is non-production with no credential, network or pipeline bridge to production. | Lower one level, never below P2. |
| **Choke point.** `attack_paths.py` shows the finding on the most paths. | Level unchanged; it goes first within its level. |

## Evidence status

Priority and evidence are separate labels.

- `confirmed`: configuration, policy or code proves the weakness. Evidence is attached.
- `to-validate`: a strong indication the scan could not prove read-only (for example, a key that looks valid but whose permissions cannot be read with the user's access).

Grade by the impact *if true*. A to-validate P0 means "validate today"; the report lists confirmed and to-validate findings separately and never words a to-validate finding as fact.

## What a graded finding looks like

```yaml
id: F-007
title: CI deploy token in repository history can write to the production bucket
stage: 2
priority: P0
evidence: confirmed
entry: exposed-credential
reach: 1-2 steps
impact: critical
visibility: logged-only
rule: "P0.4: two steps from an exposed credential to production data"
modifiers: []
facts: [K-012, K-031, K-044]
```

## When judgment disagrees with the rule

The criteria are a floor for consistency, not a replacement for thinking. If a finding clearly deserves a different level, change it and write one sentence saying why. The override and its reason are kept in the finding.
