# Stage 9: Attack paths and validation

**Question:** How do the facts chain, and which findings survive scrutiny?

Stages 1 to 8 produced facts. This stage turns them into the thing an attacker's agent actually produces: complete paths from an entry point to a crown jewel. Then it tries to break its own conclusions.

## Part 1: Chain

Run `scripts/attack_paths.py`, or search the blackboard by hand:

1. **Entry points.** Every internet-facing asset from stage 1 and every exposed or weak credential from stage 2. Add "any low-privilege employee" and "any workload in the scope" as assumed starting positions.
2. **Targets.** Every crown jewel from stage 0, plus administrative control of the identity system, the cloud and the pipeline.
3. **Search.** Follow relations from each entry point: `authenticates-as`, `can-assume`, `can-read`, `can-write`, `can-deploy-to`, `reaches`, `stores-secret-for`, `trusts`. Each relation used must rest on a fact with evidence.
4. **Write each path** as numbered steps. For every step: the fact it rests on, the technique (`attack-mapping.md`), and the answer to "would this be logged and alerted?".
5. **Estimate machine time** for the whole path, as a class, not a number: `minutes` (every step is a read or a single API call), `hours` (needs offline work such as cracking, or waiting for a pipeline), `days` (needs something that rarely happens).
6. **Find choke points.** Count how many paths each finding appears on. The finding on the most paths is the first fix.

Keep paths short and real. A path with a step that rests on a to-validate fact is itself to-validate; say which step.

## Part 2: Validate

Hand every finding and every path to the validator role (`agents/validator.md`), whose job is to refute it:

- Does the evidence show what the finding claims, or something weaker? Reaching a port is not access. A key that exists is not a key that works. A permission in a policy can be denied by a boundary, a condition or an organization-level rule.
- Is the "secret" actually secret, or a public identifier?
- Is the asset really production, really in scope, really a crown jewel?
- Does a compensating control break the path: a network restriction, a required second factor, an approval step?
- Is the same weakness reported twice under different names?

Outcomes: `confirmed`, `to-validate` (say what would confirm it), or `dropped` (say why; keep the record).

## Part 3: Regrade

With paths known, grading can change:

- a finding that seemed minor may sit on a two-step path to a crown jewel
- a finding that seemed serious may lead nowhere in this environment
- apply the modifiers in `grading.md`: silent, isolated, choke point

Run `scripts/grade.py` again over all findings and record what changed and why.

## Detection lens

For each path, mark the first step that would raise an alert. A path with no such step is silent end to end; say so prominently. For paths that do alert, compare the path's machine-time class with how fast the team can respond: an alert at step 4 of a `minutes` path only helps if the response is automatic.

## Exit criteria

- every crown jewel has either at least one path or a statement that none was found from the facts available
- every finding is `confirmed`, `to-validate` or `dropped`
- choke points are ranked
- priorities reflect the paths

## Stage report

- **What was found:** the paths, ranked by priority and then by length; the choke points; what validation dropped or downgraded.
- **What must be fixed:** the choke points first, each with the number of paths it breaks.
- **What could be exploited:** each path told as a short story in plain language, entry to impact, with its machine-time class and where, if anywhere, it would be noticed.
