# Reporting

A report is written at the end of every stage, and a consolidated report at the end of the run. Reporting during the run, not only after it, lets the user act on a P0 while the scan continues, and leaves a usable record if the run is interrupted.

## The stage report

Every stage report has the same three parts. Use `assets/templates/stage-report.md`.

1. **What was found.** The facts that matter and the findings, each with its priority (P0, P1, P2), its evidence status and a pointer to the evidence. Include what could not be seen, as gaps.
2. **What must be fixed.** One fix per finding, ordered by priority, concrete enough to act on: the setting, policy or line to change. Group by defense layer (`defense-layers.md`).
3. **What could be exploited.** For each exploitable condition: what it is, the technique an attacker would use (`attack-mapping.md`), what they would gain, and which stage it leads to. Describe; never include a payload, a working exploit or step-by-step attack instructions.

The third part is the handover to the next stage: each item becomes an intent on the blackboard.

Also give, at the top: the stage's question, what was in scope for it, counts by priority, and whether anything in the stage would have been logged and alerted.

## Chat summary

After each stage, tell the user in a few lines: the counts by priority, the single most urgent fix, and what the next stage will look at. Then continue. If the stage found a P0, say so first.

## Where the report goes

Decide once, in stage 0, and record it in `engagement.yaml` under `report.channel`.

### Channel `artifact`: the harness has an artifact tool

Use this in Claude Code, claude.ai and Cowork, when a tool for publishing artifacts is available in the session.

- The whole run has **one** artifact. Publish it at the end of stage 0. After every later stage, regenerate the page and publish again to the same artifact, so the link stays the same and the page grows.
- The page source is `live-report.html` in the run folder, rendered from `assets/templates/live-report.html` by `scripts/render_report.py --live`. Publishing the same file path again updates the artifact in the same session.
- Save the artifact's URL in `engagement.yaml` under `report.artifact_url`. When a run is resumed in a new session, read the artifact first and publish to that URL, so the run does not get a second artifact.
- Page layout: a header with the scope, the date and one progress marker per stage; counts by priority; one section per completed stage with the three parts; at stage 10, the consolidated report goes to the top.
- Name the artifact after the scope, for example "Payments API Security Scan". Keep the name for the whole run.
- The artifact is private by default. Do not change its sharing.
- Run `scripts/redact.py --check` on the page before every publish. A page that fails the check is not published.

The run folder still exists in this channel. It holds the working state (blackboard, evidence, log) that the page is rendered from and that a resumed run needs. Only the per-stage files in `stages/` are skipped.

### Channel `files`: no artifact tool

- Write one file per completed stage to `stages/NN-<stage-name>.md`.
- At stage 10, write the consolidated set to `report/`.
- Nothing is published anywhere.

### When the user wants everything local

If the user answers the stage 0 notice with "keep it local", use the `files` channel even when an artifact tool exists.

## The consolidated report (stage 10)

Written to `report/` in both channels, and shown at the top of the artifact in the `artifact` channel.

| File | Content |
|---|---|
| `executive-summary.md` | One page: scope, the three worst attack paths in plain language, counts by priority, the five fixes that remove the most risk. |
| `report.md` | All findings grouped by priority, each with evidence, fix, exploitability, ATT&CK technique and defense layer. Confirmed and to-validate findings in separate lists. Coverage gaps. |
| `remediation-plan.md` | Fixes ordered P0 (48 hours), P1 (14 days), P2 (90 days). Choke points first within each level. One owner placeholder per fix. |
| `audit-timeline.md` | What the scan itself did and when, from `actions.log`, so the security team can check which of that activity their monitoring saw. |

If an earlier run exists for the same scope, add a short comparison: findings fixed, findings still open, new findings.

## Writing rules

- Write in the user's language.
- Lead with what needs action. A reader who stops after the first screen should know the P0s.
- One finding, one fix. Avoid lists of generic advice.
- Say what was not covered and why (no access, out of scope, not implemented).
- Never state a to-validate finding as fact.
- No secret values, anywhere.
