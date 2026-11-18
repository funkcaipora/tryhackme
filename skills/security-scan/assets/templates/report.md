<!-- Template for report/report.md, the consolidated report of a run.
     Translate headings into the user's language. Replace every {{PLACEHOLDER}}. -->

# Security scan: {{SCOPE_NAME}}

Run `{{RUN_ID}}` · {{START_DATE}} to {{END_DATE}} · read-only, with the access of {{WHO_RAN_IT}}

## Summary

| | Confirmed | To validate |
|---|---|---|
| **P0** fix now | {{N}} | {{N}} |
| **P1** fix within 14 days | {{N}} | {{N}} |
| **P2** fix within 90 days | {{N}} | {{N}} |

**Attack paths found:** {{N_PATHS}}, of which {{N_SILENT}} would raise no alert from start to finish.

**Fix first:** {{FIRST_CHOKE_POINT}}, which breaks {{N}} paths.

## The worst paths

<!-- Up to three. Plain language, entry to impact, two or three sentences each. -->

1. **{{PATH_TITLE}}** ({{MACHINE_TIME_CLASS}}). {{PATH_STORY}}

## Findings

### Confirmed

<!-- P0, then P1, then P2. One block per finding, from templates/finding.md. -->

### To validate

<!-- Same order. Never worded as fact. Each says what would confirm it. -->

### Dropped in validation

| Finding | Why it was dropped |
|---|---|
| {{TITLE}} | {{REASON}} |

## Attack paths

<!-- One block per path. -->

### {{PATH_ID}} · {{ENTRY_POINT}} → {{CROWN_JEWEL}}

Machine time: {{MINUTES_HOURS_DAYS}} · first alert at: {{STEP_OR_NEVER}}

| Step | What happens | Rests on | Technique | Logged | Alerted |
|---|---|---|---|---|---|
| 1 | {{DESCRIPTION}} | {{FACT_ID}} | {{ATTACK_ID}} | {{YES_NO}} | {{YES_NO}} |

## Choke points

| Finding | Paths it breaks | Fix |
|---|---|---|
| {{FINDING_ID}} | {{N}} | {{FIX}} |

## Detection matrix

| Path step | Logged | Alerted | Contained in time |
|---|---|---|---|
| {{STEP}} | {{YES_NO}} | {{YES_NO}} | {{YES_NO_UNKNOWN}} |

## Coverage

| Part of the scope | Scanned | Why not, and what would close the gap |
|---|---|---|
| {{PART}} | {{YES_PARTLY_NO}} | {{REASON_AND_FIX}} |

Inner loop: {{N_PASSES}} passes, ended by {{NO_NEW_FACTS_LIMIT_USER}}.

## Compared with the previous run

<!-- Only when an earlier run exists for the same scope. -->

| Fixed | Still open | New |
|---|---|---|
| {{N}} | {{N}} | {{N}} |

## How this scan was done

Read-only, using only the access already present in the session. Nothing was exploited, changed or taken out of the environment. Evidence is in the run folder, redacted. The audit timeline (`audit-timeline.md`) lists everything the scan did, so monitoring can be checked against it.
