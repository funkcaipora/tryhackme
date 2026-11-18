<!-- Template for a stage report: stages/NN-<stage>.md in the `files` channel,
     and the content of one stage section of the artifact in the `artifact` channel.
     Translate headings into the user's language. Replace every {{PLACEHOLDER}}.
     Keep all three parts even when one is empty: write that nothing was found. -->

# Stage {{N}}: {{STAGE_NAME}}

**Question:** {{STAGE_QUESTION}}

Run `{{RUN_ID}}` · scope: {{SCOPE_NAME}} · {{DATE}}{{PASS_NOTE}}

| P0 | P1 | P2 | To validate | Would any of it have been alerted? |
|---|---|---|---|---|
| {{COUNT_P0}} | {{COUNT_P1}} | {{COUNT_P2}} | {{COUNT_TO_VALIDATE}} | {{VISIBILITY_SUMMARY}} |

**Covered:** {{WHAT_WAS_LOOKED_AT}}

**Not covered:** {{GAPS_AND_WHY}}

## 1. What was found

<!-- One block per finding, P0 first. Then the facts worth knowing that are not weaknesses. -->

### {{PRIORITY}} · {{FINDING_ID}} · {{FINDING_TITLE}}

- **Evidence:** {{CONFIRMED_OR_TO_VALIDATE}}. {{EVIDENCE_REFERENCE}}
- **Where:** {{ASSET_AND_ENVIRONMENT}}
- **Why this priority:** {{GRADING_RULE_AND_ANSWERS}}
- **Seen by monitoring:** {{ALERTED_LOGGED_ONLY_SILENT}}

**Other facts**

- {{FACT}}

## 2. What must be fixed

<!-- One fix per finding, in priority order, grouped by defense layer. Specific enough to act on. -->

| Priority | Finding | Fix | Layer | Until then |
|---|---|---|---|---|
| {{PRIORITY}} | {{FINDING_ID}} | {{FIX}} | {{LAYER}} | {{INTERIM_MITIGATION}} |

## 3. What could be exploited

<!-- Describe, never instruct: no payloads, no working exploit, no attack steps.
     Each item becomes an intent for the stage it leads to. -->

| Condition | Technique | What an attacker gains | Leads to |
|---|---|---|---|
| {{CONDITION}} | {{ATTACK_ID_AND_NAME}} | {{GAIN}} | Stage {{NEXT_STAGE}} |

## Next

{{WHAT_THE_NEXT_STAGE_WILL_LOOK_AT}}
