<!-- Template for one finding in report.md.
     Translate headings into the user's language. Replace every {{PLACEHOLDER}}. -->

### {{PRIORITY}} · {{FINDING_ID}} · {{FINDING_TITLE}}

| | |
|---|---|
| **Evidence** | {{CONFIRMED_OR_TO_VALIDATE}} |
| **Stage** | {{STAGE_N}}: {{STAGE_NAME}} |
| **Where** | {{ASSET}} · {{ENVIRONMENT}} |
| **Technique** | {{ATTACK_ID}} {{ATTACK_NAME}} |
| **Defense layer** | {{LAYER_N}}: {{LAYER_NAME}} |
| **On attack paths** | {{PATH_IDS_OR_NONE}} |

**What is wrong.** {{DESCRIPTION}}

**How we know.** {{EVIDENCE_SUMMARY}} (`{{EVIDENCE_PATH}}`)

**Why {{PRIORITY}}.** Entry: {{ENTRY}}. Reach: {{REACH}}. Impact: {{IMPACT}}. Visibility: {{VISIBILITY}}. Rule: {{RULE}}. Modifiers: {{MODIFIERS_OR_NONE}}.

**What must be fixed.** {{FIX}}

**Until then.** {{INTERIM_MITIGATION_OR_NONE}}

**What could be exploited.** {{CONDITION}} An attacker would gain {{GAIN}}.

<!-- Only for to-validate findings: -->
**To confirm.** {{WHAT_WOULD_CONFIRM_IT}}
