<!-- Template for report/remediation-plan.md.
     Translate headings into the user's language. Replace every {{PLACEHOLDER}}.
     Order inside each level: choke points first, then by defense layer (1 before 5). -->

# Remediation plan: {{SCOPE_NAME}}

Run `{{RUN_ID}}` · {{DATE}}

## P0: start now, mitigate within 48 hours

| # | Fix | Finding | Layer | Paths it breaks | Until the full fix | Owner | Done |
|---|---|---|---|---|---|---|---|
| 1 | {{FIX}} | {{FINDING_ID}} | {{LAYER}} | {{N}} | {{INTERIM}} | {{OWNER}} | ☐ |

## P1: within 14 days

| # | Fix | Finding | Layer | Paths it breaks | Owner | Done |
|---|---|---|---|---|---|---|
| 1 | {{FIX}} | {{FINDING_ID}} | {{LAYER}} | {{N}} | {{OWNER}} | ☐ |

## P2: within 90 days

| # | Fix | Finding | Layer | Owner | Done |
|---|---|---|---|---|---|
| 1 | {{FIX}} | {{FINDING_ID}} | {{LAYER}} | {{OWNER}} | ☐ |

## To validate first

Findings the scan could not prove read-only. Validate before scheduling the fix; a to-validate P0 is validated today.

| Finding | Priority if true | What would confirm it |
|---|---|---|
| {{FINDING_ID}} {{TITLE}} | {{PRIORITY}} | {{TO_CONFIRM}} |

## Coverage to add before the next run

| Gap | Access or connector that closes it |
|---|---|
| {{GAP}} | {{ACCESS}} |

## After the fixes

Run the scan again on the same scope. The new report compares itself with this one: fixed, still open, new.
