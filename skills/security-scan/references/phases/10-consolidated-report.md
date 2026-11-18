# Stage 10: Consolidated report

**Question:** What do we fix first?

Nothing new is collected here. This stage joins the stage reports into one, turns findings into a plan, and hands the run over.

## What an automated attacker does here

It documents as it goes: discovered services, credentials, techniques that worked, progress so far. That record is what lets another operator pick up the intrusion, or the same one resume after an interruption. The scan keeps the same discipline for the defender: the report must be good enough that someone who was not in the session can act on it, and the run folder good enough that a later session can continue or re-run it.

## What to produce

Follow `reporting.md` for the files and the channel. Use `scripts/render_report.py --final`.

**Executive summary** (one page)

- the scope and what was covered
- the three worst attack paths, each in two or three plain sentences
- counts by priority, confirmed and to-validate separately
- the five fixes that remove the most risk, choke points first

**Findings**

- grouped by priority: P0, then P1, then P2
- each with: evidence reference, fix, exploitability note, ATT&CK technique, defense layer, the paths it sits on
- to-validate findings in their own list, each with what would confirm it

**Detection matrix**

- rows: the steps of the attack paths; columns: logged, alerted, contained in time
- the summary line: how many paths are silent end to end

**Remediation plan**

- P0: start now, mitigate within 48 hours
- P1: within 14 days
- P2: within 90 days
- within each level, choke points first; for each fix, the defense layer and the paths it breaks

**Coverage**

- what was scanned, what was not and why
- which access or connector would close each gap

**Audit timeline**

- what the scan did and when, from `actions.log`
- an invitation to the security team to compare it with what their monitoring saw: every burst of read calls they did not see is a detection gap an attacker would enjoy too

**Comparison with the previous run**, when one exists for the same scope

- fixed, still open, new

## Before publishing

- run `scripts/redact.py --check` over every output file
- confirm no to-validate finding is worded as fact
- confirm every P0 has a fix someone can act on today

## Exit criteria

- the four files in `report/` exist
- in the `artifact` channel, the artifact shows the consolidated report at the top and every stage below it
- `engagement.yaml` is marked complete, with the end time

## Closing message to the user

In the user's language, short:

1. the counts by priority
2. the P0s, one line each, with their fixes
3. the first choke point and how many paths it breaks
4. where the report is
5. what the scan could not see

Offer the next step that fits: walk through a P0 fix, widen the scope, or schedule a re-run after the fixes.
