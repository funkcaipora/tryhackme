#!/usr/bin/env python3
"""Apply the P0/P1/P2 criteria to a finding.

Takes the four grading answers for a finding (entry, reach, impact,
visibility) plus its environment and evidence status, applies the criteria
and modifiers of references/grading.md, and returns the priority with the
rule that decided it. Deterministic: the same answers always give the same
priority. An override is accepted only with a written reason, which is
stored in the finding.

Planned interface:
    grade.py --finding F-007                      # reads the answers from the blackboard
    grade.py --entry exposed-credential --reach 1-2 --impact critical --visibility logged-only
    grade.py --all                                # regrade everything (stage 9)
    grade.py --finding F-007 --override P1 --reason "..."

Inputs:  the finding's answers, from the blackboard or from flags; attack-paths.json for the choke-point modifier
Outputs: priority, rule and modifiers, written to the finding
Safety:  Reads and writes the blackboard only, through blackboard.py.

Status: not implemented yet (build step 4). Until then, do this step
by hand following references/grading.md, and keep the same output files.
"""
import sys

BUILD_STEP = 4
MANUAL_REFERENCE = "references/grading.md"


def main(argv):
    if any(arg in ("-h", "--help") for arg in argv):
        print(__doc__)
        return 0
    print(
        "grade.py: not implemented yet (build step %d). "
        "Do this step by hand following %s." % (BUILD_STEP, MANUAL_REFERENCE),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
