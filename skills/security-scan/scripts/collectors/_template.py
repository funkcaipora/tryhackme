#!/usr/bin/env python3
"""Contract for a domain collector.

One collector per domain (aws.py, kubernetes_containers.py, ...). A collector
runs the fixed list of read-only commands or API calls that the domain
playbook needs for a stage, passes each through guard.py, pipes each output
through redact.py and writes normalized JSON under evidence/<stage>/. It
paginates, rate-limits and tags its calls with the run id where the platform
allows. In a session with connectors and no shell, the agent does the same
reads through the connector and passes the results through redact.py.

Planned interface:
    collectors/<domain>.py --run <run-dir> --stage 3
    collectors/<domain>.py --run <run-dir> --stage 3 --dry-run   # print the commands, run nothing

Inputs:  engagement.yaml (scope), the domain's credentials already present in the environment
Outputs: evidence/<stage>/<domain>-<check>.json, lines in actions.log
Safety:  Read class only. A command that guard.py does not classify as read is skipped and reported.

Status: not implemented yet (build step 3). Until then, do this step
by hand following references/domains/<domain>.md, and keep the same output files.
"""
import sys

BUILD_STEP = 3
MANUAL_REFERENCE = "references/domains/<domain>.md"


def main(argv):
    if any(arg in ("-h", "--help") for arg in argv):
        print(__doc__)
        return 0
    print(
        "_template.py: not implemented yet (build step %d). "
        "Do this step by hand following %s." % (BUILD_STEP, MANUAL_REFERENCE),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
