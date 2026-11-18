#!/usr/bin/env python3
"""Search the blackboard for paths from entry points to crown jewels.

Builds a graph from the blackboard's relations and searches it from every
entry point (internet-facing assets, exposed or weak credentials, an assumed
low-privilege employee or workload) to every crown jewel and to
administrative control of identity, cloud and pipeline. Each edge it uses
must rest on a fact. It ranks paths, marks the weakest-evidence step of
each, assigns a machine-time class and counts how many paths each finding
sits on, which gives the choke points.

Planned interface:
    attack_paths.py --run <run-dir>               # writes attack-paths.json and attack-paths.md
    attack_paths.py --run <run-dir> --max-steps 6
    attack_paths.py --run <run-dir> --to <crown-jewel-id>

Inputs:  blackboard.json
Outputs: attack-paths.json, attack-paths.md
Safety:  Pure computation over the blackboard. No network, no commands.

Status: not implemented yet (build step 4). Until then, do this step
by hand following references/phases/09-attack-paths.md (part 1), and keep the same output files.
"""
import sys

BUILD_STEP = 4
MANUAL_REFERENCE = "references/phases/09-attack-paths.md (part 1)"


def main(argv):
    if any(arg in ("-h", "--help") for arg in argv):
        print(__doc__)
        return 0
    print(
        "attack_paths.py: not implemented yet (build step %d). "
        "Do this step by hand following %s." % (BUILD_STEP, MANUAL_REFERENCE),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
