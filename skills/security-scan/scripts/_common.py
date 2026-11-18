"""Helpers shared by the scripts: where the current run is, timestamps, the action log."""
import datetime
import os
import sys

RUN_AREA = ".security-scan"

STAGES = {
    0: "scope-and-architecture",
    1: "initial-recon",
    2: "initial-compromise",
    3: "foothold",
    4: "privilege-escalation",
    5: "internal-recon",
    6: "lateral-movement",
    7: "persistence-and-control",
    8: "mission",
    9: "attack-paths",
    10: "consolidated-report",
}

SKILL_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fail(message, code=1):
    sys.stderr.write(message.rstrip() + "\n")
    raise SystemExit(code)


def find_run(start=None):
    """The run folder named by .security-scan/current, looking upward from `start`."""
    folder = os.path.abspath(start or os.getcwd())
    while True:
        pointer = os.path.join(folder, RUN_AREA, "current")
        if os.path.isfile(pointer):
            with open(pointer, "r", encoding="utf-8") as handle:
                run = os.path.join(folder, handle.read().strip())
            return run if os.path.isdir(run) else None
        parent = os.path.dirname(folder)
        if parent == folder:
            return None
        folder = parent


def require_run(explicit=None):
    """The run to work on: --run when given, otherwise the current one."""
    if explicit:
        run = os.path.abspath(explicit)
        if not os.path.isdir(run):
            fail("no run folder at %s" % explicit)
        return run
    run = find_run()
    if not run:
        fail("no current run: start one with `blackboard.py init`, or pass --run")
    return run


def display_path(path):
    """Show a path with the home directory written as ~."""
    home = os.path.expanduser("~")
    path = os.path.abspath(os.path.expanduser(path))
    if path == home:
        return "~"
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def log_action(run, klass, stage, command, note=""):
    """Append one line to the run's actions.log. The command text is redacted first."""
    if not run:
        return
    import redact  # local import: redact.py has no dependency on this module

    line = "\t".join(
        [
            now_iso(),
            klass,
            "stage=%s" % stage,
            redact.redact_text(" ".join(str(command).split())),
            redact.redact_text(" ".join(str(note).split())),
        ]
    )
    with open(os.path.join(run, "actions.log"), "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
