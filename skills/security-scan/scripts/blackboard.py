#!/usr/bin/env python3
"""Create a run and read or write its blackboard.

The blackboard is the run's shared memory. This script is the only writer. It
creates the run folder, checks every entry against the schema, assigns
identifiers, refuses a confirmed fact without evidence, refuses text that
contains a secret value, removes duplicates and keeps facts immutable: a
correction supersedes the old fact, it does not overwrite it. A file lock lets
several analysts write at once.

Usage:
    blackboard.py init --scope-kind repository --scope "org/name" [--include X ...] [--channel artifact]
    blackboard.py status
    blackboard.py engagement show | set KEY VALUE | add KEY VALUE
    blackboard.py add-node --kind identity --name "ci-deploy role" --domain aws [--crown-jewel]
    blackboard.py add-fact --stage 2 --domain aws --statement "..." --evidence evidence/02/x.json
    blackboard.py add-intent --question "..." --from K-012 --for-stage 3
    blackboard.py next-intent [--domain aws] [--stage 3]
    blackboard.py resolve-intent I-007 --with K-031        (or --drop "reason")
    blackboard.py link --from N-004 --rel can-read --to N-019 --fact K-031
    blackboard.py add-finding --title "..." --stage 2 --facts K-012,K-031 --priority P0 ...
    blackboard.py coverage --part "AWS account prod" --seen partly --note "no org-level access"
    blackboard.py stage-note --stage 0 --covered "..." --next "..."
    blackboard.py stage-done 0
    blackboard.py log --class read --stage 0 --command "aws sts get-caller-identity"
    blackboard.py list nodes|facts|intents|relations|findings [--stage N] [--json]
    blackboard.py export --format json|architecture
    blackboard.py validate

Every command except init works on the current run (.security-scan/current) or
on the folder given with --run.

Inputs:  the run folder; assets/schemas/*.json
Outputs: blackboard.json; engagement.yaml and the folder layout on init
Safety:  writes only inside the run folder. On init it makes sure
         .security-scan/ is ignored by git, adding it to .git/info/exclude when
         it is not, so a run is never committed.
"""
import argparse
import contextlib
import datetime
import json
import os
import re
import subprocess
import sys

import _schema
import _yamlite
import redact
from _common import RUN_AREA, fail, log_action, now_iso, require_run

try:
    import fcntl
except ImportError:  # not available on Windows; writes are then not locked
    fcntl = None

PREFIX = {"nodes": "N", "facts": "K", "intents": "I", "findings": "F"}
ENGAGEMENT_HEADER = (
    "Managed by blackboard.py. Change it with `blackboard.py engagement set`.\n"
    "Field meanings: assets/templates/engagement.yaml in the skill."
)


# ------------------------------------------------------------------- storage

@contextlib.contextmanager
def locked(run):
    handle = open(os.path.join(run, ".lock"), "w")
    try:
        if fcntl:
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl:
            fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def load_board(run):
    with open(os.path.join(run, "blackboard.json"), "r", encoding="utf-8") as handle:
        board = json.load(handle)
    board.setdefault("stages", {})
    board.setdefault("coverage", [])
    return board


def save_board(run, board):
    target = os.path.join(run, "blackboard.json")
    temporary = target + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(board, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(temporary, target)


def load_engagement(run):
    return _yamlite.load(os.path.join(run, "engagement.yaml"))


def save_engagement(run, engagement):
    errors = _schema.validate(engagement, _schema.load_schema("engagement.schema.json"))
    if errors:
        fail("engagement.yaml would be invalid:\n  " + "\n  ".join(errors))
    _yamlite.dump(engagement, os.path.join(run, "engagement.yaml"), header=ENGAGEMENT_HEADER)


def next_id(items, prefix):
    highest = 0
    for item in items:
        match = re.match(r"^%s-([0-9]+)$" % prefix, item.get("id", ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return "%s-%03d" % (prefix, highest + 1)


def item_schema(collection):
    return _schema.load_schema("blackboard.schema.json")["properties"][collection]["items"]


def check_item(collection, item):
    errors = _schema.validate(item, item_schema(collection))
    if errors:
        fail("this entry is not valid:\n  " + "\n  ".join(errors))


def ensure_clean(*texts):
    """Refuse text that holds a secret value. The blackboard records where a secret is, never what it is."""
    for text in texts:
        if text and redact.scan(str(text)):
            fail(
                "this text looks like it contains a secret value. Record the secret's type, "
                "location, age and fingerprint instead (redact.py prints the fingerprint)."
            )


def ids(items):
    return {item["id"] for item in items}


def require_ids(wanted, items, what):
    missing = [value for value in wanted if value not in ids(items)]
    if missing:
        fail("unknown %s: %s" % (what, ", ".join(missing)))


def split_list(text):
    return [part.strip() for part in (text or "").split(",") if part.strip()]


# ------------------------------------------------------------------------ init

def ensure_ignored(root):
    """Make sure git ignores the run area. Returns a note saying what was done."""
    def git(*arguments):
        return subprocess.run(["git", "-C", root] + list(arguments), capture_output=True, text=True, timeout=15)

    try:
        if git("rev-parse", "--is-inside-work-tree").returncode != 0:
            return "not a git repository, nothing to ignore"
        if git("check-ignore", "-q", RUN_AREA + "/probe").returncode == 0:
            return "%s/ is already ignored by git" % RUN_AREA
        exclude = git("rev-parse", "--git-path", "info/exclude").stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "git is not available; make sure %s/ is never committed" % RUN_AREA
    if not exclude:
        return "could not find .git/info/exclude; make sure %s/ is never committed" % RUN_AREA
    if not os.path.isabs(exclude):
        exclude = os.path.join(root, exclude)
    os.makedirs(os.path.dirname(exclude), exist_ok=True)
    with open(exclude, "a", encoding="utf-8") as handle:
        handle.write("\n# security-scan run output: findings and evidence, never commit\n%s/\n" % RUN_AREA)
    return "added %s/ to %s" % (RUN_AREA, exclude)


def cmd_init(args):
    root = os.path.abspath(args.root)
    run_id = args.run_id or datetime.datetime.now().strftime("%Y%m%d-%H%M")
    if not re.match(r"^[0-9]{8}-[0-9]{4}$", run_id):
        fail("--run-id must look like YYYYMMDD-HHMM")
    relative = os.path.join(RUN_AREA, "runs", run_id)
    run = os.path.join(root, relative)
    if os.path.exists(run):
        fail("a run named %s already exists; wait a minute or pass --run-id" % run_id)
    ensure_clean(args.scope, *(args.include or []), *(args.exclude or []))

    engagement = {
        "run_id": run_id,
        "created_at": now_iso(),
        "completed_at": None,
        "status": "in-progress",
        "scope": {
            "kind": args.scope_kind,
            "name": args.scope,
            "includes": args.include or [args.scope],
            "excludes": args.exclude or [],
            "suggested_from": args.suggested_from or [],
            "confirmed_by_user": bool(args.confirmed),
        },
        "mode": {"read_only": True, "active_checks": bool(args.active_checks)},
        "report": {"channel": args.channel, "artifact_url": None, "language": args.language},
        "limits": {"inner_loop_passes": args.passes, "calls_per_minute": 60},
        "domains": [],
        "stages_done": [],
        "inner_loop": {"passes_run": 0, "ended_by": None},
    }
    errors = _schema.validate(engagement, _schema.load_schema("engagement.schema.json"))
    if errors:
        fail("cannot start the run:\n  " + "\n  ".join(errors))

    for folder in ("evidence", "stages", "report"):
        os.makedirs(os.path.join(run, folder))
    note = ensure_ignored(root)
    save_engagement(run, engagement)
    save_board(
        run,
        {"run_id": run_id, "nodes": [], "facts": [], "intents": [], "relations": [], "findings": [], "stages": {}, "coverage": []},
    )
    with open(os.path.join(run, "actions.log"), "w", encoding="utf-8") as handle:
        handle.write("# time\tclass\tstage\tcommand\tnote\n")
    with open(os.path.join(root, RUN_AREA, "current"), "w", encoding="utf-8") as handle:
        handle.write(relative + "\n")
    print(relative)
    sys.stderr.write("git: %s\n" % note)
    return 0


# ------------------------------------------------------------------ engagement

def parse_value(text):
    return _yamlite.loads("value: %s" % text)["value"]


def locate(data, dotted):
    keys = dotted.split(".")
    for key in keys[:-1]:
        if not isinstance(data.get(key), dict):
            fail("no such setting: %s" % dotted)
        data = data[key]
    return data, keys[-1]


def cmd_engagement(args):
    run = require_run(args.run)
    with locked(run):
        engagement = load_engagement(run)
        if args.action == "show":
            sys.stdout.write(_yamlite.dumps(engagement))
            return 0
        if not args.key or args.value is None:
            fail("usage: engagement %s KEY VALUE" % args.action)
        ensure_clean(args.value)
        holder, key = locate(engagement, args.key)
        try:
            value = parse_value(args.value)
        except _yamlite.YamlError:
            value = args.value
        if args.action == "add":
            current = holder.get(key)
            if not isinstance(current, list):
                fail("%s is not a list" % args.key)
            if value not in current:
                current.append(value)
        else:
            holder[key] = value
        save_engagement(run, engagement)
    return 0


def cmd_stage_done(args):
    run = require_run(args.run)
    with locked(run):
        engagement = load_engagement(run)
        done = sorted(set(engagement.get("stages_done") or []) | {args.stage})
        engagement["stages_done"] = done
        if args.stage == 10:
            engagement["status"] = "complete"
            engagement["completed_at"] = now_iso()
        save_engagement(run, engagement)
    print("stages done: %s" % ", ".join(str(stage) for stage in done))
    return 0


# ----------------------------------------------------------------------- nodes

def cmd_add_node(args):
    run = require_run(args.run)
    attributes = {}
    for pair in args.attr or []:
        if "=" not in pair:
            fail("--attr takes key=value, got %r" % pair)
        key, value = pair.split("=", 1)
        attributes[key] = value
    ensure_clean(args.name, args.environment_basis, *attributes.values())
    with locked(run):
        board = load_board(run)
        for node in board["nodes"]:
            if (node["kind"], node["name"], node.get("domain")) == (args.kind, args.name, args.domain):
                print(node["id"])
                return 0
        node = {"id": next_id(board["nodes"], "N"), "kind": args.kind, "name": args.name}
        if args.domain:
            node["domain"] = args.domain
        node["environment"] = args.environment
        if args.environment_basis:
            node["environment_basis"] = args.environment_basis
        node["crown_jewel"] = bool(args.crown_jewel)
        node["internet_facing"] = bool(args.internet_facing)
        node["in_scope"] = not args.out_of_scope
        if attributes:
            node["attributes"] = attributes
        check_item("nodes", node)
        board["nodes"].append(node)
        save_board(run, board)
    print(node["id"])
    return 0


# ----------------------------------------------------------------------- facts

def cmd_add_fact(args):
    run = require_run(args.run)
    ensure_clean(args.statement)
    status = args.status or ("confirmed" if args.evidence else "to-validate")
    if status == "confirmed" and not args.evidence:
        fail("a confirmed fact needs --evidence: the file in the run folder that proves it")
    if args.evidence:
        evidence = os.path.normpath(os.path.join(run, args.evidence))
        if not evidence.startswith(run + os.sep) or not os.path.isfile(evidence):
            fail("evidence must be a file inside the run folder: %s" % args.evidence)
        if redact.check([evidence], out=sys.stderr):
            fail("the evidence file still holds secret-like values; pass it through redact.py first")
    with locked(run):
        board = load_board(run)
        about = split_list(args.about)
        require_ids(about, board["nodes"], "node")
        for fact in board["facts"]:
            same = (fact["statement"], fact["stage"], fact.get("domain")) == (args.statement, args.stage, args.domain)
            if same and fact["status"] != "superseded":
                print(fact["id"])
                return 0
        fact = {"id": next_id(board["facts"], "K"), "statement": args.statement, "stage": args.stage}
        if args.loop_pass:
            fact["pass"] = args.loop_pass
        if args.domain:
            fact["domain"] = args.domain
        if about:
            fact["about"] = about
        fact["status"] = status
        if args.evidence:
            fact["evidence"] = args.evidence
        if args.action:
            fact["action"] = args.action
        if args.supersedes:
            require_ids([args.supersedes], board["facts"], "fact")
            fact["supersedes"] = args.supersedes
            for old in board["facts"]:
                if old["id"] == args.supersedes:
                    old["status"] = "superseded"
        fact["recorded_at"] = now_iso()
        check_item("facts", fact)
        board["facts"].append(fact)
        save_board(run, board)
    print(fact["id"])
    return 0


# --------------------------------------------------------------------- intents

def cmd_add_intent(args):
    run = require_run(args.run)
    ensure_clean(args.question)
    with locked(run):
        board = load_board(run)
        for intent in board["intents"]:
            if intent["question"] == args.question and intent["status"] == "open":
                print(intent["id"])
                return 0
        intent = {"id": next_id(board["intents"], "I"), "question": args.question}
        if args.origin:
            require_ids([args.origin], board["facts"], "fact")
            intent["origin"] = args.origin
        if args.for_stage is not None:
            intent["for_stage"] = args.for_stage
        if args.domain:
            intent["domain"] = args.domain
        intent["status"] = "open"
        check_item("intents", intent)
        board["intents"].append(intent)
        save_board(run, board)
    print(intent["id"])
    return 0


def cmd_next_intent(args):
    run = require_run(args.run)
    board = load_board(run)
    candidates = [
        intent
        for intent in board["intents"]
        if intent["status"] == "open"
        and (args.domain is None or intent.get("domain") == args.domain)
        and (args.stage is None or intent.get("for_stage") == args.stage)
    ]
    if not candidates:
        sys.stderr.write("no open intent matches\n")
        return 3
    candidates.sort(key=lambda intent: (intent.get("for_stage", 99), intent["id"]))
    print(json.dumps(candidates[0], indent=2, ensure_ascii=False))
    return 0


def cmd_resolve_intent(args):
    run = require_run(args.run)
    if bool(args.fact) == bool(args.drop):
        fail("give exactly one of --with FACT or --drop REASON")
    ensure_clean(args.drop)
    with locked(run):
        board = load_board(run)
        require_ids([args.intent], board["intents"], "intent")
        for intent in board["intents"]:
            if intent["id"] != args.intent:
                continue
            if args.fact:
                require_ids([args.fact], board["facts"], "fact")
                intent["status"] = "answered"
                intent["answered_by"] = args.fact
            else:
                intent["status"] = "dropped"
                intent["dropped_because"] = args.drop
            check_item("intents", intent)
        save_board(run, board)
    print(args.intent)
    return 0


# ------------------------------------------------------------------- relations

def cmd_link(args):
    run = require_run(args.run)
    ensure_clean(args.condition)
    with locked(run):
        board = load_board(run)
        require_ids([args.source, args.target], board["nodes"], "node")
        require_ids([args.fact], board["facts"], "fact")
        relation = {"from": args.source, "rel": args.rel, "to": args.target, "fact": args.fact}
        if args.condition:
            relation["condition"] = args.condition
        check_item("relations", relation)
        if relation not in board["relations"]:
            board["relations"].append(relation)
            save_board(run, board)
    print("%s %s %s" % (args.source, args.rel, args.target))
    return 0


# -------------------------------------------------------------------- findings

def cmd_add_finding(args):
    run = require_run(args.run)
    ensure_clean(args.title, args.fix, args.interim, args.condition, args.gain, args.to_confirm, args.rule)
    with locked(run):
        board = load_board(run)
        facts = split_list(args.facts)
        require_ids(facts, board["facts"], "fact")
        for finding in board["findings"]:
            if finding["title"] == args.title and finding["stage"] == args.stage:
                print(finding["id"])
                return 0
        statuses = {fact["status"] for fact in board["facts"] if fact["id"] in facts}
        evidence = args.evidence or ("confirmed" if statuses == {"confirmed"} else "to-validate")
        if evidence == "confirmed" and statuses != {"confirmed"}:
            fail("a confirmed finding must rest only on confirmed facts")
        finding = {"id": next_id(board["findings"], "F"), "title": args.title, "stage": args.stage}
        if args.domain:
            finding["domain"] = args.domain
        if args.environment:
            finding["environment"] = args.environment
        finding["priority"] = args.priority
        finding["evidence"] = evidence
        if args.to_confirm:
            finding["to_confirm"] = args.to_confirm
        finding.update({"entry": args.entry, "reach": args.reach, "impact": args.impact, "visibility": args.visibility})
        if args.rule:
            finding["rule"] = args.rule
        if args.modifier:
            finding["modifiers"] = sorted(set(args.modifier))
        finding["facts"] = facts
        finding["fix"] = {"summary": args.fix, "layer": args.layer}
        if args.interim:
            finding["fix"]["interim"] = args.interim
        finding["exploit"] = {"condition": args.condition, "gain": args.gain}
        if args.leads_to is not None:
            finding["exploit"]["leads_to_stage"] = args.leads_to
        if args.attack:
            finding["attack"] = {"primary": args.attack}
            if args.attack_name:
                finding["attack"]["name"] = args.attack_name
        finding["created_at"] = now_iso()
        errors = _schema.validate(finding, _schema.load_schema("finding.schema.json"))
        if errors:
            fail("this finding is not valid:\n  " + "\n  ".join(errors))
        board["findings"].append(finding)
        save_board(run, board)
    print(finding["id"])
    return 0


# ------------------------------------------------------- notes, coverage, log

def cmd_stage_note(args):
    run = require_run(args.run)
    ensure_clean(args.covered, args.next, args.visibility, *(args.gap or []))
    with locked(run):
        board = load_board(run)
        note = board["stages"].setdefault(str(args.stage), {})
        if args.covered:
            note["covered"] = args.covered
        if args.gap:
            note["gaps"] = list(note.get("gaps", [])) + [gap for gap in args.gap if gap not in note.get("gaps", [])]
        if args.next:
            note["next"] = args.next
        if args.visibility:
            note["visibility"] = args.visibility
        save_board(run, board)
    print("stage %d noted" % args.stage)
    return 0


def cmd_coverage(args):
    run = require_run(args.run)
    ensure_clean(args.part, args.note)
    with locked(run):
        board = load_board(run)
        entry = {"part": args.part, "seen": args.seen}
        if args.note:
            entry["note"] = args.note
        if args.domain:
            entry["domain"] = args.domain
        board["coverage"] = [item for item in board["coverage"] if item["part"] != args.part] + [entry]
        save_board(run, board)
    print("coverage: %s = %s" % (args.part, args.seen))
    return 0


def cmd_log(args):
    run = require_run(args.run)
    log_action(run, args.klass, args.stage, args.command, args.note or "")
    return 0


# ------------------------------------------------------------- list and export

def _line(collection, item):
    if collection == "nodes":
        flags = "".join(["*" if item.get("crown_jewel") else "", "!" if item.get("internet_facing") else ""])
        return "%s  %-13s %-22s %-14s %-2s %s" % (
            item["id"], item["kind"], item.get("domain", "-"), item.get("environment", "unknown"), flags, item["name"]
        )
    if collection == "facts":
        return "%s  stage %d  %-12s %-11s %s" % (
            item["id"], item["stage"], item.get("domain", "-"), item["status"], item["statement"]
        )
    if collection == "intents":
        return "%s  -> stage %-2s %-9s %s" % (item["id"], item.get("for_stage", "?"), item["status"], item["question"])
    if collection == "relations":
        return "%s %s %s  (%s)" % (item["from"], item["rel"], item["to"], item["fact"])
    return "%s  %s  stage %d  %-11s %s" % (item["id"], item["priority"], item["stage"], item["evidence"], item["title"])


def cmd_list(args):
    run = require_run(args.run)
    board = load_board(run)
    items = board[args.collection]
    if args.stage is not None:
        items = [item for item in items if item.get("stage", item.get("for_stage")) == args.stage]
    if args.domain:
        items = [item for item in items if item.get("domain") == args.domain]
    if args.json:
        print(json.dumps(items, indent=2, ensure_ascii=False))
    else:
        for item in items:
            print(_line(args.collection, item))
        if args.collection == "nodes" and items:
            sys.stderr.write("(* crown jewel, ! internet-facing)\n")
    return 0


def cmd_export(args):
    run = require_run(args.run)
    board = load_board(run)
    if args.format == "json":
        print(json.dumps(board, indent=2, ensure_ascii=False))
        return 0
    target = os.path.join(run, "architecture.json")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "run_id": board["run_id"],
                "generated_at": now_iso(),
                "nodes": board["nodes"],
                "relations": board["relations"],
                "coverage": board["coverage"],
            },
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")
    print(os.path.relpath(target))
    return 0


def problems(run):
    """Everything wrong with the run's files. An empty list means the run is consistent."""
    found = []
    board = load_board(run)
    found.extend(_schema.validate(board, _schema.load_schema("blackboard.schema.json")))
    found.extend(
        "engagement" + error[1:]
        for error in _schema.validate(load_engagement(run), _schema.load_schema("engagement.schema.json"))
    )
    nodes, facts = ids(board["nodes"]), ids(board["facts"])
    for fact in board["facts"]:
        for node in fact.get("about", []):
            if node not in nodes:
                found.append("%s refers to the unknown node %s" % (fact["id"], node))
        evidence = fact.get("evidence")
        if evidence and not os.path.isfile(os.path.join(run, evidence)):
            found.append("%s points to missing evidence %s" % (fact["id"], evidence))
    for relation in board["relations"]:
        for end in (relation["from"], relation["to"]):
            if end not in nodes:
                found.append("a relation refers to the unknown node %s" % end)
        if relation["fact"] not in facts:
            found.append("a relation rests on the unknown fact %s" % relation["fact"])
    for finding in board["findings"]:
        for fact in finding["facts"]:
            if fact not in facts:
                found.append("%s rests on the unknown fact %s" % (finding["id"], fact))
    for intent in board["intents"]:
        for key in ("origin", "answered_by"):
            if intent.get(key) and intent[key] not in facts:
                found.append("%s refers to the unknown fact %s" % (intent["id"], intent[key]))
    return found


def cmd_validate(args):
    run = require_run(args.run)
    found = problems(run)
    for problem in found:
        print(problem)
    print("blackboard: %s" % ("%d problem(s)" % len(found) if found else "consistent"))
    return 1 if found else 0


def cmd_status(args):
    run = require_run(args.run)
    board = load_board(run)
    engagement = load_engagement(run)
    by_priority = {"P0": 0, "P1": 0, "P2": 0}
    for finding in board["findings"]:
        if finding["evidence"] != "dropped":
            by_priority[finding["priority"]] += 1
    scope = engagement["scope"]
    print("run:       %s (%s)" % (engagement["run_id"], engagement["status"]))
    print("scope:     %s: %s" % (scope["kind"], scope["name"]))
    print("report:    %s, language %s" % (engagement["report"]["channel"], engagement["report"]["language"]))
    print("stages:    done %s" % (", ".join(str(stage) for stage in engagement["stages_done"]) or "none"))
    print("nodes:     %d (%d crown jewels)" % (len(board["nodes"]), sum(1 for n in board["nodes"] if n.get("crown_jewel"))))
    print("facts:     %d" % sum(1 for fact in board["facts"] if fact["status"] != "superseded"))
    print("intents:   %d open" % sum(1 for intent in board["intents"] if intent["status"] == "open"))
    print("findings:  P0 %(P0)d, P1 %(P1)d, P2 %(P2)d" % by_priority)
    return 0


# ------------------------------------------------------------------------- cli

def build_parser():
    parser = argparse.ArgumentParser(description="Create a run and read or write its blackboard.")
    sub = parser.add_subparsers(dest="command")

    def add(name, function, help_text):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--run", help="run folder; default is the current run")
        command.set_defaults(function=function)
        return command

    init = sub.add_parser("init", help="create a run")
    init.set_defaults(function=cmd_init)
    init.add_argument("--scope-kind", required=True, choices=["repository", "team", "company"])
    init.add_argument("--scope", required=True, help="how the user names the scope")
    init.add_argument("--include", action="append", help="something in scope; repeat as needed")
    init.add_argument("--exclude", action="append", help="something ruled out; repeat as needed")
    init.add_argument("--suggested-from", action="append", help="a context signal behind the suggestion")
    init.add_argument("--confirmed", action="store_true", help="the user confirmed this scope")
    init.add_argument("--channel", choices=["artifact", "files"], default="files")
    init.add_argument("--language", default="en")
    init.add_argument("--active-checks", action="store_true", help="the user opted in to active checks")
    init.add_argument("--passes", type=int, default=3, help="limit of inner-loop passes")
    init.add_argument("--root", default=".", help="project folder that will hold .security-scan/")
    init.add_argument("--run-id", help="YYYYMMDD-HHMM; default is now")

    add("status", cmd_status, "summarise the run")
    add("validate", cmd_validate, "check the run's files for consistency")

    engagement = add("engagement", cmd_engagement, "show or change engagement.yaml")
    engagement.add_argument("action", choices=["show", "set", "add"])
    engagement.add_argument("key", nargs="?")
    engagement.add_argument("value", nargs="?")

    done = add("stage-done", cmd_stage_done, "mark a stage as finished")
    done.add_argument("stage", type=int, choices=range(0, 11))

    node = add("add-node", cmd_add_node, "add something that exists in the scope")
    node.add_argument("--kind", required=True, choices=item_schema("nodes")["properties"]["kind"]["enum"])
    node.add_argument("--name", required=True)
    node.add_argument("--domain")
    node.add_argument("--environment", choices=["production", "non-production", "unknown"], default="unknown")
    node.add_argument("--environment-basis", help="what the classification rests on")
    node.add_argument("--crown-jewel", action="store_true")
    node.add_argument("--internet-facing", action="store_true")
    node.add_argument("--out-of-scope", action="store_true")
    node.add_argument("--attr", action="append", help="key=value; never a secret value")

    fact = add("add-fact", cmd_add_fact, "record something observed")
    fact.add_argument("--stage", type=int, required=True, choices=range(0, 10))
    fact.add_argument("--statement", required=True)
    fact.add_argument("--domain")
    fact.add_argument("--about", help="node ids, comma separated")
    fact.add_argument("--evidence", help="path inside the run folder")
    fact.add_argument("--status", choices=["confirmed", "to-validate"])
    fact.add_argument("--action", help="the actions.log entry that produced the evidence")
    fact.add_argument("--pass", dest="loop_pass", type=int, help="inner-loop pass, for stages 3 to 6")
    fact.add_argument("--supersedes", help="the fact this one corrects")

    intent = add("add-intent", cmd_add_intent, "queue a question for a later stage")
    intent.add_argument("--question", required=True)
    intent.add_argument("--from", dest="origin", help="the fact that raised it")
    intent.add_argument("--for-stage", type=int, choices=range(1, 10))
    intent.add_argument("--domain")

    following = add("next-intent", cmd_next_intent, "print the next open intent")
    following.add_argument("--domain")
    following.add_argument("--stage", type=int)

    resolve = add("resolve-intent", cmd_resolve_intent, "answer or drop an intent")
    resolve.add_argument("intent")
    resolve.add_argument("--with", dest="fact", help="the fact that answers it")
    resolve.add_argument("--drop", help="why it is not pursued")

    link = add("link", cmd_link, "relate two nodes")
    link.add_argument("--from", dest="source", required=True)
    link.add_argument("--rel", required=True, choices=item_schema("relations")["properties"]["rel"]["enum"])
    link.add_argument("--to", dest="target", required=True)
    link.add_argument("--fact", required=True, help="the fact the relation rests on")
    link.add_argument("--condition", help="what narrows it: network, second factor, approval")

    finding_schema = _schema.load_schema("finding.schema.json")["properties"]
    finding = add("add-finding", cmd_add_finding, "record a weakness")
    finding.add_argument("--title", required=True)
    finding.add_argument("--stage", type=int, required=True, choices=range(0, 10))
    finding.add_argument("--facts", required=True, help="fact ids, comma separated")
    finding.add_argument("--priority", required=True, choices=finding_schema["priority"]["enum"])
    finding.add_argument("--entry", required=True, choices=finding_schema["entry"]["enum"])
    finding.add_argument("--reach", required=True, choices=finding_schema["reach"]["enum"])
    finding.add_argument("--impact", required=True, choices=finding_schema["impact"]["enum"])
    finding.add_argument("--visibility", required=True, choices=finding_schema["visibility"]["enum"])
    finding.add_argument("--fix", required=True, help="the change to make")
    finding.add_argument("--layer", type=int, required=True, choices=range(1, 6), help="defense layer")
    finding.add_argument("--condition", required=True, help="what could be exploited")
    finding.add_argument("--gain", required=True, help="what an attacker would gain")
    finding.add_argument("--leads-to", type=int, choices=range(1, 9), help="the stage it leads to")
    finding.add_argument("--evidence", choices=["confirmed", "to-validate"])
    finding.add_argument("--to-confirm", help="for to-validate findings: what would confirm it")
    finding.add_argument("--rule", help="the grading criterion, for example P0.4")
    finding.add_argument("--modifier", action="append", choices=["silent", "isolated", "choke-point"])
    finding.add_argument("--interim", help="a mitigation to apply until the full fix")
    finding.add_argument("--domain")
    finding.add_argument("--environment", choices=["production", "non-production", "unknown"])
    finding.add_argument("--attack", help="ATT&CK technique id, for example T1552.001")
    finding.add_argument("--attack-name")

    note = add("stage-note", cmd_stage_note, "record what a stage covered")
    note.add_argument("--stage", type=int, required=True, choices=range(0, 11))
    note.add_argument("--covered")
    note.add_argument("--gap", action="append", help="something not covered, and why")
    note.add_argument("--next", help="what the next stage will look at")
    note.add_argument("--visibility", help="whether the stage's activity would be logged and alerted")

    coverage = add("coverage", cmd_coverage, "record how much of a part of the scope was seen")
    coverage.add_argument("--part", required=True)
    coverage.add_argument("--seen", required=True, choices=["yes", "partly", "no"])
    coverage.add_argument("--note", help="why not, and what access would show it")
    coverage.add_argument("--domain")

    log = add("log", cmd_log, "append an action to actions.log")
    log.add_argument("--class", dest="klass", required=True, choices=["read", "active"])
    log.add_argument("--stage", type=int, required=True)
    log.add_argument("--command", required=True)
    log.add_argument("--note")

    listing = add("list", cmd_list, "list entries")
    listing.add_argument("collection", choices=["nodes", "facts", "intents", "relations", "findings"])
    listing.add_argument("--stage", type=int)
    listing.add_argument("--domain")
    listing.add_argument("--json", action="store_true")

    export = add("export", cmd_export, "print the blackboard, or write architecture.json")
    export.add_argument("--format", choices=["json", "architecture"], default="json")
    return parser


def main(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "function", None):
        parser.print_help()
        return 1
    return args.function(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
