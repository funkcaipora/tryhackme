#!/usr/bin/env python3
"""Render the stage report, the artifact page and the architecture map.

Turns the blackboard into what the user reads.

Usage:
    render_report.py --stage 0            stages/00-scope-and-architecture.md, the three-part stage report
    render_report.py --live               live-report.html, the page published as the run's artifact
    render_report.py --architecture       architecture.json and architecture.md, with a diagram
    render_report.py --final              the consolidated set (not implemented yet, build step 4)

Every mode works on the current run, or on the folder given with --run.
Reports are written in the language set in engagement.yaml (report.language),
using the labels in assets/i18n/. Languages without a label file fall back to
English.

Inputs:  blackboard.json, engagement.yaml, assets/templates/live-report.html, assets/i18n/
Outputs: stages/NN-<stage>.md, live-report.html, architecture.json, architecture.md
Safety:  publishes nothing; publishing is done by the agent with the harness's
         artifact tool. Refuses to keep a file in which redact.py still finds a
         secret-like value.
"""
import argparse
import html
import json
import os
import re
import sys
import time

import _yamlite
import redact
from _common import SKILL_DIR, STAGES, fail, now_iso, require_run

TEMPLATE = os.path.join(SKILL_DIR, "assets", "templates", "live-report.html")
I18N = os.path.join(SKILL_DIR, "assets", "i18n")
PRIORITIES = ["P0", "P1", "P2"]
NODE_KINDS = [
    "identity", "credential", "compute", "data-store", "network", "control-plane",
    "pipeline", "repository", "saas-tenant", "ai-service", "external",
]
MAX_FACTS = 12
MAX_DIAGRAM_NODES = 40


# ------------------------------------------------------------------- loading

def load_labels(language):
    with open(os.path.join(I18N, "en.json"), "r", encoding="utf-8") as handle:
        labels = json.load(handle)
    wanted = (language or "en").lower()
    names = sorted(name for name in os.listdir(I18N) if name.endswith(".json"))
    chosen = next((name for name in names if name[:-5].lower() == wanted), None)
    if chosen is None:
        chosen = next((name for name in names if name[:-5].split("-")[0].lower() == wanted.split("-")[0]), None)
    if chosen and chosen != "en.json":
        with open(os.path.join(I18N, chosen), "r", encoding="utf-8") as handle:
            labels.update(json.load(handle))
    return labels


def load_run(run):
    with open(os.path.join(run, "blackboard.json"), "r", encoding="utf-8") as handle:
        board = json.load(handle)
    board.setdefault("stages", {})
    board.setdefault("coverage", [])
    engagement = _yamlite.load(os.path.join(run, "engagement.yaml"))
    return board, engagement


def live_findings(board, stage=None):
    found = [
        finding for finding in board["findings"]
        if finding["evidence"] != "dropped" and (stage is None or finding["stage"] == stage)
    ]
    return sorted(found, key=lambda finding: (PRIORITIES.index(finding["priority"]), finding["id"]))


def count_by_priority(findings):
    counts = {priority: {"all": 0, "to_validate": 0} for priority in PRIORITIES}
    for finding in findings:
        counts[finding["priority"]]["all"] += 1
        if finding["evidence"] == "to-validate":
            counts[finding["priority"]]["to_validate"] += 1
    return counts


def write_checked(path, text):
    """Write a report, then make sure no secret-like value is in it."""
    if redact.scan(text):
        fail("%s was not written: redact.py still finds a secret-like value in it" % os.path.basename(path))
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# ------------------------------------------------------------- the stage view

def stage_view(board, stage, labels):
    """Everything a stage report shows, as plain data shared by the HTML and Markdown renderers."""
    facts_by_id = {fact["id"]: fact for fact in board["facts"]}
    findings = live_findings(board, stage)
    used = {fact_id for finding in findings for fact_id in finding["facts"]}
    stage_facts = [fact for fact in board["facts"] if fact["stage"] == stage and fact["status"] != "superseded"]
    stage_fact_ids = {fact["id"] for fact in stage_facts}
    other_facts = [fact for fact in stage_facts if fact["id"] not in used]
    intents = [
        intent for intent in board["intents"]
        if intent["status"] != "dropped"
        and (intent.get("origin") in stage_fact_ids or (not intent.get("origin") and intent.get("for_stage") == stage + 1))
    ]

    def evidence_label(status):
        return labels["confirmed"] if status == "confirmed" else labels["to_validate"]

    found, fixes, exploits = [], [], []
    for finding in findings:
        where = [finding.get("domain"), labels["environment_value"].get(finding.get("environment") or "")]
        statements = [facts_by_id[fact_id]["statement"] for fact_id in finding["facts"] if fact_id in facts_by_id]
        found.append({
            "chip": finding["priority"],
            "chip_class": finding["priority"].lower(),
            "title": "%s · %s" % (finding["id"], finding["title"]),
            "detail": " ".join(statements[:2]),
            "meta": " · ".join(
                part for part in [evidence_label(finding["evidence"])] + where + [labels["visibility_value"][finding["visibility"]]] if part
            ),
            "finding": finding,
        })
        fix = finding["fix"]
        fixes.append({
            "chip": finding["priority"],
            "chip_class": finding["priority"].lower(),
            "title": fix["summary"],
            "detail": "%s: %s" % (labels["until_then"], fix["interim"]) if fix.get("interim") else "",
            "meta": "%s · %s %d: %s" % (finding["id"], labels["layer"], fix["layer"], labels["layer_names"][fix["layer"] - 1]),
            "finding": finding,
        })
        exploit = finding["exploit"]
        attack = finding.get("attack") or {}
        exploits.append({
            "chip": "→ %d" % exploit["leads_to_stage"] if exploit.get("leads_to_stage") else "→",
            "chip_class": "none",
            "title": exploit["condition"],
            "detail": "%s: %s" % (labels["gain"], exploit["gain"]),
            "meta": " ".join(part for part in [attack.get("primary"), attack.get("name")] if part),
            "finding": finding,
        })
    for fact in other_facts[:MAX_FACTS]:
        found.append({
            "chip": "·",
            "chip_class": "none",
            "title": fact["statement"],
            "detail": "",
            "meta": " · ".join(part for part in [evidence_label(fact["status"]), fact.get("domain"), fact.get("evidence")] if part),
        })
    if len(other_facts) > MAX_FACTS:
        found.append({"chip": "+", "chip_class": "none", "title": labels["more_facts"] % (len(other_facts) - MAX_FACTS), "detail": "", "meta": ""})
    for intent in intents:
        exploits.append({
            "chip": "→ %s" % intent["for_stage"] if intent.get("for_stage") else "→",
            "chip_class": "none",
            "title": intent["question"],
            "detail": "",
            "meta": labels["next_question"],
        })

    counts = count_by_priority(findings)
    note = board["stages"].get(str(stage), {})
    meta = ["%d P0 · %d P1 · %d P2" % tuple(counts[priority]["all"] for priority in PRIORITIES)]
    if note.get("visibility"):
        meta.append(note["visibility"])
    view = {
        "stage": stage,
        "name": labels["stage_names"][stage],
        "question": labels["stage_questions"][stage],
        "counts": counts,
        "meta": " · ".join(meta),
        "note": note,
        "found": found,
        "fixes": fixes,
        "exploits": exploits,
        "other_facts": other_facts,
    }
    if stage == 0:
        view["architecture"] = architecture_view(board, labels)
    return view


def architecture_view(board, labels):
    rows = []
    for kind in NODE_KINDS:
        nodes = [node for node in board["nodes"] if node["kind"] == kind and node.get("in_scope", True)]
        if not nodes:
            continue
        names = [node["name"] for node in nodes[:4]]
        if len(nodes) > 4:
            names.append("+%d" % (len(nodes) - 4))
        rows.append({"kind": labels["node_kind"][kind], "count": len(nodes), "examples": ", ".join(names)})
    jewels = []
    for node in board["nodes"]:
        if node.get("crown_jewel"):
            detail = [node.get("domain"), labels["environment_value"].get(node.get("environment", "unknown"))]
            jewels.append({"name": node["name"], "detail": " · ".join(part for part in detail if part)})
    coverage = [
        {"part": item["part"], "seen": labels["seen_value"][item["seen"]], "note": item.get("note", "")}
        for item in board["coverage"]
    ]
    return {"rows": rows, "jewels": jewels, "coverage": coverage}


# --------------------------------------------------------------------- HTML

def fill(text, values):
    """Replace {{NAME}} with the escaped value. Unknown names become empty."""
    def replace(match):
        value = values.get(match.group(1), "")
        return html.escape(str(value), quote=True)

    return re.sub(r"\{\{([A-Za-z0-9_.]+)\}\}", replace, text)


def take_block(text, name):
    match = re.search(r"<!-- BEGIN:%s -->(.*?)<!-- END:%s -->" % (name, name), text, re.S)
    if not match:
        fail("the page template has no %s block" % name)
    return match.group(1)


def put_block(text, name, content):
    return re.sub(r"<!-- BEGIN:%s -->.*?<!-- END:%s -->" % (name, name), lambda match: content, text, count=1, flags=re.S)


def render_items(shell, name, items, empty_title):
    template = take_block(shell, name)
    if not items:
        items = [{"chip": "–", "chip_class": "none", "title": empty_title, "detail": "", "meta": ""}]
    rendered = "".join(
        fill(template, {
            "CHIP": item["chip"], "CHIP_CLASS": item["chip_class"],
            "TITLE": item["title"], "DETAIL": item["detail"], "META": item["meta"],
        })
        for item in items
    )
    return rendered


def render_stage_html(stage_template, view, label_values, labels):
    # Fill the shell first, with every repeated block swapped for a marker, then
    # put the rendered blocks back. Data is never run through fill() twice, so
    # text such as "${{ secrets.X }}" in a finding survives.
    pieces = {}
    shell = stage_template
    if "architecture" in view:
        arch = take_block(shell, "ARCH")
        architecture = view["architecture"]
        rows = "".join(fill(take_block(arch, "ARCH_ROW"), {"KIND": row["kind"], "COUNT": row["count"], "EXAMPLES": row["examples"]}) for row in architecture["rows"])
        jewels = "".join(fill(take_block(arch, "JEWEL"), {"NAME": jewel["name"], "DETAIL": jewel["detail"]}) for jewel in architecture["jewels"])
        if not jewels:
            jewels = fill(take_block(arch, "JEWEL"), {"NAME": labels["no_crown_jewels"], "DETAIL": ""})
        coverage = "".join(fill(take_block(arch, "COVERAGE_ROW"), {"PART": row["part"], "SEEN": row["seen"], "NOTE": row["note"]}) for row in architecture["coverage"])
        arch = put_block(put_block(put_block(arch, "ARCH_ROW", "\x00rows\x00"), "JEWEL", "\x00jewels\x00"), "COVERAGE_ROW", "\x00coverage\x00")
        arch = fill(arch, label_values).replace("\x00rows\x00", rows).replace("\x00jewels\x00", jewels).replace("\x00coverage\x00", coverage)
        pieces["\x00arch\x00"] = arch
        shell = put_block(shell, "ARCH", "\x00arch\x00")
    else:
        shell = put_block(shell, "ARCH", "")
    for name, items, empty in (
        ("FOUND_ITEM", view["found"], labels["nothing_found"]),
        ("FIX_ITEM", view["fixes"], labels["nothing_to_fix"]),
        ("EXPLOIT_ITEM", view["exploits"], labels["nothing_exploitable"]),
    ):
        marker = "\x00%s\x00" % name
        pieces[marker] = render_items(shell, name, items, empty)
        shell = put_block(shell, name, marker)
    values = dict(label_values)
    values.update({"N": view["stage"], "STAGE_NAME": view["name"], "STAGE_QUESTION": view["question"], "STAGE_META": view["meta"]})
    shell = fill(shell, values)
    for marker, content in pieces.items():
        shell = shell.replace(marker, content)
    return shell


def scope_description(engagement, labels):
    scope = engagement["scope"]
    text = "%s. %s: %s." % (labels["scope_kind"][scope["kind"]], labels["in_scope"], ", ".join(scope["includes"]))
    if scope.get("excludes"):
        text += " %s: %s." % (labels["out_of_scope"], ", ".join(scope["excludes"]))
    return text


def render_live(run, board, engagement, labels):
    with open(TEMPLATE, "r", encoding="utf-8") as handle:
        template = handle.read()
    template = re.sub(r"<!--\s*TEMPLATE NOTES.*?-->\s*", "", template, count=1, flags=re.S)
    label_values = {"t." + key: value for key, value in labels.items() if isinstance(value, str)}
    done = sorted(stage for stage in engagement.get("stages_done") or [] if stage in STAGES)
    current = next((stage for stage in sorted(STAGES) if stage not in done), None)

    stage_template = take_block(template, "STAGE")
    stages_html = "".join(
        render_stage_html(stage_template, stage_view(board, stage, labels), label_values, labels)
        for stage in done if stage <= 9
    )
    progress_template = take_block(template, "PROGRESS_ITEM")
    progress_html = "".join(
        fill(progress_template, {
            "STATE": "done" if stage in done else ("current" if stage == current else "todo"),
            "N": stage,
            "NAME": labels["stage_names"][stage],
        })
        for stage in sorted(STAGES)
    )

    findings = live_findings(board)
    counts = count_by_priority(findings)
    gaps = sum(1 for item in board["coverage"] if item["seen"] != "yes")
    values = dict(label_values)
    values.update({
        "SCOPE_NAME": engagement["scope"]["name"],
        "LANG": engagement["report"]["language"],
        "RUN_ID": engagement["run_id"],
        "UPDATED_AT": time.strftime("%Y-%m-%d %H:%M"),
        "SCOPE_DESCRIPTION": scope_description(engagement, labels),
        "MOST_URGENT_FIX": findings[0]["fix"]["summary"] if findings else labels["no_findings_yet"],
        "COVERAGE_NOTE": (labels["gaps_note"] % gaps) if gaps else (labels["full_coverage_note"] if board["coverage"] else ""),
    })
    for priority in PRIORITIES:
        values["COUNT_%s" % priority] = counts[priority]["all"]
        values["COUNT_%s_TO_VALIDATE" % priority] = counts[priority]["to_validate"]

    page = put_block(template, "STAGE", "\x00stages\x00")
    page = put_block(page, "PROGRESS_ITEM", "\x00progress\x00")
    page = put_block(page, "CONSOLIDATED", "")
    page = fill(page, values).replace("\x00stages\x00", stages_html).replace("\x00progress\x00", progress_html)
    page = re.sub(r'<p class="item-(?:detail|meta)"></p>', "", page)
    page = re.sub(r'\s*<p class="muted"></p>', "", page)
    return write_checked(os.path.join(run, "live-report.html"), page)


# ----------------------------------------------------------------- Markdown

def cell(text):
    return " ".join(str(text).split()).replace("|", "\\|")


def render_stage_markdown(run, board, engagement, labels, stage):
    view = stage_view(board, stage, labels)
    counts = view["counts"]
    note = view["note"]
    lines = [
        "# %s %d: %s" % (labels["stage"], stage, view["name"]),
        "",
        "**%s:** %s" % (labels["question"], view["question"]),
        "",
        "%s `%s` · %s: %s · %s" % (labels["run"], engagement["run_id"], labels["scope"], engagement["scope"]["name"], time.strftime("%Y-%m-%d")),
        "",
        "| P0 | P1 | P2 | %s |" % labels["to_validate"],
        "|---|---|---|---|",
        "| %d | %d | %d | %d |" % (
            counts["P0"]["all"], counts["P1"]["all"], counts["P2"]["all"],
            sum(counts[priority]["to_validate"] for priority in PRIORITIES),
        ),
        "",
    ]
    if note.get("covered"):
        lines += ["**%s:** %s" % (labels["covered"], note["covered"]), ""]
    if note.get("gaps"):
        lines += ["**%s:**" % labels["not_covered"], ""] + ["- %s" % gap for gap in note["gaps"]] + [""]
    if note.get("visibility"):
        lines += [note["visibility"], ""]

    if "architecture" in view:
        architecture = view["architecture"]
        lines += ["## %s" % labels["architecture"], "", "| %s | %s | %s |" % (labels["kind"], labels["count"], labels["examples"]), "|---|---|---|"]
        lines += ["| %s | %d | %s |" % (cell(row["kind"]), row["count"], cell(row["examples"])) for row in architecture["rows"]]
        lines += ["", "**%s**" % labels["crown_jewels"], ""]
        lines += ["- %s (%s)" % (jewel["name"], jewel["detail"]) for jewel in architecture["jewels"]] or ["- %s" % labels["no_crown_jewels"]]
        if architecture["coverage"]:
            lines += ["", "**%s**" % labels["coverage"], "", "| %s | %s | %s |" % (labels["part"], labels["seen"], labels["note"]), "|---|---|---|"]
            lines += ["| %s | %s | %s |" % (cell(row["part"]), cell(row["seen"]), cell(row["note"])) for row in architecture["coverage"]]
        lines.append("")

    lines += ["## 1. %s" % labels["found"], ""]
    findings = [item for item in view["found"] if "finding" in item]
    for item in findings:
        lines += ["### %s · %s" % (item["chip"], item["title"]), ""]
        if item["detail"]:
            lines += [item["detail"], ""]
        lines += ["- %s" % item["meta"], ""]
    if view["other_facts"]:
        if findings:
            lines += ["**%s**" % labels["other_facts"], ""]
        for fact in view["other_facts"]:
            suffix = " (`%s`)" % fact["evidence"] if fact.get("evidence") else ""
            lines.append("- %s%s" % (fact["statement"], suffix))
        lines.append("")
    if not view["found"]:
        lines += [labels["nothing_found"], ""]

    lines += ["## 2. %s" % labels["fix"], ""]
    if view["fixes"]:
        lines += ["| %s | %s | %s | %s | %s |" % (labels["priority"], labels["finding"], labels["fix_column"], labels["layer"].capitalize(), labels["until_then"]), "|---|---|---|---|---|"]
        for item in view["fixes"]:
            finding = item["finding"]
            layer = finding["fix"]["layer"]
            lines.append("| %s | %s | %s | %d: %s | %s |" % (
                finding["priority"], finding["id"], cell(finding["fix"]["summary"]), layer,
                cell(labels["layer_names"][layer - 1]), cell(finding["fix"].get("interim", "")),
            ))
        lines.append("")
    else:
        lines += [labels["nothing_to_fix"], ""]

    lines += ["## 3. %s" % labels["exploit"], ""]
    if view["exploits"]:
        lines += ["| %s | %s | %s | %s |" % (labels["condition"], labels["technique"], labels["what_attacker_gains"], labels["leads_to_column"]), "|---|---|---|---|"]
        for item in view["exploits"]:
            if "finding" in item:
                exploit = item["finding"]["exploit"]
                lines.append("| %s | %s | %s | %s |" % (cell(exploit["condition"]), cell(item["meta"]), cell(exploit["gain"]), cell(item["chip"])))
            else:
                lines.append("| %s | %s |  | %s |" % (cell(item["title"]), cell(item["meta"]), cell(item["chip"])))
        lines.append("")
    else:
        lines += [labels["nothing_exploitable"], ""]

    if note.get("next"):
        lines += ["## %s" % labels["next"], "", note["next"], ""]
    target = os.path.join(run, "stages", "%02d-%s.md" % (stage, STAGES[stage]))
    return write_checked(target, "\n".join(lines).rstrip() + "\n")


# ------------------------------------------------------------- architecture

def mermaid(board, labels):
    degree = {}
    for relation in board["relations"]:
        for end in (relation["from"], relation["to"]):
            degree[end] = degree.get(end, 0) + 1
    candidates = [
        node for node in board["nodes"]
        if node["id"] in degree or node.get("crown_jewel") or node.get("internet_facing")
    ] or list(board["nodes"])
    candidates.sort(key=lambda node: (-degree.get(node["id"], 0), node["id"]))
    shown = candidates[:MAX_DIAGRAM_NODES]
    shown_ids = {node["id"] for node in shown}

    def identifier(node_id):
        return node_id.replace("-", "")

    lines = ["flowchart LR"]
    if any(node.get("internet_facing") for node in shown):
        lines.append('  internet(("%s"))' % labels["internet"])
    for node in shown:
        label = re.sub(r"[\"`<>\[\]{}|]", " ", node["name"]).strip()[:48]
        shape = '[("%s")]' if node["kind"] == "data-store" else ('(["%s"])' if node["kind"] in ("identity", "credential") else '["%s"]')
        lines.append("  %s%s" % (identifier(node["id"]), shape % label))
        if node.get("internet_facing"):
            lines.append("  internet --> %s" % identifier(node["id"]))
    for relation in board["relations"]:
        if relation["from"] in shown_ids and relation["to"] in shown_ids:
            lines.append("  %s -- %s --> %s" % (identifier(relation["from"]), relation["rel"], identifier(relation["to"])))
    jewels = [identifier(node["id"]) for node in shown if node.get("crown_jewel")]
    if jewels:
        lines += ["  classDef jewel stroke-width:3px", "  class %s jewel" % ",".join(jewels)]
    return "\n".join(lines), len(shown), len(candidates)


def render_architecture(run, board, engagement, labels):
    data = {
        "run_id": board["run_id"],
        "generated_at": now_iso(),
        "scope": engagement["scope"],
        "nodes": board["nodes"],
        "relations": board["relations"],
        "coverage": board["coverage"],
    }
    write_checked(os.path.join(run, "architecture.json"), json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    scope = engagement["scope"]
    names = {node["id"]: node["name"] for node in board["nodes"]}
    diagram, shown, total = mermaid(board, labels)
    lines = [
        "# %s: %s" % (labels["architecture"], scope["name"]),
        "",
        "%s `%s` · %s · %s" % (labels["run"], engagement["run_id"], labels["scope_kind"][scope["kind"]], time.strftime("%Y-%m-%d")),
        "",
        "**%s:** %s" % (labels["in_scope"], ", ".join(scope["includes"])),
        "",
    ]
    if scope.get("excludes"):
        lines += ["**%s:** %s" % (labels["out_of_scope"], ", ".join(scope["excludes"])), ""]
    lines += ["## %s" % labels["diagram"], "", "```mermaid", diagram, "```", ""]
    if shown < total:
        lines += [labels["diagram_truncated"] % (shown, total), ""]
    for kind in NODE_KINDS:
        nodes = [node for node in board["nodes"] if node["kind"] == kind]
        if not nodes:
            continue
        lines += [
            "## %s" % labels["node_kind"][kind],
            "",
            "| %s | %s | %s | %s | %s | %s |" % (labels["name"], labels["domain"], labels["environment"], labels["based_on"], labels["internet_facing"], labels["crown_jewel"]),
            "|---|---|---|---|---|---|",
        ]
        for node in nodes:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                cell(node["name"]), cell(node.get("domain", "")),
                cell(labels["environment_value"].get(node.get("environment", "unknown"), "")),
                cell(node.get("environment_basis", "")),
                labels["yes"] if node.get("internet_facing") else labels["no"],
                labels["yes"] if node.get("crown_jewel") else labels["no"],
            ))
        lines.append("")
    if board["relations"]:
        lines += ["## %s" % labels["relations"], ""]
        for relation in board["relations"]:
            condition = " (%s)" % relation["condition"] if relation.get("condition") else ""
            lines.append("- %s **%s** %s%s" % (names.get(relation["from"], relation["from"]), relation["rel"], names.get(relation["to"], relation["to"]), condition))
        lines.append("")
    if board["coverage"]:
        lines += ["## %s" % labels["coverage"], "", "| %s | %s | %s |" % (labels["part"], labels["seen"], labels["note"]), "|---|---|---|"]
        lines += ["| %s | %s | %s |" % (cell(item["part"]), cell(labels["seen_value"][item["seen"]]), cell(item.get("note", ""))) for item in board["coverage"]]
        lines.append("")
    return write_checked(os.path.join(run, "architecture.md"), "\n".join(lines).rstrip() + "\n")


# ----------------------------------------------------------------------- cli

def main(argv):
    parser = argparse.ArgumentParser(description="Render the stage report, the artifact page and the architecture map.")
    parser.add_argument("--run", help="run folder; default is the current run")
    parser.add_argument("--stage", type=int, choices=range(0, 10), help="write the report of one stage as Markdown")
    parser.add_argument("--live", action="store_true", help="write live-report.html with every completed stage")
    parser.add_argument("--architecture", action="store_true", help="write architecture.json and architecture.md")
    parser.add_argument("--final", action="store_true", help="write the consolidated report (not implemented yet)")
    args = parser.parse_args(argv)

    if args.final:
        sys.stderr.write(
            "render_report.py --final: not implemented yet (build step 4). "
            "Do this step by hand following references/phases/10-consolidated-report.md.\n"
        )
        return 2
    if args.stage is None and not args.live and not args.architecture:
        parser.print_help()
        return 1

    run = require_run(args.run)
    board, engagement = load_run(run)
    labels = load_labels(engagement["report"]["language"])
    written = []
    if args.architecture:
        written.append(render_architecture(run, board, engagement, labels))
    if args.stage is not None:
        written.append(render_stage_markdown(run, board, engagement, labels, args.stage))
    if args.live:
        written.append(render_live(run, board, engagement, labels))
    for path in written:
        print(os.path.relpath(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
