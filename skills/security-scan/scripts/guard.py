#!/usr/bin/env python3
"""Classify a command before it runs.

Reads a shell command and answers with its action class:

    read         lists, describes, gets, simulates                      allowed
    active       leaves the machine or probes without changing anything allowed only when the run opted in
    collection   a read that takes a secret value or a copy of the data refused
    write        creates or changes something                           refused
    destructive  deletes or stops something                             refused
    unknown      not recognised                                         refused

The rules live in assets/command-allowlist.yaml and are an allowlist: a command
this script does not recognise is `unknown`, and unknown is refused. A pipeline
or a list of commands gets the class of its worst part. Command substitution,
subshells, here-documents and background jobs are refused, because what they
run cannot be seen from the outside; run the inner command by itself.

Usage:
    guard.py check "aws iam list-users"              prints the class; exit 0 only if allowed
    guard.py check --allow-active "curl -I https://own.example"
    guard.py check --json "kubectl get pods"         machine-readable verdict
    guard.py --self-test                             runs the built-in cases
    guard.py hook                                    reads a tool-call JSON on stdin (for a pre-tool hook)

Inputs:  the command text; assets/command-allowlist.yaml; the current run's
         engagement.yaml, for the active opt-in
Outputs: the class and the reason on stdout; exit code 0 allowed, 1 refused
Safety:  it never runs the command it classifies.
"""
import argparse
import fnmatch
import json
import os
import re
import shlex
import sys

import _yamlite

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST = os.path.normpath(os.path.join(HERE, "..", "assets", "command-allowlist.yaml"))
RUN_AREA = ".security-scan"

# From least to most serious. A pipeline takes the class of its worst part.
ORDER = ["read", "active", "unknown", "collection", "write", "destructive"]

ELEVATORS = {"sudo", "doas", "su"}
LAUNCHERS = {
    "sh", "bash", "zsh", "dash", "fish", "ksh", "eval", "source", ".", "exec", "xargs",
    "nohup", "watch", "node", "deno", "bun", "ruby", "php", "osascript", "make",
}
RULE_KEYWORDS = ("if-flag", "unless-flag", "if-flag-value")


def verdict(klass, reason, segment=""):
    return {"class": klass, "reason": reason, "segment": segment}


# ---------------------------------------------------------------- configuration

def parse_rule(text):
    parts = text.split()
    rule = {"text": text, "words": [], "if_flag": [], "unless_flag": [], "if_flag_value": []}
    index = 0
    while index < len(parts) and parts[index] not in RULE_KEYWORDS:
        rule["words"].append(parts[index])
        index += 1
    while index < len(parts):
        keyword = parts[index]
        if keyword not in RULE_KEYWORDS or index + 1 >= len(parts):
            raise ValueError("malformed rule: %r" % text)
        values = parts[index + 1].split(",")
        if keyword == "if-flag":
            rule["if_flag"] = values
        elif keyword == "unless-flag":
            rule["unless_flag"] = values
        else:
            rule["if_flag_value"] = [tuple(value.split("=", 1)) for value in values]
        index += 2
    if not rule["words"]:
        raise ValueError("a rule needs at least one word: %r" % text)
    return rule


def parse_verbs(spec):
    """'hyphen-prefix@1', 'exact@0,1', 'exact@1+', 'exact@all' -> (style, positions, start)."""
    if not spec:
        return ("exact", [], None)
    style, _, where = spec.partition("@")
    if where == "all":
        return (style, None, 0)
    if where.endswith("+"):
        return (style, None, int(where[:-1]))
    return (style, [int(item) for item in where.split(",") if item != ""], None)


def load_config(path=ALLOWLIST):
    raw = _yamlite.load(path)
    home = os.path.expanduser("~")
    protected = []
    for pattern in raw.get("protected_paths") or []:
        if pattern.startswith("~/"):
            protected.append((home + pattern[1:], True))
        elif pattern.startswith("**/"):
            protected.append(("*" + pattern[2:], False))
        else:
            protected.append((pattern, False))
    tools = {}
    for name, spec in (raw.get("tools") or {}).items():
        tools[name] = {
            "verbs": parse_verbs(spec.get("verbs")),
            "with_value": set(spec.get("options_with_value") or []),
            "options": set(spec.get("options") or []),
            "never_flags": dict(spec.get("never_flags") or {}),
            "active": [parse_rule(rule) for rule in spec.get("active") or []],
            "collection": [parse_rule(rule) for rule in spec.get("collection") or []],
            "read": [parse_rule(rule) for rule in spec.get("read") or []],
        }
    shell = raw.get("shell") or {}
    never = raw.get("never_verbs") or {}
    return {
        "tools": tools,
        "protected": protected,
        "never_verbs": {klass: set(never.get(klass) or []) for klass in ("destructive", "write", "collection")},
        "allowed_env": set(raw.get("allowed_env") or []),
        "wrappers": dict(raw.get("wrappers") or {}),
        "shell": {
            "metadata": set(shell.get("metadata") or []),
            "content": set(shell.get("content") or []),
            "content_never_flags": dict(shell.get("content_never_flags") or {}),
            "collection": set(shell.get("collection") or []),
            "write": set(shell.get("write") or []),
            "destructive": set(shell.get("destructive") or []),
            "find_never_flags": dict(shell.get("find_never_flags") or {}),
            "active_tools": set(shell.get("active_tools") or []),
            "curl": dict(shell.get("curl") or {}),
        },
    }


# --------------------------------------------------------------- command pieces

_REDIRECT = re.compile(r"(\d*)(&>>|&>|>>|>\||>&|<<<|<<|<&|>|<)")
_TARGET = re.compile(r"\s*(\"[^\"]*\"|'[^']*'|[^\s;|&<>()]+)")


def split_command(command):
    """Cut a command line into the commands it runs, with their redirections.

    Returns (segments, problems). A problem is a shell feature that hides what
    would run; the caller refuses the whole line when there is one.
    """
    segments = []
    problems = []
    buf = []
    redirects = []
    quote = None
    i = 0
    n = len(command)

    def flush():
        text = "".join(buf).strip()
        del buf[:]
        if text or redirects:
            segments.append({"text": text, "redirects": list(redirects)})
        del redirects[:]

    while i < n:
        c = command[i]
        nxt = command[i + 1] if i + 1 < n else ""
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\" and nxt:
                buf.append(c + nxt)
                i += 2
                continue
            if c == "`" or (c == "$" and nxt == "("):
                problems.append("command substitution")
            if c == '"':
                quote = None
            buf.append(c)
            i += 1
            continue
        if c == "\\" and nxt:
            buf.append(c + nxt)
            i += 2
            continue
        if c in "'\"":
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "`" or (c == "$" and nxt == "("):
            problems.append("command substitution")
            buf.append(c)
            i += 1
            continue
        if c in "<>" and nxt == "(":
            problems.append("process substitution")
            buf.append(c)
            i += 1
            continue
        if c in "()":
            problems.append("a subshell")
            i += 1
            continue
        if c in ";\n":
            flush()
            i += 1
            continue
        if c == "|":
            flush()
            i += 2 if nxt and nxt in "|&" else 1
            continue
        if c == "&" and nxt == "&":
            flush()
            i += 2
            continue
        redirect = None
        if c in "<>" or (c == "&" and nxt == ">"):
            redirect = _REDIRECT.match(command, i)
        elif c.isdigit() and (not buf or buf[-1][-1:].isspace()):
            candidate = _REDIRECT.match(command, i)
            if candidate and candidate.group(1):
                redirect = candidate
        if redirect:
            operator = redirect.group(2)
            i = redirect.end()
            if operator == "<<":
                problems.append("a here-document")
            target = _TARGET.match(command, i)
            if target:
                redirects.append((operator, target.group(1)))
                i = target.end()
            else:
                problems.append("a redirection without a target")
            continue
        if c == "&":
            problems.append("background execution")
            flush()
            i += 1
            continue
        buf.append(c)
        i += 1
    if quote:
        problems.append("unbalanced quotes")
    flush()
    return segments, problems


def in_run_area(path, cwd):
    """True when the path is inside .security-scan/ under the working directory."""
    if "$" in path or "`" in path:
        return False
    root = os.path.normpath(cwd)
    full = os.path.normpath(os.path.join(root, os.path.expanduser(path)))
    if not full.startswith(root + os.sep):
        return False
    return RUN_AREA in full[len(root):].split(os.sep)


def _full_path(argument, cwd):
    argument = argument.replace("${HOME}", "~").replace("$HOME", "~")
    return os.path.normpath(os.path.join(cwd, os.path.expanduser(argument)))


def is_protected(argument, cwd, protected):
    full = _full_path(argument, cwd)
    has_glob = any(ch in full for ch in "*?[")
    for pattern, _anchored in protected:
        if fnmatch.fnmatchcase(full, pattern):
            return True
        if has_glob and fnmatch.fnmatchcase(pattern, full):
            return True
    return False


def covers_protected(argument, cwd, protected):
    """True when the argument is a directory that contains a protected location."""
    full = _full_path(argument, cwd).rstrip(os.sep)
    if not os.path.isdir(full):
        return False
    for pattern, anchored in protected:
        if anchored and re.split(r"[*?\[]", pattern, maxsplit=1)[0].startswith(full + os.sep):
            return True
    return False


def check_redirects(redirects, cwd, protected):
    for operator, target in redirects:
        target = target.strip("\"'")
        if operator in (">&", "<&") and re.match(r"^[0-9\-]+$", target):
            continue
        if operator in ("<", "<<", "<<<", "<&"):
            if operator == "<" and is_protected(target, cwd, protected):
                return verdict("collection", "reads a protected file: %s" % target)
            continue
        if target in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            continue
        if not in_run_area(target, cwd):
            return verdict("write", "writes to %s, outside the run folder" % target)
    return None


# -------------------------------------------------------------------- arguments

def has_flag(args, flag):
    short = len(flag) == 2 and flag[0] == "-" and flag[1] != "-"
    for arg in args:
        if arg == "--":
            break
        if arg == flag or arg.startswith(flag + "="):
            return True
        if short and arg.startswith(flag) and len(arg) > 2 and not arg.startswith("--"):
            return True
    return False


def flag_value(args, flag):
    short = len(flag) == 2 and flag[0] == "-" and flag[1] != "-"
    for index, arg in enumerate(args):
        if arg == "--":
            break
        if arg == flag:
            return args[index + 1] if index + 1 < len(args) else None
        if arg.startswith(flag + "="):
            return arg[len(flag) + 1:]
        if short and arg.startswith(flag) and len(arg) > 2 and not arg.startswith("--"):
            return arg[2:]
    return None


def split_args(args, with_value, options):
    """Separate the command's words from its flags.

    Returns (words, unknown_at). unknown_at lists the word positions before which
    an unlisted flag appeared: guard.py cannot tell whether the token after such
    a flag is its value or a word, so rules must not rely on words after it.
    """
    words = []
    unknown_at = []
    i = 0
    n = len(args)
    while i < n:
        token = args[i]
        if token == "--":
            words.extend(args[i + 1:])
            break
        if token.startswith("-") and len(token) > 1:
            name = token.split("=", 1)[0]
            if name in with_value:
                if "=" not in token:
                    i += 1
            elif name in options:
                pass
            elif not token.startswith("--") and len(token) > 2 and token[:2] in with_value:
                pass
            else:
                unknown_at.append(len(words))
            i += 1
            continue
        words.append(token)
        i += 1
    return words, unknown_at


def _word_match(token, pattern, any_part):
    parts = token.split(",") if "," in token else [token]
    check = any if any_part else all
    return check(fnmatch.fnmatchcase(part, pattern) for part in parts)


def match_words(pattern, words, any_part=False, pi=0, wi=0):
    """Match rule words against command words. Returns how many words were used, or None."""
    if pi == len(pattern):
        return wi
    current = pattern[pi]
    if current == "$":
        return wi if wi == len(words) and pi == len(pattern) - 1 else None
    if current == "**":
        for take in range(1, len(words) - wi + 1):
            used = match_words(pattern, words, any_part, pi + 1, wi + take)
            if used is not None:
                return used
        return None
    if wi >= len(words) or not _word_match(words[wi], current, any_part):
        return None
    return match_words(pattern, words, any_part, pi + 1, wi + 1)


def rule_applies(rule, words, unknown_at, args, any_part, strict):
    used = match_words(rule["words"], words, any_part)
    if used is None:
        return False
    if strict and any(position < used for position in unknown_at):
        return False
    if rule["if_flag"] and not any(has_flag(args, flag) for flag in rule["if_flag"]):
        return False
    if rule["unless_flag"] and any(has_flag(args, flag) for flag in rule["unless_flag"]):
        return False
    if rule["if_flag_value"] and not any(flag_value(args, flag) == value for flag, value in rule["if_flag_value"]):
        return False
    return True


def verb_class(words, verbs, never_verbs):
    style, positions, start = verbs
    indexes = range(start, len(words)) if positions is None else positions
    for index in indexes:
        if index >= len(words):
            continue
        token = words[index]
        verb = token.split("-", 1)[0] if style == "hyphen-prefix" else token
        for klass in ("destructive", "write", "collection"):
            if verb in never_verbs[klass]:
                return klass, verb
    return None


# --------------------------------------------------------------- classification

def classify_tool(tool, args, spec, config):
    for flag, klass in spec["never_flags"].items():
        if has_flag(args, flag):
            return verdict(klass, "%s %s is not allowed in a scan" % (tool, flag))
    words, unknown_at = split_args(args, spec["with_value"], spec["options"])
    for rule in spec["active"]:
        if rule_applies(rule, words, unknown_at, args, any_part=False, strict=True):
            return verdict("active", "matches the active rule '%s'" % rule["text"])
    hit = verb_class(words, spec["verbs"], config["never_verbs"])
    if hit:
        return verdict(hit[0], "'%s' is a %s verb" % (hit[1], hit[0]))
    for rule in spec["collection"]:
        if rule_applies(rule, words, unknown_at, args, any_part=True, strict=False):
            return verdict("collection", "matches the collection rule '%s'" % rule["text"])
    for rule in spec["read"]:
        if rule_applies(rule, words, unknown_at, args, any_part=False, strict=True):
            return verdict("read", "matches the read rule '%s'" % rule["text"])
    return verdict("unknown", "no rule for: %s" % " ".join([tool] + words[:3]))


def classify_content(tool, args, config, cwd):
    for flag in config["shell"]["content_never_flags"].get(tool, []):
        if has_flag(args, flag):
            return verdict("write", "%s %s writes or runs something" % (tool, flag))
    recursive = tool == "rg" or (
        tool in ("grep", "egrep", "fgrep")
        and any(re.match(r"^-[A-Za-z]*[rR]", arg) or arg in ("--recursive", "--dereference-recursive") for arg in args)
    )
    for arg in args:
        candidates = [arg.split("=", 1)[1]] if arg.startswith("-") and "=" in arg else ([] if arg.startswith("-") else [arg])
        for candidate in candidates:
            if is_protected(candidate, cwd, config["protected"]):
                return verdict("collection", "%s would print a protected file: %s" % (tool, candidate))
            if recursive and covers_protected(candidate, cwd, config["protected"]):
                return verdict("collection", "%s would search a folder that holds credentials: %s" % (tool, candidate))
    return verdict("read", "%s prints or filters text" % tool)


def classify_curl(args, spec):
    for flag in spec.get("never_flags") or []:
        if has_flag(args, flag):
            return verdict("write", "curl %s sends data, sets credentials or writes a file" % flag)
    head = any(arg in (spec.get("require_flag") or []) or re.match(r"^-[A-Za-z]*I[A-Za-z]*$", arg) for arg in args)
    if not head:
        return verdict("unknown", "only HEAD requests are allowed: use curl -I")
    return verdict("active", "curl -I sends a request and changes nothing")


def is_skill_script(path, cwd):
    full = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
    return full.endswith(".py") and full.startswith(os.path.realpath(HERE) + os.sep) and os.path.isfile(full)


def _skill_script(args, config, cwd):
    for arg in args:
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if not value.startswith("-") and is_protected(value, cwd, config["protected"]):
            return verdict("collection", "a protected file is passed to a script: %s" % value)
    return verdict("read", "runs a script of this skill")


def classify_tokens(tokens, config, cwd, depth=0):
    if not tokens:
        return verdict("unknown", "empty command")
    tool = os.path.basename(tokens[0])
    args = tokens[1:]
    shell = config["shell"]

    if tool in ELEVATORS:
        return verdict("write", "%s elevates privileges" % tool)
    if tool in config["wrappers"] and depth < 3:
        if args and args[0].startswith("-"):
            return verdict("unknown", "options of the wrapper %s are not recognised" % tool)
        return classify_tokens(args[int(config["wrappers"][tool]):], config, cwd, depth + 1)
    if tool == "command" and depth < 3:
        if args[:1] in (["-v"], ["-V"]):
            return verdict("read", "looks up a command")
        return classify_tokens(args, config, cwd, depth + 1)
    if re.match(r"^python[0-9.]*$", tool):
        if args and is_skill_script(args[0], cwd):
            return _skill_script(args[1:], config, cwd)
        return verdict("unknown", "%s can run anything; only this skill's scripts are allowed" % tool)
    if is_skill_script(tokens[0], cwd):
        return _skill_script(args, config, cwd)
    if tool in LAUNCHERS:
        return verdict("unknown", "%s can run anything; run the inner command by itself" % tool)
    if tool in config["tools"]:
        return classify_tool(tool, args, config["tools"][tool], config)
    if tool == "find":
        for flag, klass in shell["find_never_flags"].items():
            if flag in args:
                return verdict(klass, "find %s changes or runs something" % flag)
        return verdict("read", "find lists files")
    if tool == "curl":
        return classify_curl(args, shell["curl"])
    if tool in ("mkdir", "tee"):
        targets = [arg for arg in args if not arg.startswith("-")]
        if all(in_run_area(target, cwd) for target in targets) and (targets or tool == "tee"):
            return verdict("read", "%s writes only inside the run folder" % tool)
        return verdict("write", "%s writes outside the run folder" % tool)
    if tool in shell["collection"]:
        return verdict("collection", "%s prints secret values" % tool)
    if tool in shell["destructive"]:
        return verdict("destructive", "%s deletes or stops something" % tool)
    if tool in shell["write"]:
        return verdict("write", "%s changes files" % tool)
    if tool in shell["active_tools"]:
        return verdict("active", "%s sends a request outside the machine" % tool)
    if tool in shell["metadata"]:
        return verdict("read", "%s prints facts, not file contents" % tool)
    if tool in shell["content"]:
        return classify_content(tool, args, config, cwd)
    return verdict("unknown", "%s is not in the allowlist" % tool)


def classify_segment(segment, config, cwd):
    text = segment["text"]
    redirect = check_redirects(segment["redirects"], cwd, config["protected"])
    if not text:
        return redirect or verdict("read", "only a redirection")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return verdict("unknown", "could not parse the command", text)
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        name = tokens[0].split("=", 1)[0]
        if name not in config["allowed_env"]:
            return verdict("unknown", "sets the environment variable %s" % name, text)
        tokens = tokens[1:]
    result = classify_tokens(tokens, config, cwd)
    result["segment"] = text
    if redirect and ORDER.index(redirect["class"]) > ORDER.index(result["class"]):
        redirect["segment"] = text
        return redirect
    return result


def classify(command, config=None, cwd=None, allow_active=False):
    """Classify a whole command line. Returns class, allowed, reason and the parts."""
    config = config or load_config()
    cwd = cwd or os.getcwd()
    segments, problems = split_command(command)
    parts = [verdict("unknown", "%s hides what would run; run the inner command by itself" % problem) for problem in problems]
    parts.extend(classify_segment(segment, config, cwd) for segment in segments)
    if not parts:
        parts = [verdict("unknown", "empty command")]
    top = max(parts, key=lambda part: ORDER.index(part["class"]))
    allowed = top["class"] == "read" or (top["class"] == "active" and allow_active)
    return {"class": top["class"], "allowed": allowed, "reason": top["reason"], "parts": parts}


# ----------------------------------------------------------------- current run

def find_run(start):
    """The run folder named by .security-scan/current, looking upward from `start`."""
    folder = os.path.abspath(start)
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


def run_settings(start):
    """(in_progress, active_checks) for the current run, or (False, False)."""
    run = find_run(start)
    if not run:
        return False, False
    try:
        engagement = _yamlite.load(os.path.join(run, "engagement.yaml")) or {}
    except (OSError, _yamlite.YamlError):
        return False, False
    mode = engagement.get("mode") or {}
    return engagement.get("status") == "in-progress", bool(mode.get("active_checks"))


def hook():
    """Pre-tool hook: refuse a Bash command outside the read class while a run is in progress."""
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    cwd = payload.get("cwd") or os.getcwd()
    in_progress, active = run_settings(cwd)
    if not in_progress:
        return 0
    result = classify(command, cwd=cwd, allow_active=active)
    if result["allowed"]:
        return 0
    sys.stderr.write("security-scan guard: refused (%s): %s\n" % (result["class"], result["reason"]))
    return 2


# -------------------------------------------------------------------- self-test

def _cases():
    script = os.path.join(HERE, "blackboard.py")
    run = ".security-scan/runs/20261118-1000"
    return [
        # read
        ("aws sts get-caller-identity", "read"),
        ("aws --profile prod --region us-east-1 iam list-users --max-items 5", "read"),
        ("aws iam get-account-password-policy", "read"),
        ("aws s3 ls", "read"),
        ("aws s3 ls s3://bucket/prefix/", "read"),
        ("aws s3api get-bucket-policy --bucket x", "read"),
        ("aws ec2 describe-instances --filters Name=tag:Name,Values=create-x", "read"),
        ("aws lambda get-function-configuration --function-name f", "read"),
        ("AWS_PROFILE=dev aws iam list-roles | jq '.Roles[].RoleName'", "read"),
        ("aws iam list-users --output json > %s/evidence/00/users.json" % run, "read"),
        ("aws iam list-users 2>/dev/null", "read"),
        ("aws iam list-users 2>&1 | head -3", "read"),
        ("aws iam list-users | tee %s/evidence/00/users.json" % run, "read"),
        ("timeout 10 aws sts get-caller-identity", "read"),
        ("kubectl get pods -A", "read"),
        ("kubectl -n prod get pods -o wide", "read"),
        ("kubectl get secrets -n prod", "read"),
        ("kubectl describe secret db -n prod", "read"),
        ("kubectl auth can-i create pods", "read"),
        ("kubectl config get-contexts", "read"),
        ("gh auth status", "read"),
        ("gh repo view owner/name --json name", "read"),
        ("gh api repos/o/r/actions/secrets", "read"),
        ("gh api -X GET repos/o/r/branches -f per_page=5", "read"),
        ("gh run list --limit 5", "read"),
        ("gh secret list", "read"),
        ("git status", "read"),
        ("git log --oneline -5", "read"),
        ("git remote -v", "read"),
        ("git branch -a", "read"),
        ("git config --get remote.origin.url", "read"),
        ("docker ps -a", "read"),
        ("docker image ls", "read"),
        ("terraform state list", "read"),
        ("ls -la ~/.aws", "read"),
        ("stat ~/.aws/credentials", "read"),
        ("cat README.md | head -5", "read"),
        ("find . -name '*.tf' -type f", "read"),
        ("gcloud compute instances list --format=json", "read"),
        ("gcloud run services list", "read"),
        ("gcloud projects get-iam-policy my-proj", "read"),
        ("az account show", "read"),
        ("az role assignment list --all", "read"),
        ("command -v aws", "read"),
        ("python3 %s list facts" % script, "read"),
        ("mkdir -p %s/evidence/01" % run, "read"),
        ("echo done", "read"),
        # active
        ("curl -I https://example.com", "active"),
        ("curl -sI https://example.com", "active"),
        ("aws ec2 run-instances --dry-run --image-id ami-1", "active"),
        ("dig example.com", "active"),
        # collection
        ("aws secretsmanager get-secret-value --secret-id x", "collection"),
        ("aws ssm get-parameter --name x --with-decryption", "collection"),
        ("aws s3 cp s3://b/k .", "collection"),
        ("aws kms decrypt --ciphertext-blob x", "collection"),
        ("aws ec2 describe-instance-attribute --instance-id i-1 --attribute userData", "collection"),
        ("aws sts assume-role --role-arn x --role-session-name y", "collection"),
        ("kubectl get secret db -o yaml", "collection"),
        ("kubectl get pods,secrets -n prod -o json", "collection"),
        ("kubectl get secret db -ojsonpath='{.data}'", "collection"),
        ("kubectl get --weird secrets -o yaml", "collection"),
        ("kubectl config view --raw", "collection"),
        ("cat ~/.aws/credentials", "collection"),
        ("grep -r aws_secret ~", "collection"),
        ("cat .env", "collection"),
        ("head -5 < ~/.ssh/id_ed25519", "collection"),
        ("env", "collection"),
        ("printenv AWS_SECRET_ACCESS_KEY", "collection"),
        ("gh auth token", "collection"),
        ("gh auth status --show-token", "collection"),
        ("az keyvault secret show --name x --vault-name v", "collection"),
        ("az storage account keys list -n x", "collection"),
        ("gcloud secrets versions access latest --secret x", "collection"),
        ("gcloud auth print-access-token", "collection"),
        ("terraform state pull", "collection"),
        ("docker pull alpine", "collection"),
        ("git clone https://example.com/x.git", "collection"),
        ("python3 %s add-fact --evidence ~/.aws/credentials" % script, "collection"),
        # write
        ("aws iam create-user --user-name x", "write"),
        ("aws iam put-user-policy --user-name x --policy-name p --policy-document file://p.json", "write"),
        ("aws iam attach-role-policy --role-name r --policy-arn a", "write"),
        ("aws configure set region us-east-1", "write"),
        ("aws ssm send-command --document-name x", "write"),
        ("kubectl apply -f x.yaml", "write"),
        ("kubectl exec -it pod -- sh", "write"),
        ("kubectl get pods --as system:admin", "write"),
        ("gh secret set NAME", "write"),
        ("git push origin main", "write"),
        ("git commit -m x", "write"),
        ("git -c core.pager=evil log", "write"),
        ("docker run alpine", "write"),
        ("terraform apply", "write"),
        ("gcloud run deploy svc --image x", "write"),
        ("aws iam list-users > /tmp/out.json", "write"),
        ("echo x > README.md", "write"),
        ("aws iam list-users | tee /tmp/x", "write"),
        ("sudo ls", "write"),
        ("sort -o out.txt in.txt", "write"),
        ("mkdir build", "write"),
        ("curl -X POST https://example.com", "write"),
        # destructive
        ("aws s3 rm s3://b/k", "destructive"),
        ("aws ec2 terminate-instances --instance-ids i-1", "destructive"),
        ("aws iam delete-user --user-name x", "destructive"),
        ("kubectl delete pod x", "destructive"),
        ("gh repo delete o/r", "destructive"),
        ("git reset --hard", "destructive"),
        ("git clean -fd", "destructive"),
        ("terraform destroy", "destructive"),
        ("gcloud compute instances delete list", "destructive"),
        ("find . -name '*.log' -delete", "destructive"),
        ("rm -rf x", "destructive"),
        ("aws iam list-users; rm -rf x", "destructive"),
        # unknown
        ("aws --weird-flag iam list-users", "unknown"),
        ("aws iam --weird list-x create-user", "unknown"),
        ("aws iam list-users $(whoami)", "unknown"),
        ("aws iam list-users `id`", "unknown"),
        ("echo \"$(aws iam delete-user --user-name x)\"", "unknown"),
        ("bash -c 'aws iam delete-user --user-name x'", "unknown"),
        ("python3 -c 'print(1)'", "unknown"),
        ("xargs rm", "unknown"),
        ("aws iam list-users &", "unknown"),
        ("FOO=bar aws iam list-users", "unknown"),
        ("nc -l 4444", "unknown"),
        ("ssh host ls", "unknown"),
        ("gh api -X POST repos/o/r/issues -f title=x", "unknown"),
        ("gh api repos/o/r/issues -f title=x", "unknown"),
        ("git branch newbranch", "unknown"),
        ("git config user.name x", "unknown"),
        ("(aws iam list-users)", "unknown"),
        ("cat <<EOF", "unknown"),
        ("curl https://example.com", "unknown"),
        ("terraform plan", "unknown"),
        ("", "unknown"),
    ]


def self_test():
    config = load_config()
    failures = []
    for command, expected in _cases():
        got = classify(command, config, cwd=os.getcwd())
        if got["class"] != expected:
            failures.append("%-12s expected %-12s %r (%s)" % (got["class"], expected, command, got["reason"]))
        if got["allowed"] and expected not in ("read",):
            failures.append("ALLOWED a command that must be refused: %r" % command)
    for command in ("curl -I https://example.com",):
        if not classify(command, config, allow_active=True)["allowed"]:
            failures.append("active command refused despite the opt-in: %r" % command)
    return failures, len(_cases())


def main(argv):
    if argv[:1] == ["--self-test"]:
        failures, total = self_test()
        for failure in failures:
            print("FAIL " + failure)
        print("guard.py self-test: %d cases, %s" % (total, "%d failure(s)" % len(failures) if failures else "ok"))
        return 1 if failures else 0
    if argv[:1] == ["hook"]:
        return hook()

    parser = argparse.ArgumentParser(description="Classify a command before it runs.")
    sub = parser.add_subparsers(dest="action")
    check = sub.add_parser("check", help="classify one command line")
    check.add_argument("command", help="the command, quoted as one argument; '-' reads it from stdin")
    check.add_argument("--allow-active", action="store_true", help="treat the active class as allowed")
    check.add_argument("--json", action="store_true", help="print the verdict as JSON")
    check.add_argument("--cwd", default=None, help="working directory the command would run in")
    args = parser.parse_args(argv)
    if args.action != "check":
        parser.print_help()
        return 1

    command = sys.stdin.read() if args.command == "-" else args.command
    cwd = args.cwd or os.getcwd()
    allow_active = args.allow_active or run_settings(cwd)[1]
    result = classify(command, cwd=cwd, allow_active=allow_active)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("class: %s" % result["class"])
        print("allowed: %s" % ("yes" if result["allowed"] else "no"))
        for part in result["parts"]:
            label = part["segment"] or "(whole line)"
            print("  %s -> %s: %s" % (label, part["class"], part["reason"]))
    return 0 if result["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
