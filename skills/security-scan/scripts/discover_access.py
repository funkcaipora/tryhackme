#!/usr/bin/env python3
"""Inventory what the machine and session can reach.

Finds the CLIs that are installed, asks each one who it is logged in as
(identity calls only), lists profiles, contexts and projects, and records
metadata about credential files, secret-looking environment variable names, SSH
configuration and AI assistant configuration. The result is the access half of
the stage 0 map.

Usage:
    discover_access.py --out <run-dir>/access-inventory.json
    discover_access.py --identities-only          just "who am I", for the scope question
    discover_access.py --no-cli-calls             filesystem metadata only, no command is run
    discover_access.py --only aws,gh,kubectl      limit the CLIs that are asked
    discover_access.py --connectors connectors.json   merge the agent's list of session connectors

Inputs:  the local environment; optionally connectors.json written by the agent,
         because a script cannot see the tools of the session
Outputs: access-inventory.json (stdout when --out is not given); one line per
         CLI call in the run's actions.log
Safety:  never opens a credential file: it records path, type, age and
         permissions. Configuration files are read only for the names in them.
         Environment variables are listed by name. Every command it runs is an
         identity or context call, passes guard.py first, has a timeout, and its
         output goes through redact.py.
"""
import argparse
import glob
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

import guard
import redact
from _common import display_path, find_run, log_action, now_iso

# name, domain it points to, commands that ask "who am I" or "which contexts".
TOOLS = [
    ("aws", "aws", [["aws", "sts", "get-caller-identity", "--output", "json"], ["aws", "configure", "list-profiles"]]),
    ("gcloud", "gcp", [["gcloud", "auth", "list", "--format=json"], ["gcloud", "config", "list", "--format=json"]]),
    ("az", "azure-entra-m365", [["az", "account", "show", "-o", "json"]]),
    ("kubectl", "kubernetes-containers", [["kubectl", "config", "get-contexts", "-o", "name"], ["kubectl", "config", "current-context"]]),
    ("docker", "kubernetes-containers", [["docker", "context", "ls", "--format", "{{.Name}} {{.Current}}"]]),
    ("helm", "kubernetes-containers", []),
    ("gh", "source-control-cicd", [["gh", "auth", "status"]]),
    ("glab", "source-control-cicd", [["glab", "auth", "status"]]),
    ("git", "source-control-cicd", []),
    ("terraform", None, []),
    ("pulumi", None, [["pulumi", "whoami"]]),
    ("wrangler", "edge-paas", [["wrangler", "whoami"]]),
    ("vercel", "edge-paas", [["vercel", "whoami"]]),
    ("netlify", "edge-paas", [["netlify", "status"]]),
    ("fly", "edge-paas", [["fly", "auth", "whoami"]]),
    ("flyctl", "edge-paas", [["flyctl", "auth", "whoami"]]),
    ("heroku", "edge-paas", [["heroku", "auth:whoami"]]),
    ("supabase", "edge-paas", []),
    ("firebase", "edge-paas", [["firebase", "login:list"]]),
    ("doctl", "edge-paas", [["doctl", "account", "get"]]),
    ("op", None, [["op", "whoami"]]),
    ("vault", None, []),
    ("npm", "source-control-cicd", [["npm", "whoami"]]),
    ("psql", "web-app-database", []),
    ("mysql", "web-app-database", []),
    ("mongosh", "web-app-database", []),
    ("redis-cli", "web-app-database", []),
    ("ssh", "workstation-dev-env", []),
    ("claude", "ai-llm-infrastructure", []),
]

# path (globs allowed), type. Only metadata is read.
CREDENTIAL_FILES = [
    ("~/.aws/credentials", "aws-shared-credentials"),
    ("~/.aws/config", "aws-config"),
    ("~/.aws/sso/cache/*.json", "aws-sso-token-cache"),
    ("~/.aws/cli/cache/*.json", "aws-role-credential-cache"),
    ("~/.config/gcloud/credentials.db", "gcloud-credentials"),
    ("~/.config/gcloud/application_default_credentials.json", "gcloud-application-default-credentials"),
    ("~/.config/gcloud/legacy_credentials", "gcloud-legacy-credentials"),
    ("~/.azure/msal_token_cache.json", "azure-token-cache"),
    ("~/.azure/msal_token_cache.bin", "azure-token-cache"),
    ("~/.azure/azureProfile.json", "azure-profile"),
    ("~/.kube/config", "kubeconfig"),
    ("~/.docker/config.json", "docker-config"),
    ("~/.netrc", "netrc"),
    ("~/.npmrc", "npm-config"),
    ("~/.pypirc", "pypi-config"),
    ("~/.git-credentials", "git-credential-store"),
    ("~/.config/gh/hosts.yml", "github-cli-token"),
    ("~/.config/glab-cli/config.yml", "gitlab-cli-token"),
    ("~/.terraform.d/credentials.tfrc.json", "terraform-cloud-token"),
    ("~/.terraformrc", "terraform-cli-config"),
    ("~/.vault-token", "vault-token"),
    ("~/.pgpass", "postgres-password-file"),
    ("~/.my.cnf", "mysql-client-config"),
    ("~/.config/doctl/config.yaml", "digitalocean-token"),
    ("~/.netlify/config.json", "netlify-token"),
    ("~/.fly/config.yml", "fly-token"),
    ("~/.supabase/access-token", "supabase-token"),
    ("~/.wrangler/config/default.toml", "cloudflare-token"),
    ("~/Library/Preferences/.wrangler/config/default.toml", "cloudflare-token"),
    ("~/.config/rclone/rclone.conf", "rclone-config"),
    ("~/.boto", "boto-config"),
    ("~/.s3cfg", "s3cmd-config"),
    ("~/.claude.json", "claude-code-state"),
]

SECRET_LIKE_NAME = re.compile(r"(?i)(key|token|secret|password|passwd|credential|session|auth)")
KNOWN_CREDENTIAL_VARS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET",
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN", "DOCKER_PASSWORD",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "HF_TOKEN",
    "CLOUDFLARE_API_TOKEN", "VERCEL_TOKEN", "NETLIFY_AUTH_TOKEN", "SUPABASE_ACCESS_TOKEN",
    "DATABASE_URL", "KUBECONFIG", "VAULT_TOKEN", "TF_TOKEN_app_terraform_io",
]
NOT_LOGGED_IN = re.compile(
    r"(?i)not logged in|unable to locate credentials|no credentials|expired|please run|"
    r"login required|not authenticated|no credentialed accounts|az login|could not find"
)


def child_environment():
    environment = dict(os.environ)
    environment.update({"AWS_PAGER": "", "PAGER": "cat", "NO_COLOR": "1", "TERM": "dumb", "GH_PROMPT_DISABLED": "1"})
    return environment


def run_command(command, timeout):
    """Run one identity command. Returns status, redacted output and timing."""
    started = time.time()
    try:
        done = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            env=child_environment(), stdin=subprocess.DEVNULL,
        )
        status, out, err, code = ("ok" if done.returncode == 0 else "error"), done.stdout, done.stderr, done.returncode
    except subprocess.TimeoutExpired:
        status, out, err, code = "timeout", "", "", None
    except OSError as error:
        status, out, err, code = "error", "", str(error), None
    if status == "error" and NOT_LOGGED_IN.search(out + err):
        status = "not-logged-in"
    return {
        "status": status,
        "stdout": redact.redact_text(out),
        "stderr": redact.redact_text(err),
        "exit": code,
        "ms": int((time.time() - started) * 1000),
    }


def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def summarise(name, command, result):
    """Pick the identity facts out of a command's output. Returns a dict, possibly empty."""
    out = result["stdout"]
    both = out + "\n" + result["stderr"]
    joined = " ".join(command[1:])
    if name == "aws" and "get-caller-identity" in joined:
        data = _json(out) or {}
        return {key: data[source] for key, source in (("account", "Account"), ("arn", "Arn")) if source in data}
    if name == "aws" and "list-profiles" in joined:
        return {"profiles": [line.strip() for line in out.splitlines() if line.strip()]}
    if name == "gcloud" and "auth list" in joined:
        data = _json(out) or []
        return {"accounts": [{"account": item.get("account"), "active": item.get("status") == "ACTIVE"} for item in data if isinstance(item, dict)]}
    if name == "gcloud" and "config list" in joined:
        core = (_json(out) or {}).get("core") or {}
        return {key: core[key] for key in ("project", "account") if key in core}
    if name == "az":
        data = _json(out) or {}
        summary = {}
        if isinstance(data.get("user"), dict) and "name" in data["user"]:
            summary["user"] = data["user"]["name"]
        for key, source in (("tenant", "tenantId"), ("subscription", "name"), ("subscription_id", "id")):
            if source in data:
                summary[key] = data[source]
        return summary
    if name == "kubectl" and "get-contexts" in joined:
        return {"contexts": [line.strip() for line in out.splitlines() if line.strip()]}
    if name == "kubectl" and "current-context" in joined:
        return {"current_context": out.strip()} if out.strip() else {}
    if name == "docker":
        contexts = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                contexts.append({"name": parts[0], "current": parts[-1] == "true"})
        return {"contexts": contexts}
    if name in ("gh", "glab"):
        accounts = []
        current = None
        for line in both.splitlines():
            logged = re.search(r"Logged in to (\S+) (?:account|as) (\S+)", line)
            if logged:
                current = {"host": logged.group(1), "account": logged.group(2).strip("()")}
                accounts.append(current)
            scopes = re.search(r"Token scopes: (.+)$", line)
            if scopes and current is not None:
                current["scopes"] = [scope.strip(" '\"") for scope in scopes.group(1).split(",") if scope.strip(" '\"")]
            if current is not None and re.search(r"Active account: true", line):
                current["active"] = True
        return {"accounts": accounts} if accounts else {}
    lines = [line.strip() for line in both.splitlines() if line.strip()]
    return {"text": lines[:4]} if lines and result["status"] == "ok" else {}


def inventory_tools(only, call, timeout, run, config, calls):
    tools = []
    for name, domain, commands in TOOLS:
        if only and name not in only:
            continue
        path = shutil.which(name)
        entry = {"name": name, "present": bool(path)}
        if domain:
            entry["domain"] = domain
        if not path:
            tools.append(entry)
            continue
        entry["path"] = display_path(path)
        if call and commands:
            identity = {}
            statuses = []
            for command in commands:
                text = " ".join(command)
                verdict = guard.classify(text, config)
                if verdict["class"] != "read":
                    statuses.append("skipped")
                    calls.append({"command": text, "status": "skipped", "note": "not classified as read by guard.py"})
                    continue
                result = run_command(command, timeout)
                log_action(run, "read", 0, text, "discover_access: %s" % result["status"])
                calls.append({"command": text, "status": result["status"], "exit": result["exit"], "ms": result["ms"]})
                statuses.append(result["status"])
                identity.update(summarise(name, command, result))
            # The first command is the "who am I" one; the others only add context.
            entry["identity_status"] = statuses[0] if statuses else "skipped"
            if identity:
                entry["identity"] = identity
            entry["reachable"] = entry["identity_status"] == "ok" and any(identity.values())
        tools.append(entry)
    return tools


def file_metadata(path, kind):
    try:
        info = os.stat(path)
    except OSError:
        return None
    mode = stat.S_IMODE(info.st_mode)
    entry = {
        "path": display_path(path),
        "type": kind,
        "is_directory": stat.S_ISDIR(info.st_mode),
        "modified": time.strftime("%Y-%m-%d", time.gmtime(info.st_mtime)),
        "age_days": int((time.time() - info.st_mtime) // 86400),
        "mode": "%04o" % mode,
        "group_or_world_readable": bool(mode & 0o077),
    }
    if not entry["is_directory"]:
        entry["size_bytes"] = info.st_size
    return entry


def inventory_credential_files():
    found = []
    for pattern, kind in CREDENTIAL_FILES:
        for path in sorted(glob.glob(os.path.expanduser(pattern))):
            entry = file_metadata(path, kind)
            if entry:
                found.append(entry)
    return found


def inventory_environment():
    names = sorted(os.environ)
    return {
        "secret_like_names": [name for name in names if SECRET_LIKE_NAME.search(name)],
        "known_credential_vars_present": [name for name in KNOWN_CREDENTIAL_VARS if name in os.environ],
        "note": "names only; values are never read into the inventory",
    }


def inventory_ssh():
    folder = os.path.expanduser("~/.ssh")
    result = {"present": os.path.isdir(folder), "agent_socket": "SSH_AUTH_SOCK" in os.environ}
    if not result["present"]:
        return result
    keys = []
    for path in sorted(glob.glob(os.path.join(folder, "*"))):
        name = os.path.basename(path)
        if name.endswith(".pub") or name in ("config", "known_hosts", "known_hosts.old", "authorized_keys") or os.path.isdir(path):
            continue
        if name.startswith("id_") or os.path.exists(path + ".pub"):
            entry = file_metadata(path, "ssh-private-key")
            if entry:
                entry["has_public_key_file"] = os.path.exists(path + ".pub")
                keys.append(entry)
    result["private_keys"] = keys
    hosts = []
    config = os.path.join(folder, "config")
    if os.path.isfile(config):
        current = None
        try:
            with open(config, "r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.replace("=", " ", 1).split(None, 1)
                    if len(parts) != 2:
                        continue
                    key, value = parts[0].lower(), parts[1].strip()
                    if key == "host":
                        current = None
                        names = [name for name in value.split() if not any(ch in name for ch in "*?!")]
                        if names:
                            current = {"host": names[0]}
                            hosts.append(current)
                    elif current is not None:
                        if key == "hostname":
                            current["hostname"] = value
                        elif key == "forwardagent":
                            current["forward_agent"] = value.lower() == "yes"
                        elif key == "proxyjump":
                            current["proxy_jump"] = value
                        elif key == "identityfile":
                            current["identity_file"] = display_path(value)
        except OSError:
            pass
    result["config_hosts"] = hosts[:200]
    for name in ("known_hosts", "authorized_keys"):
        path = os.path.join(folder, name)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    result[name + "_entries"] = sum(1 for line in handle if line.strip() and not line.startswith("#"))
            except OSError:
                pass
    return result


def _names_in_json(path, *keys):
    """Names under a nested key of a JSON file, never the values."""
    try:
        if os.path.getsize(path) > 20 * 1024 * 1024:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    if isinstance(data, dict):
        return sorted(data)
    if isinstance(data, list):
        return len(data)
    return None


def inventory_agent_configs(root):
    """AI assistant configuration: which connectors and hooks are defined, by name."""
    found = []

    def add(path, scope, **facts):
        if os.path.exists(path):
            entry = {"path": display_path(path) if scope == "user" else os.path.relpath(path, root), "scope": scope}
            entry.update({key: value for key, value in facts.items() if value not in (None, [], 0)})
            found.append(entry)

    for scope, base in (("project", root), ("user", os.path.expanduser("~"))):
        claude = os.path.join(base, ".claude")
        for name in ("settings.json", "settings.local.json"):
            path = os.path.join(claude, name)
            add(
                path, scope,
                hook_events=_names_in_json(path, "hooks"),
                permission_allow_rules=_names_in_json(path, "permissions", "allow"),
                enabled_plugins=_names_in_json(path, "enabledPlugins"),
            )
        for folder in ("skills", "agents", "commands"):
            path = os.path.join(claude, folder)
            if os.path.isdir(path):
                add(path, scope, entries=len(os.listdir(path)))
        add(os.path.join(base, ".cursor", "mcp.json"), scope, connectors=_names_in_json(os.path.join(base, ".cursor", "mcp.json"), "mcpServers"))
    add(os.path.join(root, ".mcp.json"), "project", connectors=_names_in_json(os.path.join(root, ".mcp.json"), "mcpServers"))
    for name in ("CLAUDE.md", "AGENTS.md", ".cursorrules", ".windsurfrules"):
        add(os.path.join(root, name), "project")
    home = os.path.expanduser("~")
    add(os.path.join(home, ".claude.json"), "user", connectors=_names_in_json(os.path.join(home, ".claude.json"), "mcpServers"))
    add(os.path.join(home, ".codex", "config.toml"), "user")
    add(os.path.join(home, ".gemini", "settings.json"), "user", connectors=_names_in_json(os.path.join(home, ".gemini", "settings.json"), "mcpServers"))
    return found


def load_connectors(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        sys.stderr.write("discover_access.py: could not read %s: %s\n" % (path, error))
        return []
    items = data.get("connectors") if isinstance(data, dict) else data
    return redact.redact_json(items) if isinstance(items, list) else []


def main(argv):
    parser = argparse.ArgumentParser(description="Inventory what the machine and session can reach.")
    parser.add_argument("--out", help="write the inventory here instead of stdout")
    parser.add_argument("--identities-only", action="store_true", help="only the CLIs and who they are logged in as")
    parser.add_argument("--no-cli-calls", action="store_true", help="run no command at all")
    parser.add_argument("--only", help="comma-separated CLI names to ask")
    parser.add_argument("--connectors", help="JSON list of session connectors, written by the agent")
    parser.add_argument("--timeout", type=float, default=8.0, help="seconds allowed per command")
    parser.add_argument("--root", default=".", help="project folder, for project-level assistant configuration")
    parser.add_argument("--run", help="run folder whose actions.log receives the calls; default is the current run")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    run = os.path.abspath(args.run) if args.run else find_run(root)
    only = set(part.strip() for part in args.only.split(",")) if args.only else None
    calls = []
    config = guard.load_config()

    inventory = {
        "generated_at": now_iso(),
        "mode": "identities-only" if args.identities_only else ("no-cli-calls" if args.no_cli_calls else "full"),
        "host": {"os": platform.system().lower(), "python": platform.python_version()},
        "tools": inventory_tools(only, not args.no_cli_calls, args.timeout, run, config, calls),
    }
    inventory["domains_hint"] = sorted(
        {tool["domain"] for tool in inventory["tools"] if tool.get("domain") and tool.get("reachable")}
    )
    if not args.identities_only:
        inventory["credential_files"] = inventory_credential_files()
        inventory["environment"] = inventory_environment()
        inventory["ssh"] = inventory_ssh()
        inventory["agent_configs"] = inventory_agent_configs(root)
    if args.connectors:
        inventory["connectors"] = load_connectors(args.connectors)
    inventory["calls"] = calls

    text = json.dumps(redact.redact_json(inventory), indent=2, ensure_ascii=False) + "\n"
    if redact.scan(text):
        sys.stderr.write("discover_access.py: the inventory still looks like it holds a secret; nothing was written\n")
        return 1
    if args.out:
        folder = os.path.dirname(os.path.abspath(args.out))
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        present = [tool["name"] for tool in inventory["tools"] if tool["present"]]
        sys.stderr.write("discover_access.py: %d CLI(s) present (%s); %d call(s) made\n" % (len(present), ", ".join(present), len([c for c in calls if c["status"] != "skipped"])))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
