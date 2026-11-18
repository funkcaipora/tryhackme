#!/usr/bin/env python3
"""Inventory the architecture signals in the repository.

Walks the working directory and reports what it finds: infrastructure code,
CI/CD definitions, container and orchestration manifests, dependency manifests,
configuration and .env files (key names only), AI assistant configuration, git
remotes, ownership files and documentation. The result is the context half of
the stage 0 map.

Usage:
    discover_workspace.py --root . --out <run-dir>/workspace-inventory.json
    discover_workspace.py --summary               short form, for the scope question

Inputs:  the repository files. Respects .gitignore when the folder is a git
         repository, skips dependency and build folders, and reads at most
         512 KB of any file.
Outputs: workspace-inventory.json (stdout when --out is not given)
Safety:  reads files, never executes them. No network. From .env files it
         records the names of the keys, never a value. Files that usually hold
         secrets (keys, state, credentials) are listed by path only.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys

import guard
import redact
from _common import now_iso

MAX_FILES = 20000
MAX_READ = 512 * 1024
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".terraform",
    ".next", ".nuxt", "target", "vendor", ".security-scan", ".idea", ".gradle", ".tox",
    ".mypy_cache", ".pytest_cache", ".cache", "Pods", ".turbo", ".svelte-kit", "coverage",
}
LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".swift": "Swift", ".c": "C", ".cc": "C++", ".cpp": "C++", ".sh": "Shell",
    ".tf": "Terraform", ".sql": "SQL", ".scala": "Scala", ".ex": "Elixir", ".dart": "Dart",
}
MANIFESTS = {
    "package.json": "node", "requirements.txt": "python", "pyproject.toml": "python", "Pipfile": "python",
    "setup.py": "python", "go.mod": "go", "Cargo.toml": "rust", "pom.xml": "java", "build.gradle": "java",
    "build.gradle.kts": "java", "Gemfile": "ruby", "composer.json": "php", "mix.exs": "elixir",
    "pubspec.yaml": "dart",
}
FRAMEWORKS = [
    (r"\bnext\b", "Next.js"), (r"\breact\b", "React"), (r"\bvue\b", "Vue"), (r"\bsvelte\b", "Svelte"),
    (r"\bexpress\b", "Express"), (r"\bfastify\b", "Fastify"), (r"@nestjs/core", "NestJS"), (r"\bhono\b", "Hono"),
    (r"\bdjango\b", "Django"), (r"\bflask\b", "Flask"), (r"\bfastapi\b", "FastAPI"), (r"\brails\b", "Rails"),
    (r"laravel/framework", "Laravel"), (r"spring-boot", "Spring Boot"), (r"\bgin-gonic/gin\b", "Gin"),
]
DATA_HINTS = [
    (r"\bprisma\b", "Prisma"), (r"\bsequelize\b", "Sequelize"), (r"\btypeorm\b", "TypeORM"), (r"\bknex\b", "Knex"),
    (r"\bdrizzle-orm\b", "Drizzle"), (r"\bmongoose\b", "Mongoose"), (r"\bsqlalchemy\b", "SQLAlchemy"),
    (r"\bpsycopg", "PostgreSQL driver"), (r"\bpg\b", "PostgreSQL driver"), (r"\bmysql2?\b", "MySQL driver"),
    (r"\bredis\b", "Redis client"), (r"@supabase/supabase-js", "Supabase client"), (r"\bfirebase(-admin)?\b", "Firebase"),
]
# dependency or provider name -> domain playbook
DOMAIN_HINTS = [
    (r"aws-sdk|@aws-sdk/|\bboto3\b|\bbotocore\b|hashicorp/aws|aws-cdk", "aws"),
    (r"@google-cloud/|google-cloud-|hashicorp/google|firebase", "gcp"),
    (r"@azure/|azure-|hashicorp/azurerm|hashicorp/azuread|msal", "azure-entra-m365"),
    (r"kubernetes|hashicorp/helm|@kubernetes/client-node", "kubernetes-containers"),
    (r"\bopenai\b|anthropic|langchain|litellm|\bollama\b|llamaindex|llama-index|@ai-sdk/|\bvercel/ai\b", "ai-llm-infrastructure"),
    (r"cloudflare|wrangler|@vercel/|netlify|@supabase/|supabase", "edge-paas"),
]
CI_FILES = {
    ".gitlab-ci.yml": "GitLab CI", "Jenkinsfile": "Jenkins", ".circleci/config.yml": "CircleCI",
    "azure-pipelines.yml": "Azure Pipelines", "bitbucket-pipelines.yml": "Bitbucket Pipelines",
    "cloudbuild.yaml": "Cloud Build", ".drone.yml": "Drone", ".travis.yml": "Travis CI",
    ".buildkite/pipeline.yml": "Buildkite",
}
PLATFORM_FILES = {
    "vercel.json": "Vercel", "netlify.toml": "Netlify", "wrangler.toml": "Cloudflare Workers",
    "wrangler.json": "Cloudflare Workers", "wrangler.jsonc": "Cloudflare Workers", "fly.toml": "Fly.io",
    "render.yaml": "Render", "app.yaml": "App Engine", "firebase.json": "Firebase", ".firebaserc": "Firebase",
    "supabase/config.toml": "Supabase", "amplify.yml": "AWS Amplify", "Procfile": "Heroku-style process file",
    "heroku.yml": "Heroku", "railway.json": "Railway", "serverless.yml": "Serverless Framework",
    "serverless.yaml": "Serverless Framework", "cdk.json": "AWS CDK", "Pulumi.yaml": "Pulumi",
}
SENSITIVE_PATTERNS = [
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa", "id_ed25519", "id_ecdsa",
    "*.tfstate", "*.tfstate.backup", "*.tfvars", "credentials.json", "service-account*.json",
    "*.kdbx", ".npmrc", ".netrc", ".htpasswd", "secrets.yml", "secrets.yaml", ".pypirc",
]
AGENT_FILES = [
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", "CLAUDE.md", "AGENTS.md",
    ".cursorrules", ".windsurfrules", ".github/copilot-instructions.md", ".claude-plugin/plugin.json",
    "hooks/hooks.json", ".cursor/mcp.json",
]
EXAMPLE_ENV = re.compile(r"\.(example|sample|template|dist|defaults)$")
ENV_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def git(root, *arguments):
    """Run a read-only git command. Returns stdout, or None when it fails or is not a read."""
    command = ["git", "-C", root] + list(arguments)
    if guard.classify(" ".join(["git"] + list(arguments)))["class"] != "read":
        return None
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def list_files(root):
    """Relative paths of the files to look at, and the set that git tracks."""
    tracked = None
    listing = git(root, "ls-files", "-z")
    if listing is not None:
        tracked = set(path for path in listing.split("\0") if path)
        others = git(root, "ls-files", "-o", "--exclude-standard", "-z") or ""
        candidates = sorted(tracked | set(path for path in others.split("\0") if path))
    else:
        candidates = []
        for folder, dirs, names in os.walk(root):
            dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
            for name in sorted(names):
                candidates.append(os.path.relpath(os.path.join(folder, name), root))
    files = []
    for path in candidates:
        parts = path.replace(os.sep, "/").split("/")
        if any(part in SKIP_DIRS for part in parts[:-1]):
            continue
        files.append("/".join(parts))
        if len(files) >= MAX_FILES:
            break
    return files, tracked


def read_text(root, path, limit=MAX_READ):
    try:
        with open(os.path.join(root, path), "rb") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    if b"\x00" in data[:2048]:
        return ""
    return data.decode("utf-8", "replace")


def parse_remote(url):
    match = re.match(r"^(?:[a-z+]+://)?(?:[^@/]+@)?([^:/]+)[:/](.+?)(?:\.git)?/?$", url.strip())
    if not match:
        return None
    parts = match.group(2).split("/")
    return {"host": match.group(1), "owner": "/".join(parts[:-1]), "name": parts[-1]}


def git_facts(root, tracked):
    if tracked is None:
        return {"is_repository": False}
    facts = {"is_repository": True, "tracked_files": len(tracked)}
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
    if branch:
        facts["branch"] = branch.strip()
    remotes = {}
    for line in (git(root, "remote", "-v") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] not in remotes:
            parsed = parse_remote(parts[1])
            if parsed:
                remotes[parts[0]] = parsed
    facts["remotes"] = remotes
    return facts


def env_file(root, path, tracked):
    names = []
    has_values = False
    for line in read_text(root, path).splitlines():
        match = ENV_KEY.match(line)
        if match:
            names.append(match.group(1))
            if match.group(2).strip().strip("\"'"):
                has_values = True
    return {
        "path": path,
        "example": bool(EXAMPLE_ENV.search(path)),
        "tracked_by_git": None if tracked is None else path in tracked,
        "keys": sorted(set(names)),
        "has_values": has_values,
    }


def workflow(root, path):
    text = read_text(root, path)
    name = re.search(r"(?m)^name:\s*(.+)$", text)
    uses = re.findall(r"uses:\s*([^\s@#]+)@([^\s#]+)", text)
    third_party = [(action, ref) for action, ref in uses if not action.startswith(("actions/", "./", "github/"))]
    return {
        "path": path,
        "name": name.group(1).strip().strip("\"'") if name else None,
        "pull_request_target": "pull_request_target" in text,
        "declares_permissions": bool(re.search(r"(?m)^\s*permissions:", text)),
        "oidc_token": bool(re.search(r"id-token:\s*write", text)),
        "self_hosted_runner": "self-hosted" in text,
        "secret_names": sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))),
        "third_party_actions": len(third_party),
        "third_party_actions_not_pinned_to_commit": sum(1 for _, ref in third_party if not re.match(r"^[0-9a-f]{40}$", ref)),
    }


def terraform(root, paths):
    providers, resources, backends = set(), {}, set()
    for path in paths:
        text = read_text(root, path)
        providers.update(re.findall(r'(?m)^\s*provider\s+"([a-z0-9_\-]+)"', text))
        providers.update(source.split("/")[-1] for source in re.findall(r'source\s*=\s*"([a-z0-9_\-]+/[a-z0-9_\-]+)"', text))
        backends.update(re.findall(r'backend\s+"([a-z0-9_]+)"', text))
        for kind in re.findall(r'(?m)^\s*resource\s+"([a-z0-9_]+)"', text):
            resources[kind] = resources.get(kind, 0) + 1
    top = sorted(resources.items(), key=lambda item: (-item[1], item[0]))[:20]
    return {"files": len(paths), "providers": sorted(providers), "backends": sorted(backends), "resource_types": dict(top)}


def dockerfile(root, path):
    text = read_text(root, path)
    return {
        "path": path,
        "base_images": re.findall(r"(?mi)^FROM\s+(?:--platform=\S+\s+)?(\S+)", text)[:6],
        "sets_user": bool(re.search(r"(?mi)^USER\s+\S+", text)),
        "exposes": re.findall(r"(?mi)^EXPOSE\s+(.+)$", text)[:6],
    }


def compose(root, path):
    text = read_text(root, path)
    services = []
    inside = False
    for line in text.splitlines():
        if re.match(r"^services:\s*$", line):
            inside = True
            continue
        if inside:
            if re.match(r"^\S", line):
                inside = False
                continue
            match = re.match(r"^ {2}([A-Za-z0-9_.\-]+):\s*$", line)
            if match:
                services.append(match.group(1))
    return {"path": path, "services": services, "published_ports": sorted(set(re.findall(r"-\s*[\"']?(?:[0-9.]+:)?([0-9]+):[0-9]+", text)))[:20]}


def kubernetes_kinds(root, path):
    head = read_text(root, path, 64 * 1024)
    if "apiVersion:" not in head or "kind:" not in head:
        return []
    return re.findall(r"(?m)^kind:\s*([A-Za-z]+)", head)


def is_cloudformation(root, path):
    head = read_text(root, path, 8 * 1024)
    return "AWSTemplateFormatVersion" in head or "AWS::Serverless" in head


def owners(root, files):
    found = set()
    sources = []
    for path in files:
        base = path.split("/")[-1]
        if base == "CODEOWNERS":
            sources.append(path)
            for line in read_text(root, path).splitlines():
                if not line.strip().startswith("#"):
                    found.update(re.findall(r"(?<!\S)(@[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)?)", line))
        elif base in ("catalog-info.yaml", "catalog-info.yml"):
            sources.append(path)
            found.update(re.findall(r"(?m)^\s*owner:\s*[\"']?([^\s\"'#]+)", read_text(root, path)))
    return {"sources": sources, "owners": sorted(found)[:50]}


def agent_configs(root, files):
    found = []
    present = set(files)
    for path in AGENT_FILES:
        if path in present:
            entry = {"path": path}
            if path.endswith("settings.json") or path.endswith("settings.local.json"):
                data = _load_json(root, path)
                if isinstance(data, dict):
                    if isinstance(data.get("hooks"), dict):
                        entry["hook_events"] = sorted(data["hooks"])
                    allow = (data.get("permissions") or {}).get("allow") if isinstance(data.get("permissions"), dict) else None
                    if isinstance(allow, list):
                        entry["permission_allow_rules"] = len(allow)
            if path.endswith("mcp.json"):
                data = _load_json(root, path)
                if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
                    entry["connectors"] = sorted(data["mcpServers"])
            found.append(entry)
    skills = sorted(path for path in files if path.endswith("/SKILL.md") or path == "SKILL.md")
    if skills:
        found.append({"path": "skills", "skill_files": skills[:30]})
    return found


def _load_json(root, path):
    try:
        return json.loads(read_text(root, path))
    except ValueError:
        return None


def package_json(root, path):
    data = _load_json(root, path)
    if not isinstance(data, dict):
        return {"path": path, "ecosystem": "node"}
    dependencies = {}
    for key in ("dependencies", "devDependencies"):
        if isinstance(data.get(key), dict):
            dependencies.update(data[key])
    entry = {"path": path, "ecosystem": "node", "dependencies": len(dependencies)}
    if isinstance(data.get("name"), str):
        entry["name"] = data["name"]
    if data.get("workspaces"):
        entry["workspaces"] = True
    if isinstance(data.get("scripts"), dict):
        entry["scripts"] = sorted(data["scripts"])[:30]
    entry["_dependency_names"] = " ".join(sorted(dependencies))
    return entry


def build(root):
    files, tracked = list_files(root)
    present = set(files)
    inventory = {"generated_at": now_iso(), "root": ".", "files_seen": len(files), "git": git_facts(root, tracked)}

    languages = {}
    manifests, workflows, dockerfiles, composes, env_files, sensitive, docs = [], [], [], [], [], [], []
    terraform_files, kube_kinds, cloudformation, helm_charts, kustomize = [], {}, [], [], []
    ci_systems, platforms = set(), {}
    dependency_text = []

    for path in files:
        base = path.split("/")[-1]
        extension = os.path.splitext(base)[1].lower()
        if extension in LANGUAGES:
            languages[LANGUAGES[extension]] = languages.get(LANGUAGES[extension], 0) + 1

        if base in MANIFESTS or extension == ".csproj" or re.match(r"^requirements.*\.txt$", base):
            if base == "package.json":
                entry = package_json(root, path)
                dependency_text.append(entry.pop("_dependency_names", ""))
            else:
                entry = {"path": path, "ecosystem": MANIFESTS.get(base, "dotnet" if extension == ".csproj" else "python")}
                dependency_text.append(read_text(root, path, 64 * 1024).lower())
            manifests.append(entry)

        if path.startswith(".github/workflows/") and extension in (".yml", ".yaml"):
            workflows.append(workflow(root, path))
            ci_systems.add("GitHub Actions")
        for name, system in CI_FILES.items():
            if path == name or path.endswith("/" + name):
                ci_systems.add(system)
        for name, platform in PLATFORM_FILES.items():
            if path == name or path.endswith("/" + name):
                platforms.setdefault(platform, []).append(path)

        if extension == ".tf":
            terraform_files.append(path)
        if base == "Chart.yaml":
            helm_charts.append(path)
        if base in ("kustomization.yaml", "kustomization.yml"):
            kustomize.append(path)
        if base == "Dockerfile" or base.startswith("Dockerfile.") or extension == ".dockerfile":
            dockerfiles.append(dockerfile(root, path))
        if re.match(r"^(docker-)?compose.*\.ya?ml$", base):
            composes.append(compose(root, path))
        elif extension in (".yml", ".yaml") and not path.startswith(".github/"):
            for kind in kubernetes_kinds(root, path):
                kube_kinds[kind] = kube_kinds.get(kind, 0) + 1
            if base.startswith("template") and is_cloudformation(root, path):
                cloudformation.append(path)
        if extension == ".json" and base.startswith("template") and is_cloudformation(root, path):
            cloudformation.append(path)
        if extension == ".bicep":
            platforms.setdefault("Azure Bicep", []).append(path)

        if base == ".env" or base.startswith(".env."):
            env_files.append(env_file(root, path, tracked))
        if any(fnmatch.fnmatchcase(base, pattern) for pattern in SENSITIVE_PATTERNS):
            sensitive.append({"path": path, "tracked_by_git": None if tracked is None else path in tracked})
        if re.match(r"(?i)^(readme|architecture|security|contributing)(\.[a-z]+)?$", base) or (
            path.startswith("docs/") and extension == ".md"
        ):
            docs.append(path)

    dependency_blob = " ".join(dependency_text)
    terraform_facts = terraform(root, terraform_files) if terraform_files else None
    hint_blob = dependency_blob + " " + " ".join("hashicorp/" + name for name in (terraform_facts or {}).get("providers", []))
    hint_blob += " " + " ".join(platforms).lower()

    domains = {"workstation-dev-env"}
    if inventory["git"].get("is_repository") or ci_systems:
        domains.add("source-control-cicd")
    for pattern, domain in DOMAIN_HINTS:
        if re.search(pattern, hint_blob, re.I):
            domains.add(domain)
    if cloudformation or any(name in platforms for name in ("AWS CDK", "AWS Amplify", "Serverless Framework")):
        domains.add("aws")
    if kube_kinds or helm_charts or kustomize or dockerfiles or composes:
        domains.add("kubernetes-containers")
    frameworks = sorted({label for pattern, label in FRAMEWORKS if re.search(pattern, dependency_blob, re.I)})
    data = sorted({label for pattern, label in DATA_HINTS if re.search(pattern, dependency_blob, re.I)})
    if frameworks or data:
        domains.add("web-app-database")
    if any(name in platforms for name in ("Vercel", "Netlify", "Cloudflare Workers", "Fly.io", "Render", "Firebase", "Supabase", "Railway")):
        domains.add("edge-paas")
    agents = agent_configs(root, files)
    if agents:
        domains.add("ai-llm-infrastructure")

    manifest_folders = {m["path"].rsplit("/", 1)[0] if "/" in m["path"] else "." for m in manifests}
    code_files = sum(languages.values()) or 1
    if ".claude-plugin/plugin.json" in present:
        shape = "plugin"
    elif len(manifest_folders) >= 2:
        shape = "monorepo"
    elif (terraform_files or cloudformation or kube_kinds) and languages.get("Terraform", 0) + len(cloudformation) >= code_files / 2.0:
        shape = "infrastructure"
    elif manifests:
        shape = "single-service"
    else:
        shape = "unknown"

    inventory.update(
        {
            "shape": shape,
            "languages": dict(sorted(languages.items(), key=lambda item: (-item[1], item[0]))[:8]),
            "manifests": manifests,
            "frameworks": frameworks,
            "data_access": data,
            "infrastructure_as_code": {
                "terraform": terraform_facts,
                "cloudformation": cloudformation,
                "helm_charts": helm_charts,
                "kustomize": kustomize,
                "kubernetes_kinds": dict(sorted(kube_kinds.items())),
            },
            "containers": {"dockerfiles": dockerfiles, "compose": composes},
            "ci_cd": {"systems": sorted(ci_systems), "github_workflows": workflows},
            "platforms": {name: paths[:5] for name, paths in sorted(platforms.items())},
            "env_files": env_files,
            "sensitive_files": sensitive,
            "agent_configs": agents,
            "ownership": owners(root, files),
            "docs": docs[:40],
            "domains_hint": sorted(domains),
        }
    )
    return inventory


def summary(inventory):
    """The few facts the scope question needs."""
    remote = (inventory["git"].get("remotes") or {}).get("origin") or next(iter((inventory["git"].get("remotes") or {}).values()), None)
    return {
        "repository": remote,
        "branch": inventory["git"].get("branch"),
        "shape": inventory["shape"],
        "languages": list(inventory["languages"])[:3],
        "frameworks": inventory["frameworks"],
        "infrastructure_as_code": [
            name for name, value in inventory["infrastructure_as_code"].items() if value
        ],
        "ci_cd": inventory["ci_cd"]["systems"],
        "platforms": list(inventory["platforms"]),
        "owners": inventory["ownership"]["owners"][:10],
        "manifest_folders": sorted({m["path"].rsplit("/", 1)[0] if "/" in m["path"] else "." for m in inventory["manifests"]})[:12],
        "domains_hint": inventory["domains_hint"],
    }


def main(argv):
    parser = argparse.ArgumentParser(description="Inventory the architecture signals in the repository.")
    parser.add_argument("--root", default=".", help="folder to walk")
    parser.add_argument("--out", help="write the inventory here instead of stdout")
    parser.add_argument("--summary", action="store_true", help="print only what the scope question needs")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.stderr.write("discover_workspace.py: no folder at %s\n" % args.root)
        return 1
    inventory = build(root)
    result = summary(inventory) if args.summary else inventory
    text = json.dumps(redact.redact_json(result), indent=2, ensure_ascii=False) + "\n"
    if redact.scan(text):
        sys.stderr.write("discover_workspace.py: the inventory still looks like it holds a secret; nothing was written\n")
        return 1
    if args.out:
        folder = os.path.dirname(os.path.abspath(args.out))
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        sys.stderr.write(
            "discover_workspace.py: %d file(s) seen, shape %s, domains: %s\n"
            % (inventory["files_seen"], inventory["shape"], ", ".join(inventory["domains_hint"]))
        )
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
