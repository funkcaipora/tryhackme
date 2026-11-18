"""discover_access.py and discover_workspace.py: they see the shape of things, never the secrets."""
import json
import os
import shutil
import subprocess
import unittest

import _helpers


def build_home(home):
    """A home folder full of fake credentials."""
    _helpers.write(os.path.join(home, ".aws", "credentials"),
                   "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n" % (_helpers.fake_aws_key(), "x" * 40))
    os.chmod(os.path.join(home, ".aws", "credentials"), 0o644)
    _helpers.write(os.path.join(home, ".ssh", "id_ed25519"), "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nAAAA\n-----END OPENSSH " + "PRIVATE KEY-----\n")
    os.chmod(os.path.join(home, ".ssh", "id_ed25519"), 0o600)
    _helpers.write(os.path.join(home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 AAAA test\n")
    _helpers.write(os.path.join(home, ".ssh", "config"), "Host bastion\n  HostName bastion.example.com\n  ForwardAgent yes\nHost db-*\n  ProxyJump bastion\n")
    _helpers.write(os.path.join(home, ".kube", "config"), "apiVersion: v1\n")
    _helpers.write(os.path.join(home, ".claude.json"),
                   json.dumps({"mcpServers": {"cloudflare": {"env": {"API_TOKEN": _helpers.fake_github_token()}}, "github": {}}}))
    _helpers.write(os.path.join(home, ".claude", "settings.json"), json.dumps({"hooks": {"PreToolUse": [], "Stop": []}}))


def build_repository(root):
    """A small repository with one of everything, and fake secrets in the usual places."""
    _helpers.write(os.path.join(root, "infra", "main.tf"),
                   'terraform {\n  backend "s3" {}\n  required_providers { aws = { source = "hashicorp/aws" } }\n}\n'
                   'provider "aws" {}\nresource "aws_s3_bucket" "data" {}\nresource "aws_iam_role" "deploy" {}\n')
    _helpers.write(os.path.join(root, "infra", "terraform.tfstate"), '{"version": 4}\n')
    _helpers.write(os.path.join(root, ".github", "workflows", "deploy.yml"),
                   "name: Deploy\non:\n  pull_request_target:\npermissions:\n  id-token: write\njobs:\n  deploy:\n    runs-on: self-hosted\n"
                   "    steps:\n      - uses: actions/checkout@v4\n      - uses: some-org/deploy-action@main\n"
                   "      - run: echo ${{ secrets.AWS_DEPLOY_KEY }}\n")
    _helpers.write(os.path.join(root, "apps", "api", "Dockerfile"), "FROM node:20-alpine\nEXPOSE 3000\n")
    _helpers.write(os.path.join(root, "apps", "api", "package.json"),
                   json.dumps({"name": "api", "dependencies": {"express": "4", "prisma": "5", "@aws-sdk/client-s3": "3", "openai": "4"}}))
    _helpers.write(os.path.join(root, "apps", "web", "package.json"), json.dumps({"name": "web", "dependencies": {"next": "15"}}))
    _helpers.write(os.path.join(root, "k8s", "api.yaml"), "apiVersion: apps/v1\nkind: Deployment\n")
    _helpers.write(os.path.join(root, ".env"),
                   "DATABASE_URL=postgres://app:%s@db.internal/app\nOPENAI_API_KEY=%s\n" % (_helpers.fake_password(), "sk-" + "live" + "-9f8e7d6c5b4a3210ffeeddcc"))
    _helpers.write(os.path.join(root, ".env.example"), "DATABASE_URL=\nOPENAI_API_KEY=\n")
    _helpers.write(os.path.join(root, "CODEOWNERS"), "* @acme/platform\n/apps/api/ @acme/payments\n")
    _helpers.write(os.path.join(root, ".mcp.json"), json.dumps({"mcpServers": {"prod-db": {"env": {"PGPASSWORD": _helpers.fake_password()}}}}))
    _helpers.write(os.path.join(root, "node_modules", "x", "package.json"), "{}")
    _helpers.write(os.path.join(root, "server.pem"), "fake\n")


class AccessTests(unittest.TestCase):
    def test_only_metadata_leaves_the_home_folder(self):
        with _helpers.TempDir() as home:
            build_home(home)
            project = os.path.join(home, "project")
            _helpers.write(os.path.join(project, ".mcp.json"), json.dumps({"mcpServers": {"internal-db": {}}}))
            connectors = os.path.join(home, "connectors.json")
            _helpers.write(connectors, json.dumps([{"name": "Cloudflare", "tools": ["workers_list"], "note": "token=" + _helpers.fake_password() + "9"}]))
            out = os.path.join(home, "inventory.json")
            result = _helpers.run_script(
                "discover_access.py", "--no-cli-calls", "--root", project, "--connectors", connectors, "--out", out,
                env={"HOME": home, "MY_SERVICE_TOKEN": _helpers.fake_github_token()},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out, encoding="utf-8") as handle:
                text = handle.read()
            inventory = json.loads(text)
            for secret in (_helpers.fake_aws_key(), _helpers.fake_github_token(), _helpers.fake_password(), "AAAA"):
                self.assertNotIn(secret, text)
            self.assertEqual(inventory["calls"], [])
            files = {entry["path"]: entry for entry in inventory["credential_files"]}
            self.assertTrue(files["~/.aws/credentials"]["group_or_world_readable"])
            self.assertEqual(files["~/.aws/credentials"]["type"], "aws-shared-credentials")
            self.assertIn("MY_SERVICE_TOKEN", inventory["environment"]["secret_like_names"])
            self.assertEqual(inventory["ssh"]["private_keys"][0]["mode"], "0600")
            self.assertEqual([host["host"] for host in inventory["ssh"]["config_hosts"]], ["bastion"])
            self.assertTrue(inventory["ssh"]["config_hosts"][0]["forward_agent"])
            by_path = {entry["path"]: entry for entry in inventory["agent_configs"]}
            self.assertEqual(by_path["~/.claude.json"]["connectors"], ["cloudflare", "github"])
            self.assertEqual(by_path[".mcp.json"]["connectors"], ["internal-db"])
            self.assertEqual(by_path["~/.claude/settings.json"]["hook_events"], ["PreToolUse", "Stop"])
            self.assertIn("[redacted:", inventory["connectors"][0]["note"])

    def test_identities_only_is_small(self):
        with _helpers.TempDir() as home:
            result = _helpers.run_script("discover_access.py", "--identities-only", "--no-cli-calls", env={"HOME": home})
            self.assertEqual(result.returncode, 0, result.stderr)
            inventory = json.loads(result.stdout)
            self.assertEqual(inventory["mode"], "identities-only")
            self.assertNotIn("credential_files", inventory)
            self.assertIn("tools", inventory)

    def test_every_identity_command_is_a_read(self):
        import discover_access
        import guard
        config = guard.load_config()
        for name, _domain, commands in discover_access.TOOLS:
            for command in commands:
                self.assertEqual(guard.classify(" ".join(command), config)["class"], "read", " ".join(command))


class WorkspaceTests(unittest.TestCase):
    def inventory(self, root, *extra):
        result = _helpers.run_script("discover_workspace.py", "--root", root, *extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout, json.loads(result.stdout)

    def check(self, text, inventory, tracked):
        for secret in (_helpers.fake_password(), "9f8e7d6c5b4a3210"):
            self.assertNotIn(secret, text)
        self.assertEqual(inventory["shape"], "monorepo")
        self.assertEqual(inventory["infrastructure_as_code"]["terraform"]["providers"], ["aws"])
        self.assertEqual(inventory["infrastructure_as_code"]["terraform"]["backends"], ["s3"])
        self.assertEqual(inventory["infrastructure_as_code"]["kubernetes_kinds"], {"Deployment": 1})
        workflow = inventory["ci_cd"]["github_workflows"][0]
        self.assertTrue(workflow["pull_request_target"] and workflow["oidc_token"] and workflow["self_hosted_runner"])
        self.assertEqual(workflow["secret_names"], ["AWS_DEPLOY_KEY"])
        self.assertEqual(workflow["third_party_actions_not_pinned_to_commit"], 1)
        env = {entry["path"]: entry for entry in inventory["env_files"]}
        self.assertEqual(env[".env"]["keys"], ["DATABASE_URL", "OPENAI_API_KEY"])
        self.assertTrue(env[".env"]["has_values"])
        self.assertFalse(env[".env.example"]["has_values"])
        self.assertEqual(env[".env"]["tracked_by_git"], tracked)
        self.assertEqual(sorted(entry["path"] for entry in inventory["sensitive_files"]), ["infra/terraform.tfstate", "server.pem"])
        self.assertEqual(inventory["ownership"]["owners"], ["@acme/payments", "@acme/platform"])
        self.assertEqual(inventory["agent_configs"][0]["connectors"], ["prod-db"])
        self.assertFalse(any("node_modules" in manifest["path"] for manifest in inventory["manifests"]))
        for domain in ("aws", "kubernetes-containers", "web-app-database", "ai-llm-infrastructure", "workstation-dev-env"):
            self.assertIn(domain, inventory["domains_hint"])

    def test_plain_folder(self):
        with _helpers.TempDir() as root:
            build_repository(root)
            text, inventory = self.inventory(root)
            self.assertFalse(inventory["git"]["is_repository"])
            self.check(text, inventory, tracked=None)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_git_repository(self):
        with _helpers.TempDir() as root:
            build_repository(root)
            _helpers.write(os.path.join(root, ".gitignore"), "node_modules/\n")
            subprocess.run(["git", "-C", root, "init", "-q"], check=True)
            remote = "https://user:" + "t0ken" + "@github.com/acme/payments.git"
            subprocess.run(["git", "-C", root, "remote", "add", "origin", remote], check=True)
            subprocess.run(["git", "-C", root, "add", "-A"], check=True, capture_output=True)
            text, inventory = self.inventory(root)
            self.assertNotIn("t0ken", text)
            self.assertEqual(inventory["git"]["remotes"]["origin"], {"host": "github.com", "owner": "acme", "name": "payments"})
            self.check(text, inventory, tracked=True)
            _text, summary = self.inventory(root, "--summary")
            self.assertEqual(summary["repository"]["name"], "payments")
            self.assertEqual(summary["owners"], ["@acme/payments", "@acme/platform"])


if __name__ == "__main__":
    unittest.main()
