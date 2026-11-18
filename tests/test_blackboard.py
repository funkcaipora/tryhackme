"""blackboard.py: the run's memory accepts only consistent, secret-free entries."""
import json
import os
import shutil
import subprocess
import unittest

import _helpers
import _yamlite


class BlackboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = _helpers.TempDir()
        self.root = self.temp.__enter__()
        started = _helpers.run_script(
            "blackboard.py", "init", "--root", self.root, "--scope-kind", "repository", "--scope", "acme/payments",
            "--include", "acme/payments", "--include", "aws:123456789012", "--language", "pt-BR", "--run-id", "20261118-1000",
        )
        self.assertEqual(started.returncode, 0, started.stderr)
        self.run_dir = os.path.join(self.root, started.stdout.strip())

    def tearDown(self):
        self.temp.__exit__()

    def bb(self, *arguments):
        return _helpers.run_script("blackboard.py", *(list(arguments) + ["--run", self.run_dir]))

    def ok(self, *arguments):
        result = self.bb(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def board(self):
        with open(os.path.join(self.run_dir, "blackboard.json"), encoding="utf-8") as handle:
            return json.load(handle)

    def evidence(self, name="02/key.json", text='{"UserName": "ci", "CreateDate": "2025-10-02"}'):
        _helpers.write(os.path.join(self.run_dir, "evidence", name), text)
        return "evidence/" + name

    def test_init_creates_the_run(self):
        for name in ("engagement.yaml", "blackboard.json", "actions.log", "evidence", "stages", "report"):
            self.assertTrue(os.path.exists(os.path.join(self.run_dir, name)), name)
        engagement = _yamlite.load(os.path.join(self.run_dir, "engagement.yaml"))
        self.assertEqual(engagement["scope"]["includes"], ["acme/payments", "aws:123456789012"])
        self.assertIs(engagement["mode"]["read_only"], True)
        with open(os.path.join(self.root, ".security-scan", "current"), encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), os.path.join(".security-scan", "runs", "20261118-1000"))
        self.assertEqual(self.bb("validate").returncode, 0)

    def test_a_second_run_with_the_same_id_is_refused(self):
        again = _helpers.run_script("blackboard.py", "init", "--root", self.root, "--scope-kind", "team", "--scope", "x", "--run-id", "20261118-1000")
        self.assertEqual(again.returncode, 1)

    def test_nodes_facts_relations_findings(self):
        role = self.ok("add-node", "--kind", "identity", "--name", "ci-deploy role", "--domain", "aws", "--environment", "production")
        store = self.ok("add-node", "--kind", "data-store", "--name", "payments-db", "--domain", "aws", "--crown-jewel")
        self.assertEqual(self.ok("add-node", "--kind", "identity", "--name", "ci-deploy role", "--domain", "aws"), role)
        fact = self.ok("add-fact", "--stage", "2", "--domain", "aws", "--statement", "Key of user ci is 412 days old",
                       "--evidence", self.evidence(), "--about", role)
        self.assertEqual(self.ok("add-fact", "--stage", "2", "--domain", "aws", "--statement", "Key of user ci is 412 days old",
                                 "--evidence", self.evidence()), fact)
        self.ok("link", "--from", role, "--rel", "can-read", "--to", store, "--fact", fact)
        intent = self.ok("add-intent", "--question", "What can the key do?", "--from", fact, "--for-stage", "3")
        self.assertEqual(json.loads(self.ok("next-intent", "--stage", "3"))["id"], intent)
        self.ok("resolve-intent", intent, "--with", fact)
        self.assertEqual(self.bb("next-intent").returncode, 3)
        finding = self.ok(
            "add-finding", "--title", "Old CI key reaches the payments database", "--stage", "2", "--facts", fact,
            "--priority", "P1", "--entry", "exposed-credential", "--reach", "1-2 steps", "--impact", "critical",
            "--visibility", "logged-only", "--fix", "Use pipeline identity federation", "--layer", "2",
            "--condition", "A long-lived key in CI variables", "--gain", "the ci-deploy role", "--leads-to", "3",
            "--attack", "T1552.001",
        )
        board = self.board()
        self.assertEqual([node["id"] for node in board["nodes"]], [role, store])
        self.assertEqual(board["findings"][0]["id"], finding)
        self.assertEqual(board["findings"][0]["evidence"], "confirmed")
        self.assertEqual(self.bb("validate").returncode, 0)
        self.assertIn("P1 1", self.ok("status"))

    def test_a_confirmed_fact_needs_evidence(self):
        refused = self.bb("add-fact", "--stage", "2", "--statement", "x", "--status", "confirmed")
        self.assertEqual(refused.returncode, 1)
        missing = self.bb("add-fact", "--stage", "2", "--statement", "x", "--evidence", "evidence/nope.json")
        self.assertEqual(missing.returncode, 1)
        outside = self.bb("add-fact", "--stage", "2", "--statement", "x", "--evidence", "../../../outside.txt")
        self.assertEqual(outside.returncode, 1)
        self.assertEqual(self.board()["facts"], [])

    def test_secret_values_are_refused(self):
        secret = "password=" + _helpers.fake_password() + "9"
        self.assertEqual(self.bb("add-fact", "--stage", "2", "--statement", "found %s in repo" % secret).returncode, 1)
        self.assertEqual(self.bb("add-node", "--kind", "credential", "--name", "key", "--attr", "value=%s" % _helpers.fake_github_token()).returncode, 1)
        raw = self.evidence("02/raw.txt", "token %s\n" % _helpers.fake_github_token())
        refused = self.bb("add-fact", "--stage", "2", "--statement", "y", "--evidence", raw)
        self.assertEqual(refused.returncode, 1)
        self.assertNotIn(_helpers.fake_github_token(), refused.stdout + refused.stderr)
        self.assertEqual(self.board()["facts"], [])

    def test_a_confirmed_finding_needs_confirmed_facts(self):
        fact = self.ok("add-fact", "--stage", "3", "--statement", "role may read every secret", "--status", "to-validate")
        arguments = ["add-finding", "--title", "z", "--stage", "3", "--facts", fact, "--priority", "P1", "--entry", "low-privilege",
                     "--reach", "direct", "--impact", "significant", "--visibility", "silent", "--fix", "f", "--layer", "2",
                     "--condition", "c", "--gain", "g"]
        self.assertEqual(self.bb(*(arguments + ["--evidence", "confirmed"])).returncode, 1)
        self.ok(*arguments)
        self.assertEqual(self.board()["findings"][0]["evidence"], "to-validate")

    def test_corrections_supersede(self):
        first = self.ok("add-fact", "--stage", "1", "--statement", "bucket is public", "--status", "to-validate")
        second = self.ok("add-fact", "--stage", "1", "--statement", "bucket is private, a policy denies anonymous reads",
                         "--status", "to-validate", "--supersedes", first)
        facts = {fact["id"]: fact for fact in self.board()["facts"]}
        self.assertEqual(facts[first]["status"], "superseded")
        self.assertEqual(facts[second]["supersedes"], first)

    def test_engagement_notes_and_log(self):
        self.ok("engagement", "add", "domains", "aws")
        self.ok("engagement", "set", "report.channel", "artifact")
        self.ok("stage-note", "--stage", "0", "--covered", "one repository", "--gap", "no identity provider access")
        self.ok("coverage", "--part", "AWS organization", "--seen", "partly", "--note", "no organization-level access")
        self.ok("stage-done", "0")
        self.ok("log", "--class", "read", "--stage", "0", "--command", "aws sts get-caller-identity")
        engagement = _yamlite.load(os.path.join(self.run_dir, "engagement.yaml"))
        self.assertEqual(engagement["domains"], ["aws"])
        self.assertEqual(engagement["report"]["channel"], "artifact")
        self.assertEqual(engagement["stages_done"], [0])
        self.assertEqual(self.bb("engagement", "set", "mode.read_only", "false").returncode, 1)
        with open(os.path.join(self.run_dir, "actions.log"), encoding="utf-8") as handle:
            self.assertIn("aws sts get-caller-identity", handle.read())
        board = self.board()
        self.assertEqual(board["coverage"][0]["seen"], "partly")
        self.assertEqual(board["stages"]["0"]["gaps"], ["no identity provider access"])

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_git_is_told_to_ignore_the_run(self):
        with _helpers.TempDir() as repo:
            subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
            first = _helpers.run_script("blackboard.py", "init", "--root", repo, "--scope-kind", "repository", "--scope", "x", "--run-id", "20261118-1001")
            self.assertEqual(first.returncode, 0, first.stderr)
            with open(os.path.join(repo, ".git", "info", "exclude"), encoding="utf-8") as handle:
                self.assertIn(".security-scan/", handle.read())
            second = _helpers.run_script("blackboard.py", "init", "--root", repo, "--scope-kind", "repository", "--scope", "x", "--run-id", "20261118-1002")
            self.assertIn("already ignored", second.stderr)


if __name__ == "__main__":
    unittest.main()
