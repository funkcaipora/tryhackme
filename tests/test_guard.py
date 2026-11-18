"""guard.py: only reads pass, and nothing unrecognised slips through."""
import json
import os
import unittest

import _helpers
import guard


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = guard.load_config()

    def klass(self, command, **options):
        return guard.classify(command, self.config, **options)

    def test_built_in_table(self):
        failures, total = guard.self_test()
        self.assertEqual(failures, [])
        self.assertGreater(total, 100)

    def test_only_read_is_allowed_by_default(self):
        self.assertTrue(self.klass("aws sts get-caller-identity")["allowed"])
        for command in ("curl -I https://example.com", "aws iam create-user --user-name x", "rm -rf x",
                        "cat ~/.aws/credentials", "some-unknown-tool --help"):
            self.assertFalse(self.klass(command)["allowed"], command)

    def test_active_needs_the_opt_in(self):
        self.assertFalse(self.klass("curl -I https://example.com")["allowed"])
        self.assertTrue(self.klass("curl -I https://example.com", allow_active=True)["allowed"])
        self.assertFalse(self.klass("aws iam delete-user --user-name x", allow_active=True)["allowed"])

    def test_a_pipeline_takes_its_worst_part(self):
        result = self.klass("aws iam list-users | jq . ; rm -rf x")
        self.assertEqual(result["class"], "destructive")
        self.assertEqual(len(result["parts"]), 3)

    def test_a_flag_value_cannot_pose_as_the_operation(self):
        self.assertEqual(self.klass("aws iam --weird list-users create-user")["class"], "unknown")
        # --profile takes "iam" as its value, so the operation is create-user: refused as a write.
        self.assertEqual(self.klass("aws --profile iam list-users create-user")["class"], "write")
        self.assertEqual(self.klass("aws --no-such-flag iam list-users")["class"], "unknown")
        self.assertEqual(self.klass("gcloud compute instances delete list")["class"], "destructive")

    def test_hidden_commands_are_refused(self):
        for command in ("aws iam list-users $(id)", "aws iam list-users `id`", "bash -c 'aws iam list-users'",
                        "(aws iam list-users)", "aws iam list-users &", "cat <<EOF"):
            self.assertEqual(self.klass(command)["class"], "unknown", command)

    def test_writes_are_allowed_only_inside_the_run_folder(self):
        with _helpers.TempDir() as folder:
            inside = "aws iam list-users > .security-scan/runs/20261118-1000/evidence/00/users.json"
            self.assertEqual(self.klass(inside, cwd=folder)["class"], "read")
            self.assertEqual(self.klass("aws iam list-users > users.json", cwd=folder)["class"], "write")
            self.assertEqual(self.klass("aws iam list-users > ../.security-scan/x.json", cwd=folder)["class"], "write")

    def test_secret_bearing_reads_are_collection(self):
        for command in ("kubectl get secret db -o yaml", "kubectl get pods,secrets -o json", "gh auth token",
                        "aws secretsmanager get-secret-value --secret-id x", "cat .env", "env"):
            self.assertEqual(self.klass(command)["class"], "collection", command)

    def test_check_command(self):
        allowed = _helpers.run_script("guard.py", "check", "--json", "git status")
        self.assertEqual(allowed.returncode, 0)
        self.assertEqual(json.loads(allowed.stdout)["class"], "read")
        refused = _helpers.run_script("guard.py", "check", "git push origin main")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("class: write", refused.stdout)

    def test_hook_stays_out_of_the_way_without_a_run(self):
        with _helpers.TempDir() as folder:
            payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf x"}, "cwd": folder})
            self.assertEqual(_helpers.run_script("guard.py", "hook", stdin=payload).returncode, 0)

    def test_hook_refuses_during_a_run(self):
        with _helpers.TempDir() as folder:
            started = _helpers.run_script("blackboard.py", "init", "--root", folder, "--scope-kind", "repository", "--scope", "x")
            self.assertEqual(started.returncode, 0, started.stderr)
            refuse = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf x"}, "cwd": folder})
            allow = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": folder})
            other = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "x"}, "cwd": folder})
            self.assertEqual(_helpers.run_script("guard.py", "hook", stdin=refuse).returncode, 2)
            self.assertEqual(_helpers.run_script("guard.py", "hook", stdin=allow).returncode, 0)
            self.assertEqual(_helpers.run_script("guard.py", "hook", stdin=other).returncode, 0)

    def test_every_rule_in_the_allowlist_parses(self):
        self.assertGreater(len(self.config["tools"]), 15)
        for name, spec in self.config["tools"].items():
            self.assertTrue(spec["read"] or spec["collection"] or spec["active"], name)
        self.assertTrue(os.path.isfile(guard.ALLOWLIST))


if __name__ == "__main__":
    unittest.main()
