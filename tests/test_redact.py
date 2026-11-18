"""redact.py: secrets never survive, non-secrets are left alone."""
import json
import os
import unittest

import _helpers
import redact


class RedactTests(unittest.TestCase):
    def test_built_in_cases(self):
        self.assertEqual(redact.self_test(), [])

    def test_text_is_redacted_and_stable(self):
        key, token = _helpers.fake_aws_key(), _helpers.fake_github_token()
        text = "export GITHUB_TOKEN=%s\nkey %s\n" % (token, key)
        cleaned = redact.redact(text)
        self.assertNotIn(token, cleaned)
        self.assertNotIn(key, cleaned)
        self.assertEqual(redact.redact(cleaned), cleaned)
        self.assertEqual(redact.scan(cleaned), [])

    def test_same_secret_same_fingerprint(self):
        key = _helpers.fake_aws_key()
        first = redact.MARKER.search(redact.redact("in repo: " + key)).group(0)
        second = redact.MARKER.search(redact.redact("in pipeline: " + key)).group(0)
        self.assertEqual(first, second)

    def test_json_is_walked_by_key(self):
        data = {"ClientSecret": "hunter" + "two", "SecretName": "prod/db", "PasswordLastUsed": "2026-01-02",
                "nested": [{"db_password": _helpers.fake_password()}]}
        cleaned = json.loads(redact.redact(json.dumps(data)))
        self.assertTrue(redact.MARKER.fullmatch(cleaned["ClientSecret"]))
        self.assertTrue(redact.MARKER.fullmatch(cleaned["nested"][0]["db_password"]))
        self.assertEqual(cleaned["SecretName"], "prod/db")
        self.assertEqual(cleaned["PasswordLastUsed"], "2026-01-02")

    def test_leaves_descriptions_and_references_alone(self):
        for text in ("password_policy: required", "token_type: Bearer", "DB_PASSWORD=${DB_PASSWORD}",
                     "api_key_path: /etc/app/key", "secret_arn: arn:aws:secretsmanager:us-east-1:1:secret:x"):
            self.assertEqual(redact.redact_text(text), text)

    def test_url_password_and_header(self):
        password = _helpers.fake_password()
        cleaned = redact.redact("postgres://app:%s@db.internal:5432/x\nAuthorization: Bearer %s" % (password, "abcDEF123456" + "ghiJKL"))
        self.assertNotIn(password, cleaned)
        self.assertIn("postgres://app:[redacted:url-password:", cleaned)
        self.assertIn("@db.internal", cleaned)

    def test_check_mode_reports_location_not_value(self):
        token = _helpers.fake_github_token()
        with _helpers.TempDir() as folder:
            _helpers.write(os.path.join(folder, "leak.txt"), "first line\ntoken %s\n" % token)
            _helpers.write(os.path.join(folder, "clean.txt"), "nothing here\n")
            result = _helpers.run_script("redact.py", "--check", folder)
            self.assertEqual(result.returncode, 1)
            self.assertIn("leak.txt:2: github-token", result.stdout)
            self.assertNotIn(token, result.stdout + result.stderr)
            fixed = _helpers.run_script("redact.py", "--in", os.path.join(folder, "leak.txt"), "--out", os.path.join(folder, "leak.txt"))
            self.assertEqual(fixed.returncode, 0)
            self.assertEqual(_helpers.run_script("redact.py", "--check", folder).returncode, 0)

    def test_filter_mode(self):
        result = _helpers.run_script("redact.py", stdin="DB_PASSWORD=%s\nuser: alice\n" % (_helpers.fake_password() + "9"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("user: alice", result.stdout)
        self.assertIn("[redacted:named-secret:", result.stdout)


if __name__ == "__main__":
    unittest.main()
