"""render_report.py: every stage report has its three parts, and no secret reaches a report."""
import json
import os
import re
import unittest

import _helpers


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = _helpers.TempDir()
        self.root = self.temp.__enter__()
        started = _helpers.run_script(
            "blackboard.py", "init", "--root", self.root, "--scope-kind", "repository", "--scope", "acme/payments",
            "--language", "pt-BR", "--run-id", "20261118-1000",
        )
        self.assertEqual(started.returncode, 0, started.stderr)
        self.run_dir = os.path.join(self.root, started.stdout.strip())
        role = self.bb("add-node", "--kind", "identity", "--name", "ci-deploy role", "--domain", "aws", "--environment", "production")
        store = self.bb("add-node", "--kind", "data-store", "--name", "payments-db", "--domain", "aws", "--crown-jewel", "--internet-facing")
        _helpers.write(os.path.join(self.run_dir, "evidence", "00", "role.json"), '{"RoleName": "ci-deploy"}\n')
        fact = self.bb("add-fact", "--stage", "0", "--domain", "aws", "--statement", "ci-deploy can read payments-db",
                       "--evidence", "evidence/00/role.json", "--about", role)
        self.bb("add-fact", "--stage", "0", "--statement", "Workflow passes ${{ secrets.DEPLOY }} to a third-party action", "--status", "to-validate")
        self.bb("link", "--from", role, "--rel", "can-read", "--to", store, "--fact", fact)
        self.bb("add-intent", "--question", "Is payments-db reachable from the internet?", "--from", fact, "--for-stage", "1")
        self.bb("add-finding", "--title", "CI role reads the payments database", "--stage", "0", "--facts", fact,
                "--priority", "P1", "--entry", "low-privilege", "--reach", "direct", "--impact", "critical",
                "--visibility", "silent", "--fix", "Scope the role to the tables the pipeline needs", "--layer", "2",
                "--interim", "Alert on reads by this role", "--condition", "A pipeline role with broad database access",
                "--gain", "customer payment data", "--leads-to", "8", "--attack", "T1530")
        self.bb("coverage", "--part", "AWS organization", "--seen", "partly", "--note", "no organization-level access")
        self.bb("stage-note", "--stage", "0", "--covered", "one repository", "--next", "what is exposed")
        self.bb("stage-done", "0")

    def tearDown(self):
        self.temp.__exit__()

    def bb(self, *arguments):
        result = _helpers.run_script("blackboard.py", *(list(arguments) + ["--run", self.run_dir]))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def render(self, *arguments):
        return _helpers.run_script("render_report.py", *(list(arguments) + ["--run", self.run_dir]))

    def read(self, *parts):
        with open(os.path.join(self.run_dir, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_stage_report_has_three_parts_in_the_user_language(self):
        self.assertEqual(self.render("--stage", "0").returncode, 0)
        report = self.read("stages", "00-scope-and-architecture.md")
        for heading in ("# Etapa 0: Escopo e arquitetura", "## 1. O que foi encontrado", "## 2. O que precisa ser corrigido",
                        "## 3. O que pode ser explorado", "## Arquitetura", "**Joias da coroa**", "## A seguir"):
            self.assertIn(heading, report)
        self.assertIn("### P1 · F-001 · CI role reads the payments database", report)
        self.assertIn("Scope the role to the tables the pipeline needs", report)
        self.assertIn("Is payments-db reachable from the internet?", report)
        self.assertIn("${{ secrets.DEPLOY }}", report)

    def test_an_empty_stage_still_has_three_parts(self):
        self.assertEqual(self.render("--stage", "4").returncode, 0)
        report = self.read("stages", "04-privilege-escalation.md")
        for text in ("## 1. O que foi encontrado", "Nada encontrado nesta etapa.", "Nada a corrigir a partir desta etapa.",
                     "Nada explorável identificado nesta etapa."):
            self.assertIn(text, report)

    def test_live_page(self):
        self.assertEqual(self.render("--live").returncode, 0)
        page = self.read("live-report.html")
        self.assertEqual(re.findall(r"\{\{[A-Za-z0-9_.]+\}\}", page), [])
        self.assertEqual(re.findall(r"<!-- (?:BEGIN|END):\w+ -->", page), [])
        self.assertNotIn("TEMPLATE NOTES", page)
        self.assertNotIn("\x00", page)
        self.assertIn("<title>acme/payments Security Scan</title>", page)
        self.assertIn('lang="pt-BR"', page)
        self.assertEqual(re.findall(r'id="stage-(\d+)"', page), ["0"])
        states = dict((number, state) for state, number in re.findall(r'<li class="(\w+)"><span class="n">(\d+)', page))
        self.assertEqual((states["0"], states["1"], states["2"]), ("done", "current", "todo"))
        self.assertIn("<dt>P1 · em até 14 dias</dt><dd>1</dd>", page)
        self.assertIn("O que foi encontrado", page)
        self.assertIn("O que precisa ser corrigido", page)
        self.assertIn("O que pode ser explorado", page)
        self.assertIn("${{ secrets.DEPLOY }}", page)
        self.assertIn("Scope the role to the tables the pipeline needs", page)
        self.assertNotIn("<html", page.lower())

    def test_live_page_grows_with_each_stage(self):
        self.bb("stage-done", "1")
        self.assertEqual(self.render("--live").returncode, 0)
        self.assertEqual(re.findall(r'id="stage-(\d+)"', self.read("live-report.html")), ["0", "1"])

    def test_architecture(self):
        self.assertEqual(self.render("--architecture").returncode, 0)
        data = json.loads(self.read("architecture.json"))
        self.assertEqual(len(data["nodes"]), 2)
        text = self.read("architecture.md")
        for expected in ("```mermaid", "flowchart LR", "N001 -- can-read --> N002", 'internet(("Internet"))', "class N002 jewel", "## Identidades"):
            self.assertIn(expected, text)

    def test_user_text_cannot_break_out_of_the_page(self):
        self.bb("add-fact", "--stage", "0", "--statement", "Bucket <script>alert(1)</script> named {{SCOPE_NAME}}", "--status", "to-validate")
        self.assertEqual(self.render("--live").returncode, 0)
        page = self.read("live-report.html")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("named {{SCOPE_NAME}}", page)

    def test_a_secret_in_the_blackboard_stops_the_report(self):
        path = os.path.join(self.run_dir, "blackboard.json")
        with open(path, encoding="utf-8") as handle:
            board = json.load(handle)
        board["facts"][0]["statement"] = "token %s was found" % _helpers.fake_github_token()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(board, handle)
        for arguments in (["--stage", "0"], ["--live"]):
            result = self.render(*arguments)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(_helpers.fake_github_token(), result.stdout + result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, "live-report.html")))

    def test_final_is_not_implemented_yet(self):
        self.assertEqual(self.render("--final").returncode, 2)


if __name__ == "__main__":
    unittest.main()
