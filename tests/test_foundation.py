"""The YAML reader and the schema validator."""
import json
import os
import unittest

import _helpers
import _schema
import _yamlite


class YamlTests(unittest.TestCase):
    def test_reads_the_files_the_skill_ships(self):
        allowlist = _yamlite.load(os.path.join(_helpers.SKILL, "assets", "command-allowlist.yaml"))
        self.assertIn("aws", allowlist["tools"])
        self.assertIn("~/.aws/credentials", allowlist["protected_paths"])
        engagement = _yamlite.load(os.path.join(_helpers.SKILL, "assets", "templates", "engagement.yaml"))
        self.assertIs(engagement["mode"]["read_only"], True)
        self.assertEqual(engagement["scope"]["includes"], [])

    def test_scalars(self):
        value = _yamlite.loads(
            'a: "x: y"\nb: [1, "two", three]\nc: ~/.aws/credentials\nd: 3.5\ne: true\nf: null\ng: \'it\'\'s\'\nh: 7 # note'
        )
        self.assertEqual(
            value,
            {"a": "x: y", "b": [1, "two", "three"], "c": "~/.aws/credentials", "d": 3.5, "e": True, "f": None, "g": "it's", "h": 7},
        )

    def test_nested_mappings_and_sequences(self):
        value = _yamlite.loads("top:\n  inner:\n    - one\n    - \"* two\"\n  other: {}\nlist:\n- a\n- b\n")
        self.assertEqual(value, {"top": {"inner": ["one", "* two"], "other": {}}, "list": ["a", "b"]})

    def test_round_trip(self):
        data = {"run_id": "20261118-1000", "when": "2026-11-18T10:00:00Z", "n": 3, "ok": True, "none": None,
                "nested": {"items": ["a b", "true", "x: y"], "empty": []}}
        self.assertEqual(_yamlite.loads(_yamlite.dumps(data, header="managed")), data)

    def test_rejects_what_it_does_not_support(self):
        for text in ("a: b: c", "a:\n  - x: 1", "a: |\n  text", "a: *ref", "a: 1\na: 2", "\ta: 1", "a: {b: 1}", "a: [1, [2]]"):
            with self.assertRaises(_yamlite.YamlError, msg=text):
                _yamlite.loads(text)


class SchemaTests(unittest.TestCase):
    def good_finding(self):
        return {
            "id": "F-001", "title": "t", "stage": 2, "priority": "P0", "evidence": "confirmed", "facts": ["K-001"],
            "entry": "none", "reach": "direct", "impact": "critical", "visibility": "silent",
            "fix": {"summary": "s", "layer": 2}, "exploit": {"condition": "c", "gain": "g"},
        }

    def test_schemas_are_valid_json(self):
        for name in ("engagement.schema.json", "blackboard.schema.json", "finding.schema.json"):
            with open(os.path.join(_schema.SCHEMA_DIR, name), encoding="utf-8") as handle:
                json.load(handle)

    def test_accepts_a_good_finding(self):
        self.assertEqual(_schema.validate(self.good_finding(), _schema.load_schema("finding.schema.json")), [])

    def test_reports_what_is_wrong(self):
        bad = dict(self.good_finding(), priority="P9", facts=[], extra=1, stage=12)
        errors = " ".join(_schema.validate(bad, _schema.load_schema("finding.schema.json")))
        for expected in ("priority", "facts", "extra", "stage"):
            self.assertIn(expected, errors)

    def test_follows_references_and_conditions(self):
        board = {"run_id": "x", "nodes": [], "intents": [], "relations": [], "findings": [dict(self.good_finding(), priority="nope")],
                 "facts": [{"id": "K-001", "statement": "s", "stage": 1, "status": "confirmed"}]}
        errors = " ".join(_schema.validate(board, _schema.load_schema("blackboard.schema.json")))
        self.assertIn("findings[0].priority", errors)
        self.assertIn("missing 'evidence'", errors)


if __name__ == "__main__":
    unittest.main()
