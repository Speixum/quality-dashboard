"""rules.py：数据读取、8 类规则与评分。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from qdash.rules import evaluate, load_dataset, load_rules

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo.csv"
RULES = ROOT / "examples" / "rules.json"
NOW = "2026-11-08T02:00:00Z"


class DatasetTests(unittest.TestCase):
    def test_demo_shape(self) -> None:
        dataset = load_dataset(DEMO)
        self.assertEqual(len(dataset.rows), 16)
        self.assertEqual(len(dataset.columns), 10)
        self.assertEqual(dataset.warnings, [])

    def test_unsupported_extension(self) -> None:
        with self.assertRaises(ValueError):
            load_dataset(ROOT / "README.md")

    def test_missing_file(self) -> None:
        with self.assertRaises(OSError):
            load_dataset(ROOT / "examples" / "nope.csv")


class RuleLoadTests(unittest.TestCase):
    def test_example_rules(self) -> None:
        loaded = load_rules(RULES)
        self.assertEqual(len(loaded.rules), 9)
        self.assertEqual(loaded.warnings, [])

    def test_bad_rules_are_skipped_with_warnings(self) -> None:
        payload = {
            "schema": "quality-rules/1.0",
            "rules": [
                {"id": "X", "type": "bogus", "column": "a"},
                {"id": "Y", "type": "consistency", "column": "a"},
                {"id": "Z", "type": "range", "column": "amount"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_rules(path)
        self.assertEqual(len(loaded.rules), 1)
        self.assertEqual(len(loaded.warnings), 2)
        self.assertTrue(any("unsupported type" in item for item in loaded.warnings))
        self.assertTrue(any("two columns" in item for item in loaded.warnings))


class EvaluateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dataset = load_dataset(DEMO)
        self.rules = load_rules(RULES).rules
        self.result = evaluate(self.dataset, self.rules, subject={"name": "demo"}, now=NOW)
        self.report = self.result.report

    def test_summary_baseline(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(summary["score"], 86.8)
        self.assertEqual(summary["grade"], "B")
        self.assertEqual(summary["checks_total"], 144)
        self.assertEqual(summary["checks_passed"], 126)
        self.assertEqual(summary["issues_total"], 9)
        self.assertEqual(summary["issues_open"], 9)

    def test_dimension_scores(self) -> None:
        scores = {item["key"]: item["score"] for item in self.report["dimensions"]}
        self.assertEqual(scores["completeness"], 75.0)
        self.assertEqual(scores["uniqueness"], 93.8)
        self.assertEqual(scores["validity"], 92.2)
        self.assertEqual(scores["consistency"], 93.8)
        self.assertEqual(scores["timeliness"], 81.2)
        weights = {item["key"]: item["weight"] for item in self.report["dimensions"]}
        self.assertEqual(sum(weights.values()), 1.0)

    def test_per_rule_violations(self) -> None:
        violations = {item.id: item.violations for item in self.result.rule_results}
        self.assertEqual(violations, {
            "R-001": 1, "R-002": 7, "R-003": 1, "R-004": 2, "R-005": 1,
            "R-006": 1, "R-007": 1, "R-008": 3, "R-009": 1,
        })
        for item in self.result.rule_results:
            self.assertEqual(item.checks, 16)

    def test_issue_counts_match_rules(self) -> None:
        self.assertEqual(len(self.report["issues"]), 9)
        self.assertEqual(sum(item["count"] for item in self.report["issues"]), 18)
        for issue in self.report["issues"]:
            self.assertEqual(issue["status"], "open")
            self.assertIn(issue["severity"], ("high", "medium", "low"))

    def test_distributions(self) -> None:
        self.assertEqual(len(self.report["distributions"]), 2)
        names = [item["name"] for item in self.report["distributions"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(item["buckets"] for item in self.report["distributions"]))
        self.assertEqual(self.report["trend"], [])

    def test_subject_is_echoed(self) -> None:
        self.assertEqual(self.report["subject"]["name"], "demo")
        self.assertEqual(self.report["schema"], "data-quality-report/1.0")

    def test_empty_dataset(self) -> None:
        dataset = type(self.dataset)(columns=self.dataset.columns, rows=[], source="empty")
        result = evaluate(dataset, self.rules, now=NOW)
        self.assertIsNone(result.report["summary"]["score"])
        for dimension in result.report["dimensions"]:
            self.assertIsNone(dimension["score"])
        self.assertEqual(result.report["issues"], [])

    def test_no_rules(self) -> None:
        result = evaluate(self.dataset, [], now=NOW)
        self.assertIsNone(result.report["summary"]["score"])
        self.assertEqual(result.report["summary"]["checks_total"], 0)
