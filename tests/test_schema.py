"""schema.py：报告契约、容错归一化、校验与辅助取值。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from qdash import schema as sc

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_report.json"


def sample_report() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


class GradeTests(unittest.TestCase):
    def test_grade_boundaries(self) -> None:
        self.assertEqual(sc.grade_for(100), "A")
        self.assertEqual(sc.grade_for(90), "A")
        self.assertEqual(sc.grade_for(89.9), "B")
        self.assertEqual(sc.grade_for(80), "B")
        self.assertEqual(sc.grade_for(70), "C")
        self.assertEqual(sc.grade_for(60), "D")
        self.assertEqual(sc.grade_for(59.9), "E")
        self.assertEqual(sc.grade_for(0), "E")

    def test_grade_none(self) -> None:
        self.assertIsNone(sc.grade_for(None))


class WeightedScoreTests(unittest.TestCase):
    def test_weighted_average(self) -> None:
        result = sc.weighted_score([
            {"score": 100, "weight": 1},
            {"score": 0, "weight": 1},
        ])
        self.assertEqual(result, 50.0)

    def test_none_scores_are_skipped(self) -> None:
        result = sc.weighted_score([
            {"score": None, "weight": 1},
            {"score": 50, "weight": 1},
        ])
        self.assertEqual(result, 50.0)

    def test_zero_total_weight(self) -> None:
        self.assertIsNone(sc.weighted_score([{"score": 100, "weight": 0}]))

    def test_empty(self) -> None:
        self.assertIsNone(sc.weighted_score([]))


class NormalizeTests(unittest.TestCase):
    def test_empty_report_has_defaults(self) -> None:
        report = sc.normalize_report({})
        self.assertEqual(report["schema"], sc.REPORT_SCHEMA)
        self.assertEqual([item["key"] for item in report["dimensions"]], list(sc.DIMENSION_KEYS))
        self.assertEqual(report["summary"]["score"], None)
        self.assertEqual(report["summary"]["grade"], sc.DASH)
        self.assertEqual(report["summary"]["checks_total"], 0)
        for key in ("issues", "trend", "distributions"):
            self.assertEqual(report[key], [])
        self.assertIsNone(report["lineage"])
        self.assertIsNone(report["pii"])

    def test_non_mapping_input(self) -> None:
        for raw in (None, "nope", 42, ["a"]):
            report = sc.normalize_report(raw)
            self.assertEqual(report["schema"], sc.REPORT_SCHEMA)

    def test_bad_schema_is_replaced(self) -> None:
        self.assertEqual(sc.normalize_report({"schema": "bad"})["schema"], sc.REPORT_SCHEMA)

    def test_sample_keeps_values(self) -> None:
        raw = sample_report()
        report = sc.normalize_report(raw)
        self.assertEqual(report["summary"], raw["summary"])
        self.assertEqual(len(report["issues"]), len(raw["issues"]))
        self.assertEqual(len(report["dimensions"]), 5)
        self.assertEqual(report["subject"]["name"], raw["subject"]["name"])

    def test_empty_report_factory(self) -> None:
        report = sc.empty_report()
        self.assertEqual(report["schema"], sc.REPORT_SCHEMA)
        self.assertEqual(len(report["dimensions"]), 5)


class ValidateTests(unittest.TestCase):
    def test_sample_is_valid(self) -> None:
        result = sc.validate_report(sample_report())
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.warnings, ())

    def test_missing_schema_is_an_error(self) -> None:
        result = sc.validate_report({})
        self.assertFalse(result.ok)
        self.assertTrue(any("schema" in item for item in result.errors))

    def test_wrong_schema_is_an_error(self) -> None:
        result = sc.validate_report({"schema": "something/2.0"})
        self.assertFalse(result.ok)

    def test_field_problems_are_warnings(self) -> None:
        raw = {"schema": sc.REPORT_SCHEMA, "summary": {"score": 150, "grade": "Z"}, "issues": {}}
        result = sc.validate_report(raw)
        self.assertTrue(result.ok)
        self.assertTrue(any("0..100" in item for item in result.warnings))
        self.assertTrue(any("grade" in item for item in result.warnings))

    def test_as_dict_shape(self) -> None:
        payload = sc.validate_report({}).as_dict()
        self.assertEqual(set(payload), {"ok", "errors", "warnings"})
        self.assertFalse(payload["ok"])
        json.dumps(payload)


class HelperTests(unittest.TestCase):
    def test_as_int(self) -> None:
        self.assertEqual(sc.as_int("12"), 12)
        self.assertEqual(sc.as_int("x", 5), 5)
        self.assertEqual(sc.as_int(None, 0), 0)

    def test_as_number(self) -> None:
        self.assertEqual(sc.as_number("1.5"), 1.5)
        self.assertEqual(sc.as_number(2), 2.0)
        self.assertIsNone(sc.as_number("x"))

    def test_as_bool(self) -> None:
        for value in (True, 1, "1", "yes", "true", "on"):
            self.assertTrue(sc.as_bool(value), value)
        for value in (False, 0, "0", "no", "false", "off", None):
            self.assertFalse(sc.as_bool(value), value)

    def test_as_text(self) -> None:
        self.assertEqual(sc.as_text(" a "), " a ")
        self.assertEqual(sc.as_text(42), "42")
        self.assertEqual(sc.as_text(None), sc.DASH)
        self.assertEqual(sc.as_text(None, "-"), "-")

    def test_dimension_name(self) -> None:
        self.assertEqual(sc.dimension_name("completeness"), "完整性")
        self.assertEqual(sc.dimension_name("unknown"), "unknown")
