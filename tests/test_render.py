"""render.py：单文件 HTML 的完整性、无外链与体积控制。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from qdash import schema as sc
from qdash.render import MAX_HTML_BYTES, build_html

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_report.json"


def sample_report() -> dict:
    return sc.normalize_report(json.loads(SAMPLE.read_text(encoding="utf-8")))


class HtmlBasicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = build_html(sample_report())

    def test_is_a_complete_document(self) -> None:
        self.assertTrue(self.page.lstrip().lower().startswith("<!doctype html"))
        self.assertIn("</html>", self.page)
        self.assertIn("<svg", self.page)

    def test_is_self_contained(self) -> None:
        for token in ("<script src", "<link", "@import", "http://", "https://", "src=\"http"):
            self.assertNotIn(token, self.page)
        for token in ("@@BODY@@", "@@DATA@@", "@@TITLE@@"):
            self.assertNotIn(token, self.page)

    def test_within_default_budget(self) -> None:
        self.assertLessEqual(len(self.page.encode("utf-8")), MAX_HTML_BYTES)

    def test_sections_are_rendered(self) -> None:
        for title in ("质量维度", "问题清单", "数据血缘", "PII 扫描"):
            self.assertIn(title, self.page)

    def test_title_can_be_overridden(self) -> None:
        page = build_html(sample_report(), title="数据质量看板")
        self.assertIn("数据质量看板", page)

    def test_empty_report_renders(self) -> None:
        page = build_html(sc.normalize_report({}))
        self.assertTrue(page.lstrip().lower().startswith("<!doctype html"))


class PiiSectionTests(unittest.TestCase):
    def test_pii_types_are_labelled_in_chinese(self) -> None:
        pii = {
            "source": "data/sample.txt",
            "generated_at": "2026-11-08T02:00:00Z",
            "findings": [
                {"type": "cn_id_card", "level": "high_sensitive", "confidence": "high",
                 "preview": "110***1234", "line": 1, "col": 1},
                {"type": "mobile_cn", "level": "sensitive", "confidence": "high",
                 "preview": "138****5678", "line": 2, "col": 5},
            ],
            "summary": {"total": 2, "by_type": {"cn_id_card": 1, "mobile_cn": 1}},
        }
        report = sc.normalize_report({"schema": sc.REPORT_SCHEMA, "pii": pii})
        page = build_html(report)
        self.assertIn("身份证号", page)
        self.assertIn("手机号", page)
        self.assertIn('class="type-chip"', page)


class HtmlSafetyTests(unittest.TestCase):
    def test_subject_name_is_escaped(self) -> None:
        report = sc.normalize_report({
            "schema": sc.REPORT_SCHEMA,
            "subject": {"name": "<script>alert(1)</script>"},
        })
        page = build_html(report)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_issue_text_is_escaped(self) -> None:
        report = sc.normalize_report({
            "schema": sc.REPORT_SCHEMA,
            "issues": [{
                "id": "Q-001",
                "title": "<img src=x onerror=alert(1)>",
                "severity": "high",
                "dimension": "completeness",
                "status": "open",
                "count": 1,
            }],
        })
        page = build_html(report)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)


class HtmlBudgetTests(unittest.TestCase):
    def test_tiny_budget_does_not_crash(self) -> None:
        page = build_html(sample_report(), max_bytes=1)
        self.assertTrue(page.lstrip().lower().startswith("<!doctype html"))

    def test_large_report_is_tightened(self) -> None:
        issues = [
            {
                "id": f"Q-{index:04d}",
                "title": "字段缺失 " + "x" * 60,
                "severity": "high",
                "dimension": "completeness",
                "status": "open",
                "count": index + 1,
                "samples": ["a" * 40, "b" * 40],
            }
            for index in range(1500)
        ]
        report = sc.normalize_report({
            "schema": sc.REPORT_SCHEMA,
            "summary": {"score": 61.0, "grade": "D", "checks_total": 100, "checks_passed": 61,
                        "issues_total": 1500, "issues_open": 1500},
            "issues": issues,
        })
        page = build_html(report, max_bytes=384 * 1024)
        self.assertLessEqual(len(page.encode("utf-8")), 384 * 1024)
        self.assertIn("Q-0000", page)
        self.assertIn("</html>", page)
