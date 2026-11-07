"""collect.py：按 schema 识别并归并 lineage / pii 产物。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from qdash.collect import collect_artifacts

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "examples" / "artifacts"


class CollectExampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = collect_artifacts(ARTIFACTS)

    def test_stats(self) -> None:
        stats = self.result.stats
        self.assertEqual(stats.scanned, 2)
        self.assertEqual(stats.recognized, 2)
        self.assertEqual(stats.lineage_files, 1)
        self.assertEqual(stats.pii_files, 1)
        self.assertEqual(stats.errors, [])

    def test_lineage_is_embedded(self) -> None:
        lineage = self.result.report["lineage"]
        self.assertIsInstance(lineage, dict)
        self.assertEqual(lineage["name"], "orders_daily")
        self.assertEqual(lineage["status"], "failed")
        self.assertEqual(len(lineage["nodes"]), 6)

    def test_pii_is_embedded(self) -> None:
        pii = self.result.report["pii"]
        self.assertEqual(pii["source"], "orders_daily")
        self.assertEqual(pii["summary"]["total"], 9)
        self.assertEqual(len(pii["findings"]), 9)

    def test_report_stays_a_contract_report(self) -> None:
        self.assertEqual(self.result.report["schema"], "data-quality-report/1.0")
        for key in ("summary", "dimensions", "issues"):
            self.assertIn(key, self.result.report)

    def test_single_file_input(self) -> None:
        single = collect_artifacts(ARTIFACTS / "pii_orders.json")
        self.assertEqual(single.stats.pii_files, 1)
        self.assertIsNone(single.report["lineage"])


class CollectMessyDirTests(unittest.TestCase):
    def test_unknown_and_broken_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "unknown.json").write_text(json.dumps({"schema": "other/1.0"}), encoding="utf-8")
            (root / "broken.json").write_text("{not json", encoding="utf-8")
            (root / "notes.txt").write_text("hello", encoding="utf-8")
            result = collect_artifacts(root)
        self.assertEqual(result.stats.ignored, 1)
        self.assertEqual(result.stats.skipped, 1)
        self.assertEqual(result.stats.recognized, 0)
        self.assertTrue(any("broken.json" in item for item in result.stats.errors))


class CollectBaseTests(unittest.TestCase):
    def test_base_report_is_kept(self) -> None:
        base = json.loads((ROOT / "examples" / "sample_report.json").read_text(encoding="utf-8"))
        result = collect_artifacts(ARTIFACTS, base_report=base)
        self.assertEqual(result.report["subject"]["name"], base["subject"]["name"])
        self.assertEqual(result.report["summary"]["score"], base["summary"]["score"])
        self.assertIsNotNone(result.report["lineage"])
        self.assertIsNotNone(result.report["pii"])
