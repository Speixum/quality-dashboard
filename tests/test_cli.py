"""cli.py：四个子命令的退出码、产物与错误处理。"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from qdash.cli import EXIT_INVALID, EXIT_OK, EXIT_USAGE, main

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo.csv"
RULES = ROOT / "examples" / "rules.json"
SAMPLE = ROOT / "examples" / "sample_report.json"
ARTIFACTS = ROOT / "examples" / "artifacts"
NOW = "2026-11-08T02:00:00Z"


def run(args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue() + err.getvalue()


class HelpTests(unittest.TestCase):
    def test_no_command_prints_help(self) -> None:
        code, output = run([])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("build", output)


class CheckTests(unittest.TestCase):
    def test_check_writes_json_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            page = Path(tmp) / "report.html"
            code, output = run([
                "check", str(DEMO), "--rules", str(RULES),
                "-o", str(report), "--html", str(page),
                "--name", "demo", "--now", NOW,
            ])
            self.assertEqual(code, EXIT_OK, output)
            self.assertTrue(report.is_file())
            self.assertTrue(page.is_file())
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "data-quality-report/1.0")
            self.assertEqual(payload["summary"]["score"], 86.8)
            self.assertEqual(payload["subject"]["name"], "demo")
            self.assertIn("html:", output)

    def test_check_missing_rules_file(self) -> None:
        code, output = run(["check", str(DEMO), "--rules", "nope.json"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("error:", output)


class BuildTests(unittest.TestCase):
    def test_build_default_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "r.json"
            source.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            code, output = run(["build", str(source)])
            self.assertEqual(code, EXIT_OK, output)
            self.assertTrue(source.with_suffix(".html").is_file())

    def test_build_strict_accepts_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "out.html"
            code, output = run(["build", str(SAMPLE), "-o", str(page), "--strict"])
            self.assertEqual(code, EXIT_OK, output)

    def test_build_strict_rejects_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bad.json"
            source.write_text(json.dumps({"schema": "wrong/1.0"}), encoding="utf-8")
            page = Path(tmp) / "out.html"
            code, output = run(["build", str(source), "-o", str(page), "--strict"])
            self.assertEqual(code, EXIT_INVALID)
            self.assertFalse(page.exists())
            self.assertIn("warning:", output)


class ValidateTests(unittest.TestCase):
    def test_valid_report(self) -> None:
        code, output = run(["validate", str(SAMPLE)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("result: OK", output)

    def test_invalid_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bad.json"
            source.write_text(json.dumps({"schema": "wrong/1.0"}), encoding="utf-8")
            code, output = run(["validate", str(source)])
        self.assertEqual(code, EXIT_INVALID)
        self.assertIn("result: INVALID", output)

    def test_json_output(self) -> None:
        code, output = run(["validate", str(SAMPLE), "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["errors"], [])

    def test_missing_file(self) -> None:
        code, output = run(["validate", "does-not-exist.json"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("error:", output)


class CollectTests(unittest.TestCase):
    def test_collect_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "collected.json"
            page = Path(tmp) / "collected.html"
            code, output = run(["collect", str(ARTIFACTS), "-o", str(report), "--html", str(page)])
            self.assertEqual(code, EXIT_OK, output)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["lineage"]["name"], "orders_daily")
            self.assertEqual(payload["pii"]["summary"]["total"], 9)
            self.assertTrue(page.is_file())

    def test_collect_with_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "collected.json"
            code, output = run(["collect", str(ARTIFACTS), "-b", str(SAMPLE), "-o", str(report)])
            self.assertEqual(code, EXIT_OK, output)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertIsNotNone(payload["lineage"])
