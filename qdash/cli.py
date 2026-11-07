"""qdash 命令行入口：build / collect / check / validate。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import __version__
from . import schema as sc
from .collect import collect_artifacts
from .console import configure_stdout, format_table, human_size
from .jsonio import read_json, write_json
from .render import build_html
from .rules import evaluate, load_dataset, load_rules

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


def _error(message: str) -> int:
    """打印 ASCII 前缀的错误信息并返回用法错误码。"""
    print(f"error: {message}")
    return EXIT_USAGE


def _warn_all(warnings: Sequence[str], limit: int = 12) -> None:
    """以 ASCII 前缀打印警告，避免刷屏。"""
    for warning in list(warnings)[:limit]:
        print(f"warning: {warning}")
    if len(warnings) > limit:
        print(f"warning: ... {len(warnings) - limit} more warnings omitted")


def _report_rows(report: Mapping[str, Any]) -> list[list[str]]:
    """构造报告概览表的行。"""
    subject = report.get("subject") if isinstance(report.get("subject"), Mapping) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    dimensions = report.get("dimensions") if isinstance(report.get("dimensions"), list) else []
    dim_text = " ".join(
        f"{sc.dimension_name(str(item.get('key')))}={sc.DASH if item.get('score') is None else item.get('score')}"
        for item in dimensions
        if isinstance(item, Mapping)
    )
    score = summary.get("score")
    grade = summary.get("grade")
    return [
        ["subject", sc.as_text(subject.get("name"))],
        ["version", sc.as_text(subject.get("version"))],
        ["score", f"{score if score is not None else sc.DASH} / {grade}"],
        ["checks", f"{summary.get('checks_passed', 0)} / {summary.get('checks_total', 0)}"],
        ["issues", f"{summary.get('issues_total', 0)} total, {summary.get('issues_open', 0)} open"],
        ["dimensions", dim_text or sc.DASH],
    ]


def _print_report(report: Mapping[str, Any], source: str) -> None:
    """打印报告概览。"""
    print(f"report: {source}")
    print(format_table(["field", "value"], _report_rows(report), max_width=72))
    lineage = report.get("lineage")
    if isinstance(lineage, Mapping):
        nodes = lineage.get("nodes") if isinstance(lineage.get("nodes"), list) else []
        print(f"lineage: {sc.as_text(lineage.get('run_id'))} status={sc.as_text(lineage.get('status'))} nodes={len(nodes)}")
    pii = report.get("pii")
    if isinstance(pii, Mapping):
        findings = pii.get("findings") if isinstance(pii.get("findings"), list) else []
        summary = pii.get("summary") if isinstance(pii.get("summary"), Mapping) else {}
        total = summary.get("total", len(findings))
        print(f"pii: source={sc.as_text(pii.get('source'))} findings={total}")


def _rule_rows(results: Sequence[Any]) -> list[list[str]]:
    """把规则执行结果转成表格行。"""
    rows: list[list[str]] = []
    for item in results:
        rows.append([
            str(item.id),
            str(item.type),
            str(item.column),
            sc.dimension_name(str(item.dimension)),
            str(item.severity),
            str(item.violations),
            str(item.checks),
        ])
    return rows


def _cmd_build(args: argparse.Namespace) -> int:
    """把报告 JSON 渲染为单文件 HTML。"""
    source = Path(args.report)
    try:
        raw = read_json(source)
    except (OSError, ValueError) as exc:
        return _error(f"cannot read report: {exc}")
    result = sc.validate_report(raw)
    if args.strict and result.errors:
        _warn_all(result.errors)
        return EXIT_INVALID
    report = sc.normalize_report(raw)
    output = Path(args.output) if args.output else source.with_suffix(".html")
    try:
        page = build_html(report, title=args.title, max_bytes=args.max_bytes)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(page, encoding="utf-8", newline="\n")
    except OSError as exc:
        return _error(f"cannot write html: {exc}")
    _print_report(report, str(source))
    print(format_table(["field", "value"], [
        ["html", str(output)],
        ["size", human_size(len(page.encode("utf-8")))],
        ["title", args.title or sc.as_text(report.get("subject", {}).get("name") if isinstance(report.get("subject"), Mapping) else None)],
    ], max_width=72))
    _warn_all(list(result.warnings) + list(result.errors))
    return EXIT_OK


def _cmd_collect(args: argparse.Namespace) -> int:
    """扫描目录，把血缘与 PII 产物合并进报告。"""
    try:
        result = collect_artifacts(args.directory, base_report=read_json(args.base) if args.base else None)
    except (OSError, ValueError) as exc:
        return _error(f"cannot collect artifacts: {exc}")
    stats = result.stats
    print(format_table(["stat", "value"], [
        ["scanned", str(stats.scanned)],
        ["recognized", str(stats.recognized)],
        ["lineage files", str(stats.lineage_files)],
        ["pii files", str(stats.pii_files)],
        ["ignored", str(stats.ignored)],
        ["skipped", str(stats.skipped)],
        ["errors", str(len(stats.errors))],
    ], max_width=72))
    _print_report(result.report, str(args.directory))
    if args.output:
        try:
            write_json(args.output, result.report)
        except OSError as exc:
            return _error(f"cannot write report: {exc}")
        print(f"json: {args.output}")
    if args.html:
        try:
            page = build_html(result.report, title=args.title)
            Path(args.html).parent.mkdir(parents=True, exist_ok=True)
            Path(args.html).write_text(page, encoding="utf-8", newline="\n")
        except OSError as exc:
            return _error(f"cannot write html: {exc}")
        print(f"html: {args.html} ({human_size(len(page.encode('utf-8')))})")
    _warn_all(stats.errors)
    return EXIT_OK


def _cmd_check(args: argparse.Namespace) -> int:
    """对 CSV / JSONL 执行质量规则并生成报告。"""
    try:
        dataset = load_dataset(args.dataset)
        loaded = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        return _error(f"cannot load input: {exc}")
    subject: dict[str, str] = {}
    if args.name:
        subject["name"] = args.name
    if args.version:
        subject["version"] = args.version
    if args.owner:
        subject["owner"] = args.owner
    result = evaluate(dataset, loaded.rules, subject=subject or None, now=args.now)
    _print_report(result.report, str(args.dataset))
    print(format_table(
        ["id", "type", "column", "dimension", "severity", "bad", "checks"],
        _rule_rows(result.rule_results),
        max_width=42,
        aligns=["l", "l", "l", "l", "l", "r", "r"],
    ))
    if args.output:
        try:
            write_json(args.output, result.report)
        except OSError as exc:
            return _error(f"cannot write report: {exc}")
        print(f"json: {args.output}")
    if args.html:
        try:
            page = build_html(result.report, title=args.title)
            Path(args.html).parent.mkdir(parents=True, exist_ok=True)
            Path(args.html).write_text(page, encoding="utf-8", newline="\n")
        except OSError as exc:
            return _error(f"cannot write html: {exc}")
        print(f"html: {args.html} ({human_size(len(page.encode('utf-8')))})")
    _warn_all(loaded.warnings + result.warnings)
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    """校验报告 JSON 的字段与取值。"""
    try:
        raw = read_json(args.report)
    except (OSError, ValueError) as exc:
        return _error(f"cannot read report: {exc}")
    result = sc.validate_report(raw)
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    else:
        print("result: OK" if result.ok else "result: INVALID")
        print(format_table(["kind", "message"], [["error", item] for item in result.errors] + [["warning", item] for item in result.warnings], max_width=90))
        if not result.errors and not result.warnings:
            print("no findings")
    return EXIT_OK if result.ok else EXIT_INVALID


def _build_parser() -> argparse.ArgumentParser:
    """构造命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="qdash",
        description="Offline dataset quality report toolkit (stdlib only).",
        epilog=(
            "examples:\n"
            "  python -m qdash build examples/sample_report.json -o report.html\n"
            "  python -m qdash collect examples/artifacts -o report.json --html report.html\n"
            "  python -m qdash check examples/demo.csv --rules examples/rules.json --html report.html\n"
            "  python -m qdash validate report.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"qdash {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    build = sub.add_parser("build", help="render a report JSON into a single-file HTML")
    build.add_argument("report", help="input report JSON")
    build.add_argument("-o", "--output", help="output HTML path (default: next to input)")
    build.add_argument("--title", help="page title")
    build.add_argument("--max-bytes", type=int, default=480 * 1024, help="soft size limit for the HTML")
    build.add_argument("--strict", action="store_true", help="fail when schema validation reports errors")
    build.set_defaults(func=_cmd_build)

    collect = sub.add_parser("collect", help="scan a directory for lineage and pii artifacts")
    collect.add_argument("directory", help="directory or single JSON file")
    collect.add_argument("-b", "--base", help="base report JSON to extend")
    collect.add_argument("-o", "--output", help="output report JSON")
    collect.add_argument("--html", help="also render a single-file HTML")
    collect.add_argument("--title", help="HTML page title")
    collect.set_defaults(func=_cmd_collect)

    check = sub.add_parser("check", help="run quality rules on CSV or JSONL")
    check.add_argument("dataset", help="dataset file (.csv / .jsonl / .ndjson)")
    check.add_argument("--rules", required=True, help="rules JSON file")
    check.add_argument("-o", "--output", help="output report JSON")
    check.add_argument("--html", help="also render a single-file HTML")
    check.add_argument("--title", help="HTML page title")
    check.add_argument("--name", help="subject dataset name")
    check.add_argument("--version", help="subject dataset version")
    check.add_argument("--owner", help="subject owner")
    check.add_argument("--now", help="evaluation time in ISO 8601 (UTC)")
    check.set_defaults(func=_cmd_check)

    validate = sub.add_parser("validate", help="validate a report JSON")
    validate.add_argument("report", help="input report JSON")
    validate.add_argument("--json", action="store_true", help="print machine-readable JSON")
    validate.set_defaults(func=_cmd_validate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """命令行主函数，返回进程退出码。"""
    configure_stdout()
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("error: interrupted")
        return 130
    except Exception as exc:  # 兜底：CLI 不向外抛 traceback
        print(f"error: {type(exc).__name__}: {exc}")
        return EXIT_USAGE
