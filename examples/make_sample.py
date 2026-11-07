"""生成 examples/ 下的演示数据。

生成内容：
- examples/demo.csv：带空值、重复、越界、格式错误与过期日期的样例数据。
- examples/artifacts/lineage_orders.json：dataset-lineage/1.0 风格血缘。
- examples/artifacts/pii_orders.json：pii-hits/1.0 风格敏感信息命中。
- examples/sample_report.json：综合演示报告，内嵌上面的血缘与 PII 数据。

所有文件都是生成物，已被 .gitignore 忽略；本脚本是唯一需要入库的生成器。
"""

from __future__ import annotations

import csv
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qdash import schema as sc
from qdash.console import configure_stdout, format_table, human_size
from qdash.jsonio import read_json, write_json

EXAMPLES = Path(__file__).resolve().parent
ARTIFACTS = EXAMPLES / "artifacts"
DEMO_CSV = EXAMPLES / "demo.csv"
SAMPLE_REPORT = EXAMPLES / "sample_report.json"
LINEAGE_PATH = ARTIFACTS / "lineage_orders.json"
PII_PATH = ARTIFACTS / "pii_orders.json"

NOW = datetime(2026, 11, 8, 1, 40, 0, tzinfo=timezone.utc)


def _lineage() -> dict[str, Any]:
    """构造一份包含失败节点的血缘样例。"""
    nodes = [
        {
            "id": "ingest_raw",
            "step": "ingest_raw",
            "seq": 0,
            "status": "success",
            "started_at": "2026-11-08T00:42:10Z",
            "duration_ms": 42000,
            "params": {"source": "orders_api", "batch": "2026-11-08"},
            "inputs": ["orders_api"],
            "outputs": ["raw/orders.csv"],
            "error": None,
            "unstable": False,
        },
        {
            "id": "validate_schema",
            "step": "validate_schema",
            "seq": 1,
            "status": "success",
            "started_at": "2026-11-08T00:42:52Z",
            "duration_ms": 8300,
            "params": {"contract": "orders_v2"},
            "inputs": ["raw/orders.csv"],
            "outputs": ["staged/orders.csv"],
            "error": None,
            "unstable": False,
        },
        {
            "id": "normalize_types",
            "step": "normalize_types",
            "seq": 2,
            "status": "success",
            "started_at": "2026-11-08T00:43:00Z",
            "duration_ms": 5100,
            "params": {"timezone": "UTC"},
            "inputs": ["staged/orders.csv"],
            "outputs": ["staged/orders_typed.parquet"],
            "error": None,
            "unstable": False,
        },
        {
            "id": "build_features",
            "step": "build_features",
            "seq": 3,
            "status": "warning",
            "started_at": "2026-11-08T00:43:05Z",
            "duration_ms": 18700,
            "params": {"window_days": 30},
            "inputs": ["staged/orders_typed.parquet"],
            "outputs": ["features/orders_daily.parquet"],
            "error": None,
            "unstable": True,
        },
        {
            "id": "export_dw",
            "step": "export_dw",
            "seq": 4,
            "status": "success",
            "started_at": "2026-11-08T00:43:24Z",
            "duration_ms": 12600,
            "params": {"target": "warehouse.orders_daily"},
            "inputs": ["features/orders_daily.parquet"],
            "outputs": ["warehouse.orders_daily"],
            "error": None,
            "unstable": False,
        },
        {
            "id": "quality_gate",
            "step": "quality_gate",
            "seq": 5,
            "status": "failed",
            "started_at": "2026-11-08T00:43:36Z",
            "duration_ms": 3200,
            "params": {"gate": "completeness", "threshold": 0.90},
            "inputs": ["features/orders_daily.parquet"],
            "outputs": [],
            "error": {
                "code": "DQ_GATE",
                "message": "completeness 0.82 below threshold 0.90",
            },
            "unstable": False,
        },
    ]
    edges = [
        {"from": "ingest_raw", "to": "validate_schema", "label": "raw"},
        {"from": "validate_schema", "to": "normalize_types", "label": "staged"},
        {"from": "normalize_types", "to": "build_features", "label": "typed"},
        {"from": "build_features", "to": "export_dw", "label": "features"},
        {"from": "build_features", "to": "quality_gate", "label": "gate"},
    ]
    return {
        "schema": sc.LINEAGE_SCHEMA,
        "run_id": "run-20261108-0421",
        "name": "orders_daily",
        "started_at": "2026-11-08T00:42:10Z",
        "finished_at": "2026-11-08T00:48:33Z",
        "status": "failed",
        "env": {"python": "3.11.9", "engine": "qdash", "host": "win-dev"},
        "nodes": nodes,
        "edges": edges,
    }


def _finding(
    ftype: str,
    level: str,
    confidence: str,
    score: float,
    line: int,
    col: int,
    length: int,
    preview: str,
    reasons: list[str],
) -> dict[str, Any]:
    """构造一条脱敏后的 PII 命中记录。"""
    return {
        "type": ftype,
        "level": level,
        "confidence": confidence,
        "score": score,
        "offset": (line - 1) * 200 + col,
        "end": (line - 1) * 200 + col + length,
        "line": line,
        "col": col,
        "length": length,
        "preview": preview,
        "checksum": "sha256:" + hashlib.sha256(preview.encode("utf-8")).hexdigest(),
        "reasons": reasons,
    }


def _pii() -> dict[str, Any]:
    """构造一份 PII 命中样例，预览均已脱敏。"""
    findings = [
        _finding("phone", "high_sensitive", "high", 0.98, 4, 20, 11, "138****1111", ["regex:cn_mobile", "column:phone"]),
        _finding("phone", "sensitive", "medium", 0.86, 10, 18, 11, "139****2222", ["regex:cn_mobile"]),
        _finding("phone", "sensitive", "medium", 0.81, 14, 18, 11, "134****0000", ["context:remark"]),
        _finding("email", "sensitive", "high", 0.94, 3, 32, 21, "a***@example.com", ["regex:email"]),
        _finding("email", "sensitive", "medium", 0.78, 12, 32, 22, "b***@example.com", ["regex:email"]),
        _finding("id_card", "high_sensitive", "high", 0.99, 7, 24, 18, "110101********1234", ["regex:cn_id", "checksum:valid"]),
        _finding("id_card", "high_sensitive", "medium", 0.88, 16, 24, 18, "310101********5678", ["regex:cn_id"]),
        _finding("bank_card", "high_sensitive", "high", 0.97, 8, 26, 19, "6222 **** **** 1234", ["luhn:valid"]),
        _finding("address", "general", "low", 0.62, 20, 12, 14, "上海市浦东新区***", ["keyword:address"]),
    ]
    summary = {
        "total": len(findings),
        "by_type": {"phone": 3, "email": 2, "id_card": 2, "bank_card": 1, "address": 1},
        "by_confidence": {"high": 4, "medium": 4, "low": 1},
        "by_level": {"high_sensitive": 4, "sensitive": 4, "general": 1},
    }
    return {
        "schema": sc.PII_SCHEMA,
        "source": "orders_daily",
        "generated_at": "2026-11-08T01:12:00Z",
        "findings": findings,
        "summary": summary,
        "ruleset": {"name": "cn-pii", "version": "1.4.0", "file": "rules/cn-pii.json"},
    }


def _write_demo_csv(path: Path) -> None:
    """写入带空值、重复、越界与格式错误的 CSV。"""
    header = [
        "user_id", "order_id", "email", "phone", "amount_cents",
        "status", "payment_status", "paid_at", "event_date", "coupon_code",
    ]
    rows = [
        ["U1001", "O10001", "alice@example.com", "13800001111", "12900", "paid", "paid", "2026-11-07T10:00:00Z", "2026-11-07", "C10"],
        ["", "O10002", "bob@example.com", "13900002222", "8800", "paid", "paid", "2026-11-06T09:12:00Z", "2026-11-06", ""],
        ["U1003", "O10003", "carol@example.com", "13700003333", "19900", "pending", "pending", "", "2026-11-08", "C11"],
        ["U1004", "O10003", "dave@example.com", "13600004444", "25900", "paid", "paid", "2026-11-05T18:30:00Z", "2026-11-05", ""],
        ["U1005", "O10005", "not-an-email", "13500005555", "-1200", "paid", "paid", "2026-11-05T20:01:00Z", "2026-11-05", "C12"],
        ["U1006", "O10006", "eve@example.com", "1340000", "3200", "paid", "paid", "2026-11-04T11:11:00Z", "2026-11-04", "C13"],
        ["U1007", "O10007", "frank@example.com", "13300007777", "4500", "shipped", "shipped", "2026-11-04T12:00:00Z", "2026-11-04", ""],
        ["U1008", "O10008", "grace@example.com", "13200008888", "9900", "refunded", "paid", "2026-11-03T08:45:00Z", "2026-11-03", "C14"],
        ["U1009", "O10009", "henry@example.com", "13100009999", "15000", "paid", "paid", "2026-09-20T08:00:00Z", "2026-09-20", ""],
        ["U1010", "O10010", "ivy@example.com", "13000001010", "6700", "pending", "pending", "", "2026-11-08", ""],
        ["U1011", "O10011", "jack@example.com", "18900001111", "230000", "paid", "paid", "2026-11-02T15:20:00Z", "2026-11-02", "C15"],
        ["U1012", "O10012", "kate@example.com", "18800002222", "600000", "paid", "paid", "2026-11-01T16:40:00Z", "2026-11-01", ""],
        ["U1013", "O10013", "leo@example.com", "18700003333", "5600", "cancelled", "cancelled", "", "2026-11-01", "C16"],
        ["U1014", "O10014", "mia@example.com", "18600004444", "7800", "paid", "paid", "", "2026-11-07", ""],
        ["U1015", "O10015", "nick@example.com", "18500005555", "8800", "paid", "paid", "2026-11-02T10:10:00Z", "2026-11-02", "C17"],
        ["U1016", "O10016", "olivia@example.com", "18400006666", "9900", "paid", "paid", "2026-11-08T00:20:00Z", "2026-11-08", "C18"],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _issues() -> list[dict[str, Any]]:
    """构造演示问题列表。"""
    raw = [
        ("Q-001", "completeness", "high", "user_id 存在空值", 14, "row 37: user_id=''", "open", "data-platform", "2026-10-30"),
        ("Q-002", "uniqueness", "high", "order_id 存在重复值", 6, "order_id=O10003", "open", "data-platform", "2026-10-31"),
        ("Q-003", "validity", "medium", "amount_cents 超出允许范围", 9, "amount_cents=-1200", "open", "payments-team", "2026-11-01"),
        ("Q-004", "validity", "medium", "email 格式不匹配", 4, "row 88: email=not-an-email", "fixed", "growth-team", "2026-10-28"),
        ("Q-005", "validity", "low", "phone 长度越界", 3, "row 103: phone=1340000", "open", "growth-team", "2026-11-02"),
        ("Q-006", "consistency", "medium", "status 与 payment_status 不一致", 2, "refunded != paid", "ignored", "payments-team", "2026-10-26"),
        ("Q-007", "timeliness", "high", "event_date 数据已过期", 3, "event_date=2026-09-20", "open", "data-platform", "2026-11-03"),
        ("Q-008", "completeness", "low", "coupon_code 存在空值", 25, "row 12: coupon_code=''", "fixed", "growth-team", "2026-10-25"),
    ]
    issues: list[dict[str, Any]] = []
    for item in raw:
        issues.append({
            "id": item[0],
            "dimension": item[1],
            "severity": item[2],
            "title": item[3],
            "count": item[4],
            "sample": item[5],
            "status": item[6],
            "owner": item[7],
            "first_seen": item[8],
        })
    return issues


def _distributions(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按问题列表计算严重度与维度分布。"""
    severity_labels = {"high": "高", "medium": "中", "low": "低"}
    severity_buckets = [
        {"label": severity_labels[key], "value": sum(1 for issue in issues if issue["severity"] == key)}
        for key in ("high", "medium", "low")
    ]
    dimension_buckets = [
        {
            "label": sc.DIMENSION_NAMES[key],
            "value": sum(1 for issue in issues if issue["dimension"] == key),
        }
        for key in sc.DIMENSION_KEYS
    ]
    return [
        {"name": "问题严重度分布", "buckets": severity_buckets},
        {"name": "问题维度分布", "buckets": dimension_buckets},
    ]


def _sample_report(lineage: dict[str, Any], pii: dict[str, Any]) -> dict[str, Any]:
    """组合完整演示报告。"""
    scores = {
        "completeness": 92.5,
        "uniqueness": 88.0,
        "validity": 76.4,
        "consistency": 95.0,
        "timeliness": 81.2,
    }
    dimensions = [
        {"key": key, "name": sc.DIMENSION_NAMES[key], "score": scores[key], "weight": sc.DEFAULT_WEIGHTS[key]}
        for key in sc.DIMENSION_KEYS
    ]
    issues = _issues()
    score = sc.weighted_score(dimensions)
    trend_dates = ["2026-10-01", "2026-10-08", "2026-10-15", "2026-10-22", "2026-10-29", "2026-11-05", "2026-11-08"]
    trend_scores = [71.2, 74.8, 73.5, 78.9, 81.4, 84.7, score]
    report = {
        "schema": sc.REPORT_SCHEMA,
        "generated_at": sc.iso_utc(NOW),
        "subject": {"name": "orders_daily", "version": "v2.4.1", "owner": "data-platform"},
        "summary": {
            "score": score,
            "grade": sc.grade_for(score),
            "checks_total": 1200,
            "checks_passed": 1104,
            "issues_total": len(issues),
            "issues_open": sum(1 for issue in issues if issue["status"] == "open"),
        },
        "dimensions": dimensions,
        "issues": issues,
        "distributions": _distributions(issues),
        "lineage": lineage,
        "pii": pii,
        "model_fitness": {
            "models": [
                {
                    "name": "quality-bert",
                    "metrics": {"f1": 0.91, "accuracy": 0.94, "coverage": 0.88},
                    "thresholds": {"f1": 0.90, "accuracy": 0.92, "coverage": 0.90},
                    "verdict": "warn",
                },
                {
                    "name": "rule-baseline",
                    "metrics": {"f1": 0.72, "accuracy": 0.80, "coverage": 0.70},
                    "thresholds": {"f1": 0.85, "accuracy": 0.82, "coverage": 0.75},
                    "verdict": "fail",
                },
                {
                    "name": "mini-llm",
                    "metrics": {"f1": 0.83, "accuracy": 0.86, "coverage": 0.82},
                    "thresholds": {"f1": 0.85, "accuracy": 0.88, "coverage": 0.80},
                    "verdict": "warn",
                },
            ],
        },
        "trend": [{"date": date, "score": value} for date, value in zip(trend_dates, trend_scores)],
    }
    return sc.normalize_report(report)


def main() -> int:
    """生成全部演示数据并打印文件清单。"""
    configure_stdout()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    write_json(LINEAGE_PATH, _lineage())
    write_json(PII_PATH, _pii())
    _write_demo_csv(DEMO_CSV)
    lineage = read_json(LINEAGE_PATH)
    pii = read_json(PII_PATH)
    report = _sample_report(lineage, pii)
    write_json(SAMPLE_REPORT, report)
    files = [DEMO_CSV, LINEAGE_PATH, PII_PATH, SAMPLE_REPORT]
    rows = [[str(path.relative_to(ROOT)), human_size(path.stat().st_size)] for path in files]
    print("generated demo assets")
    print(format_table(["file", "size"], rows, max_width=64))
    print(f"dimensions: {len(report['dimensions'])} / issues: {len(report['issues'])} / score: {report['summary']['score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
