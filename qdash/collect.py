"""扫描产物目录，把 lineage / pii-hits 合并进统一报告。

规则：
- 只按顶层 "schema" 字段识别，文件是否叫 lineage.json 不影响结果。
- 同一份 lineage（按 name 归并）取 finished_at 最新的；同源 PII（按 source
  归并）取 generated_at 最新的。
- 多个不同来源的 PII 汇总成一个对象：findings 合并、summary 重算、source
  用 "; " 连接。单个来源时原样内嵌，保持 3.2 契约不变。
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .jsonio import read_json
from .schema import (
    LINEAGE_SCHEMA,
    PII_CONFIDENCES,
    PII_LEVELS,
    PII_SCHEMA,
    empty_report,
    normalize_report,
)

MAX_ERRORS = 50


@dataclass
class CollectStats:
    """一次扫描的统计信息。"""

    scanned: int = 0
    recognized: int = 0
    lineage_files: int = 0
    pii_files: int = 0
    ignored: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class CollectResult:
    """collect 的结果：合并后的报告 + 扫描统计。"""

    report: dict[str, Any]
    stats: CollectStats


def _parse_moment(value: Any) -> datetime | None:
    """解析 ISO 8601 时间；失败返回 None。"""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _file_epoch(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _lineage_moment(data: Mapping[str, Any], path: Path) -> float:
    for key in ("finished_at", "started_at"):
        moment = _parse_moment(data.get(key))
        if moment is not None:
            return moment.timestamp()
    return _file_epoch(path)


def _pii_moment(data: Mapping[str, Any], path: Path) -> float:
    moment = _parse_moment(data.get("generated_at"))
    if moment is not None:
        return moment.timestamp()
    return _file_epoch(path)


def _lineage_source(data: Mapping[str, Any], path: Path) -> str:
    for key in ("name", "run_id"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return path.stem


def _pii_source(data: Mapping[str, Any], path: Path) -> str:
    value = data.get("source")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return path.stem


def _iter_json_files(root: Path) -> list[Path]:
    if root.is_dir():
        return sorted(path for path in root.rglob("*.json") if path.is_file())
    return [root]


def _append_error(stats: CollectStats, message: str) -> None:
    if len(stats.errors) < MAX_ERRORS:
        stats.errors.append(message)
    elif len(stats.errors) == MAX_ERRORS:
        stats.errors.append("... more errors omitted")


def _pii_summary(findings: list[Mapping[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_confidence = {key: 0 for key in PII_CONFIDENCES}
    by_level = {key: 0 for key in PII_LEVELS}
    for finding in findings:
        finding_type = finding.get("type")
        if isinstance(finding_type, str) and finding_type:
            by_type[finding_type] = by_type.get(finding_type, 0) + 1
        confidence = finding.get("confidence")
        if isinstance(confidence, str) and confidence in by_confidence:
            by_confidence[confidence] += 1
        level = finding.get("level")
        if isinstance(level, str) and level in by_level:
            by_level[level] += 1
    return {
        "total": len(findings),
        "by_type": by_type,
        "by_confidence": by_confidence,
        "by_level": by_level,
    }


def _aggregate_pii(entries: list[tuple[str, Mapping[str, Any]]]) -> dict[str, Any]:
    """把多个来源的 pii-hits 汇总成一个契约内对象。"""
    findings: list[dict[str, Any]] = []
    ruleset: dict[str, Any] = {"name": "unknown", "version": "unknown", "file": None}
    latest_generated = ""
    sources: list[str] = []
    for source, data in entries:
        sources.append(source)
        raw_findings = data.get("findings")
        if isinstance(raw_findings, list):
            for finding in raw_findings:
                if isinstance(finding, Mapping):
                    findings.append(copy.deepcopy(dict(finding)))
        raw_ruleset = data.get("ruleset")
        if isinstance(raw_ruleset, Mapping):
            ruleset = copy.deepcopy(dict(raw_ruleset))
        generated = data.get("generated_at")
        if isinstance(generated, str) and generated > latest_generated:
            latest_generated = generated
    return {
        "schema": PII_SCHEMA,
        "source": "; ".join(sorted(set(sources))),
        "generated_at": latest_generated,
        "findings": findings,
        "summary": _pii_summary(findings),
        "ruleset": ruleset,
    }


def _select_latest_lineage(
    candidates: list[tuple[float, str, str, dict[str, Any]]],
) -> dict[str, Any]:
    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return candidates[-1][3]


def _select_latest_pii(
    candidates: list[tuple[float, str, str, dict[str, Any]]],
) -> dict[str, Any] | None:
    if not candidates:
        return None
    latest: dict[str, tuple[float, str, str, dict[str, Any]]] = {}
    for item in candidates:
        source = item[1]
        previous = latest.get(source)
        if previous is None or (item[0], item[2]) >= (previous[0], previous[2]):
            latest[source] = item
    entries = [(source, item[3]) for source, item in sorted(latest.items())]
    if len(entries) == 1:
        return copy.deepcopy(entries[0][1])
    return _aggregate_pii(entries)


def collect_artifacts(
    root: str | Path,
    base_report: Mapping[str, Any] | None = None,
) -> CollectResult:
    """扫描目录（或单个文件），把 lineage / pii-hits 合并进报告。

    缺失产物时对应字段保持 None；目录不存在时抛 FileNotFoundError。
    解析失败的 JSON 只记录到 stats.errors，不中断扫描。
    """
    target = Path(root)
    if not target.exists():
        raise FileNotFoundError(str(target))

    stats = CollectStats()
    report = normalize_report(base_report) if isinstance(base_report, Mapping) else empty_report()

    lineage_candidates: list[tuple[float, str, str, dict[str, Any]]] = []
    pii_candidates: list[tuple[float, str, str, dict[str, Any]]] = []

    for path in _iter_json_files(target):
        stats.scanned += 1
        try:
            data = read_json(path)
        except (OSError, ValueError) as exc:
            stats.skipped += 1
            _append_error(stats, f"{path.name}: {type(exc).__name__}: {exc}"[:300])
            continue
        if not isinstance(data, Mapping):
            stats.skipped += 1
            _append_error(stats, f"{path.name}: top-level JSON value is not an object")
            continue

        schema = data.get("schema")
        if schema == LINEAGE_SCHEMA:
            stats.recognized += 1
            stats.lineage_files += 1
            lineage_candidates.append((
                _lineage_moment(data, path),
                _lineage_source(data, path),
                path.name,
                copy.deepcopy(dict(data)),
            ))
        elif schema == PII_SCHEMA:
            stats.recognized += 1
            stats.pii_files += 1
            pii_candidates.append((
                _pii_moment(data, path),
                _pii_source(data, path),
                path.name,
                copy.deepcopy(dict(data)),
            ))
        else:
            stats.ignored += 1

    if lineage_candidates:
        report["lineage"] = _select_latest_lineage(lineage_candidates)
    if pii_candidates:
        selected = _select_latest_pii(pii_candidates)
        if selected is not None:
            report["pii"] = selected

    return CollectResult(report=normalize_report(report), stats=stats)
