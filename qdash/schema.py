"""报告 schema：定义、容错归一化与校验。

设计约束：
- 所有公共函数都不抛异常；缺字段补默认值，非法类型降级为 "—" 或 None。
- 报告顶层 schema 固定为 data-quality-report/1.0。
- lineage / pii 字段保留原始完整对象，渲染层再做只读容错访问。
"""

from __future__ import annotations

import copy
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

REPORT_SCHEMA = "data-quality-report/1.0"
LINEAGE_SCHEMA = "dataset-lineage/1.0"
PII_SCHEMA = "pii-hits/1.0"
RULES_SCHEMA = "quality-rules/1.0"
DASH = "—"

DIMENSION_NAMES: dict[str, str] = {
    "completeness": "完整性",
    "uniqueness": "唯一性",
    "validity": "有效性",
    "consistency": "一致性",
    "timeliness": "及时性",
}
DIMENSION_KEYS: tuple[str, ...] = tuple(DIMENSION_NAMES)
DEFAULT_WEIGHTS: dict[str, float] = {
    "completeness": 0.25,
    "uniqueness": 0.20,
    "validity": 0.25,
    "consistency": 0.15,
    "timeliness": 0.15,
}

SEVERITIES: tuple[str, ...] = ("high", "medium", "low")
ISSUE_STATUSES: tuple[str, ...] = ("open", "fixed", "ignored")
GRADES: tuple[str, ...] = ("A", "B", "C", "D", "E")
PII_LEVELS: tuple[str, ...] = ("high_sensitive", "sensitive", "general")
PII_CONFIDENCES: tuple[str, ...] = ("high", "medium", "low")
VERDICTS: tuple[str, ...] = ("pass", "warn", "fail")


# ---------------------------------------------------------------------------
# 基础类型转换：永不抛异常
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    """返回当前 UTC 时间（秒精度，时区感知）。"""
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(value: datetime | None = None) -> str:
    """格式化为 ISO 8601 UTC，例如 2026-11-08T01:35:00Z。"""
    moment = value or utc_now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def today_utc(value: datetime | None = None) -> str:
    """返回 UTC 日期字符串 YYYY-MM-DD。"""
    moment = value or utc_now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d")


def as_text(value: Any, default: str = DASH) -> str:
    """把值转成展示文本；非字符串/数值或空串时返回 default。"""
    if isinstance(value, str):
        return value if value != "" else default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return str(value)
    return default


def as_number(value: Any) -> float | None:
    """转成有限浮点数；无法转换或 NaN/Inf 时返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def as_int(value: Any, default: int = 0) -> int:
    """转成整数；失败时返回 default。"""
    number = as_number(value)
    if number is None:
        return default
    try:
        return int(number)
    except (OverflowError, ValueError):
        return default


def as_bool(value: Any, default: bool = False) -> bool:
    """宽松布尔转换：true/false/yes/no/1/0。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "y", "1", "on"):
            return True
        if text in ("false", "no", "n", "0", "off"):
            return False
    return default


def clamp(value: float, low: float, high: float) -> float:
    """把数值限制在 [low, high] 区间。"""
    return max(low, min(high, value))


def grade_for(score: float | None) -> str | None:
    """按分数返回等级：>=90 A，>=80 B，>=70 C，>=60 D，其余 E。"""
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "E"


def dimension_name(key: str) -> str:
    """返回维度中文名；未知 key 原样返回。"""
    return DIMENSION_NAMES.get(key, key)


def weighted_score(dimensions: list[Mapping[str, Any]]) -> float | None:
    """按权重计算总分；没有可用维度分数时返回 None。"""
    total_weight = 0.0
    total = 0.0
    for item in dimensions:
        score = as_number(item.get("score"))
        weight = as_number(item.get("weight"))
        if score is None or weight is None or weight <= 0:
            continue
        total += score * weight
        total_weight += weight
    if total_weight <= 0:
        return None
    return round(total / total_weight, 1)


def compare_verdict(
    metrics: Mapping[str, float | None],
    thresholds: Mapping[str, float | None],
) -> str | None:
    """比较模型指标与阈值，返回 pass/warn/fail；没有可比较项时返回 None。

    约定指标越大越好：实测 >= 阈值判 pass；低于阈值但差距在 10% 以内判
    warn；再低判 fail。
    """
    worst = 0
    compared = 0
    for key, threshold in thresholds.items():
        actual = metrics.get(key)
        if actual is None or threshold is None:
            continue
        compared += 1
        if threshold == 0:
            level = 0 if actual >= 0 else 2
        elif actual >= threshold:
            level = 0
        elif actual >= threshold * 0.9:
            level = 1
        else:
            level = 2
        worst = max(worst, level)
    if compared == 0:
        return None
    return VERDICTS[worst]


# ---------------------------------------------------------------------------
# 归一化
# ---------------------------------------------------------------------------


def empty_report(
    subject: Mapping[str, Any] | None = None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """构造字段齐全的空报告，所有维度分数为空、问题为空。"""
    dimensions = [
        {
            "key": key,
            "name": DIMENSION_NAMES[key],
            "score": None,
            "weight": DEFAULT_WEIGHTS[key],
        }
        for key in DIMENSION_KEYS
    ]
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at or iso_utc(),
        "subject": _normalize_subject(subject),
        "summary": {
            "score": None,
            "grade": DASH,
            "checks_total": 0,
            "checks_passed": 0,
            "issues_total": 0,
            "issues_open": 0,
        },
        "dimensions": dimensions,
        "issues": [],
        "distributions": [],
        "lineage": None,
        "pii": None,
        "model_fitness": {"models": []},
        "trend": [],
    }


def _normalize_subject(value: Any) -> dict[str, str]:
    raw = value if isinstance(value, Mapping) else {}
    return {
        "name": as_text(raw.get("name")),
        "version": as_text(raw.get("version")),
        "owner": as_text(raw.get("owner")),
    }


def _normalize_timestamp(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return iso_utc()


def _normalize_dimensions(value: Any) -> list[dict[str, Any]]:
    raw_map: dict[str, Mapping[str, Any]] = {}
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            key = item.get("key")
            if not isinstance(key, str):
                continue
            normalized_key = key.strip().lower()
            if normalized_key in DIMENSION_NAMES:
                raw_map.setdefault(normalized_key, item)
    dimensions: list[dict[str, Any]] = []
    for key in DIMENSION_KEYS:
        item = raw_map.get(key, {})
        score = as_number(item.get("score"))
        if score is not None:
            score = round(clamp(score, 0.0, 100.0), 1)
        weight = as_number(item.get("weight"))
        if weight is None or weight < 0:
            weight = DEFAULT_WEIGHTS[key]
        name = as_text(item.get("name"), DIMENSION_NAMES[key])
        dimensions.append({
            "key": key,
            "name": name,
            "score": score,
            "weight": round(weight, 4),
        })
    return dimensions


def _normalize_summary(value: Any, dimensions: list[dict[str, Any]]) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    score = as_number(raw.get("score"))
    if score is not None:
        score = round(clamp(score, 0.0, 100.0), 1)
    if score is None:
        score = weighted_score(dimensions)

    grade: str | None = None
    raw_grade = raw.get("grade")
    if isinstance(raw_grade, str):
        candidate = raw_grade.strip().upper()
        if candidate in GRADES:
            grade = candidate
    if grade is None:
        grade = grade_for(score)

    checks_total = max(as_int(raw.get("checks_total"), 0), 0)
    checks_passed = max(as_int(raw.get("checks_passed"), 0), 0)
    if checks_total > 0:
        checks_passed = min(checks_passed, checks_total)

    issues_total = max(as_int(raw.get("issues_total"), 0), 0)
    issues_open = max(as_int(raw.get("issues_open"), 0), 0)
    if issues_total > 0:
        issues_open = min(issues_open, issues_total)

    return {
        "score": score,
        "grade": grade or DASH,
        "checks_total": checks_total,
        "checks_passed": checks_passed,
        "issues_total": issues_total,
        "issues_open": issues_open,
    }


def _normalize_issues(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    issues: list[dict[str, Any]] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, Mapping):
            continue
        dimension = item.get("dimension")
        if not isinstance(dimension, str) or dimension.strip().lower() not in DIMENSION_NAMES:
            dimension = DASH
        else:
            dimension = dimension.strip().lower()
        severity = item.get("severity")
        if not isinstance(severity, str) or severity.strip().lower() not in SEVERITIES:
            severity = DASH
        else:
            severity = severity.strip().lower()
        status = item.get("status")
        if not isinstance(status, str) or status.strip().lower() not in ISSUE_STATUSES:
            status = DASH
        else:
            status = status.strip().lower()
        issues.append({
            "id": as_text(item.get("id"), f"Q-{index:03d}"),
            "dimension": dimension,
            "severity": severity,
            "title": as_text(item.get("title")),
            "count": max(as_int(item.get("count"), 0), 0),
            "sample": as_text(item.get("sample"), DASH),
            "status": status,
            "owner": as_text(item.get("owner")),
            "first_seen": as_text(item.get("first_seen")),
        })
    return issues


def _normalize_model_fitness(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, Mapping) else {}
    raw_models = raw.get("models")
    if not isinstance(raw_models, list):
        raw_models = []
    models: list[dict[str, Any]] = []
    for index, item in enumerate(raw_models, start=1):
        if not isinstance(item, Mapping):
            continue
        metrics: dict[str, float | None] = {}
        raw_metrics = item.get("metrics")
        if isinstance(raw_metrics, Mapping):
            for key, metric in raw_metrics.items():
                if isinstance(key, str):
                    metrics[key] = as_number(metric)
        thresholds: dict[str, float | None] = {}
        raw_thresholds = item.get("thresholds")
        if isinstance(raw_thresholds, Mapping):
            for key, threshold in raw_thresholds.items():
                if isinstance(key, str):
                    thresholds[key] = as_number(threshold)
        computed = compare_verdict(metrics, thresholds)
        explicit = item.get("verdict")
        explicit_text = explicit.strip().lower() if isinstance(explicit, str) else ""
        if computed is not None:
            verdict = computed
        elif explicit_text in VERDICTS:
            verdict = explicit_text
        else:
            verdict = DASH
        models.append({
            "name": as_text(item.get("name"), f"model-{index}"),
            "metrics": metrics,
            "thresholds": thresholds,
            "verdict": verdict,
        })
    return {"models": models}


def _normalize_distributions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    distributions: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        buckets: list[dict[str, Any]] = []
        raw_buckets = item.get("buckets")
        if isinstance(raw_buckets, list):
            for bucket in raw_buckets:
                if not isinstance(bucket, Mapping):
                    continue
                buckets.append({
                    "label": as_text(bucket.get("label")),
                    "value": max(as_int(bucket.get("value"), 0), 0),
                })
        distributions.append({
            "name": as_text(item.get("name"), "未命名分布"),
            "buckets": buckets,
        })
    return distributions


def _normalize_trend(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    points: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        score = as_number(item.get("score"))
        if score is None:
            continue
        points.append({
            "date": as_text(item.get("date")),
            "score": round(clamp(score, 0.0, 100.0), 1),
        })
    points.sort(key=lambda point: point["date"] if point["date"] != DASH else "9999-99-99")
    return points


def _copy_artifact(value: Any) -> dict[str, Any] | None:
    """lineage / pii 保留完整对象（深拷贝），非对象视为缺失。"""
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return None


def normalize_report(raw: Any) -> dict[str, Any]:
    """把任意输入归一化成字段齐全的报告；永不抛异常。

    - 缺字段补默认值。
    - 字符串字段非法类型降级为 "—"，数值字段非法类型降级为 None。
    - 缺失维度补齐为五个固定 key。
    - summary.score 缺失时按维度加权分推导。
    """
    source = raw if isinstance(raw, Mapping) else {}
    dimensions = _normalize_dimensions(source.get("dimensions"))
    summary = _normalize_summary(source.get("summary"), dimensions)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "generated_at": _normalize_timestamp(source.get("generated_at")),
        "subject": _normalize_subject(source.get("subject")),
        "summary": summary,
        "dimensions": dimensions,
        "issues": _normalize_issues(source.get("issues")),
        "distributions": _normalize_distributions(source.get("distributions")),
        "lineage": _copy_artifact(source.get("lineage")),
        "pii": _copy_artifact(source.get("pii")),
        "model_fitness": _normalize_model_fitness(source.get("model_fitness")),
        "trend": _normalize_trend(source.get("trend")),
    }
    return report


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationResult:
    """校验结果：errors 非空即视为不通过，warnings 只提示不阻断。"""

    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """没有 error 时返回 True。"""
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        """转成可 JSON 序列化的字典。"""
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_report(raw: Any) -> ValidationResult:
    """校验报告结构与取值，返回错误 / 警告列表；永不抛异常。"""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(raw, Mapping):
        return ValidationResult(("report must be a JSON object",), ())

    if raw.get("schema") != REPORT_SCHEMA:
        errors.append(f"schema must be '{REPORT_SCHEMA}'")

    if not isinstance(raw.get("generated_at"), str) or not str(raw.get("generated_at")).strip():
        warnings.append("generated_at missing or not a string")

    subject = raw.get("subject")
    if not isinstance(subject, Mapping):
        warnings.append("subject must be an object")
    else:
        for key in ("name", "version", "owner"):
            if key not in subject:
                warnings.append(f"subject.{key} missing")

    summary = raw.get("summary")
    if not isinstance(summary, Mapping):
        warnings.append("summary must be an object")
    else:
        score = as_number(summary.get("score"))
        if score is not None and not 0.0 <= score <= 100.0:
            warnings.append("summary.score must be within 0..100")
        if score is not None:
            raw_grade = summary.get("grade")
            expected = grade_for(score)
            if not isinstance(raw_grade, str) or raw_grade.strip().upper() not in GRADES:
                warnings.append("summary.grade missing or invalid")
            elif raw_grade.strip().upper() != expected:
                warnings.append(f"summary.grade {raw_grade!r} does not match score grade {expected!r}")
        for key in ("checks_total", "checks_passed", "issues_total", "issues_open"):
            if not _is_non_negative_int(summary.get(key)):
                warnings.append(f"summary.{key} must be a non-negative integer")
        checks_total = as_int(summary.get("checks_total"), 0)
        checks_passed = as_int(summary.get("checks_passed"), 0)
        if checks_total > 0 and checks_passed > checks_total:
            warnings.append("summary.checks_passed must not exceed checks_total")
        issues_total = as_int(summary.get("issues_total"), 0)
        issues_open = as_int(summary.get("issues_open"), 0)
        if issues_total > 0 and issues_open > issues_total:
            warnings.append("summary.issues_open must not exceed issues_total")

    dimensions = raw.get("dimensions")
    if not isinstance(dimensions, list):
        warnings.append("dimensions must be an array")
    else:
        seen: set[str] = set()
        total_weight = 0.0
        for index, item in enumerate(dimensions):
            if not isinstance(item, Mapping):
                warnings.append(f"dimensions[{index}] must be an object")
                continue
            key = item.get("key")
            if not isinstance(key, str) or key not in DIMENSION_NAMES:
                warnings.append(f"dimensions[{index}].key must be one of {', '.join(DIMENSION_KEYS)}")
            elif key in seen:
                warnings.append(f"dimensions contains duplicate key {key!r}")
            else:
                seen.add(key)
            score = as_number(item.get("score"))
            if score is not None and not 0.0 <= score <= 100.0:
                warnings.append(f"dimensions[{index}].score must be within 0..100")
            weight = as_number(item.get("weight"))
            if weight is None or weight < 0:
                warnings.append(f"dimensions[{index}].weight must be a non-negative number")
            else:
                total_weight += weight
        missing = [key for key in DIMENSION_KEYS if key not in seen]
        if missing:
            warnings.append("dimensions missing keys: " + ", ".join(missing))
        if dimensions and seen and abs(total_weight - 1.0) > 1e-6:
            warnings.append(f"dimensions weights sum to {total_weight:.4f}, expected 1.0")

    issues = raw.get("issues")
    if not isinstance(issues, list):
        warnings.append("issues must be an array")
    else:
        for index, item in enumerate(issues):
            if not isinstance(item, Mapping):
                warnings.append(f"issues[{index}] must be an object")
                continue
            if item.get("dimension") not in DIMENSION_NAMES:
                warnings.append(f"issues[{index}].dimension invalid")
            if item.get("severity") not in SEVERITIES:
                warnings.append(f"issues[{index}].severity invalid")
            if item.get("status") not in ISSUE_STATUSES:
                warnings.append(f"issues[{index}].status invalid")
            if not _is_non_negative_int(item.get("count")):
                warnings.append(f"issues[{index}].count must be a non-negative integer")

    lineage = raw.get("lineage")
    if lineage is not None:
        if not isinstance(lineage, Mapping):
            warnings.append("lineage must be an object or null")
        else:
            if lineage.get("schema") != LINEAGE_SCHEMA:
                warnings.append(f"lineage.schema must be '{LINEAGE_SCHEMA}'")
            if not isinstance(lineage.get("nodes"), list):
                warnings.append("lineage.nodes must be an array")
            if not isinstance(lineage.get("edges"), list):
                warnings.append("lineage.edges must be an array")

    pii = raw.get("pii")
    if pii is not None:
        if not isinstance(pii, Mapping):
            warnings.append("pii must be an object or null")
        else:
            if pii.get("schema") != PII_SCHEMA:
                warnings.append(f"pii.schema must be '{PII_SCHEMA}'")
            if not isinstance(pii.get("findings"), list):
                warnings.append("pii.findings must be an array")
            if not isinstance(pii.get("summary"), Mapping):
                warnings.append("pii.summary must be an object")

    if "model_fitness" in raw:
        fitness = raw.get("model_fitness")
        if not isinstance(fitness, Mapping):
            warnings.append("model_fitness must be an object")
        else:
            models = fitness.get("models")
            if not isinstance(models, list):
                warnings.append("model_fitness.models must be an array")
            else:
                for index, model in enumerate(models):
                    if not isinstance(model, Mapping):
                        warnings.append(f"model_fitness.models[{index}] must be an object")
                        continue
                    if not isinstance(model.get("metrics"), Mapping):
                        warnings.append(f"model_fitness.models[{index}].metrics must be an object")
                    if not isinstance(model.get("thresholds"), Mapping):
                        warnings.append(f"model_fitness.models[{index}].thresholds must be an object")
                    if model.get("verdict") not in VERDICTS:
                        warnings.append(f"model_fitness.models[{index}].verdict invalid")

    trend = raw.get("trend")
    if not isinstance(trend, list):
        warnings.append("trend must be an array")
    else:
        for index, point in enumerate(trend):
            if not isinstance(point, Mapping):
                warnings.append(f"trend[{index}] must be an object")
                continue
            if as_number(point.get("score")) is None:
                warnings.append(f"trend[{index}].score must be a number")

    distributions = raw.get("distributions")
    if not isinstance(distributions, list):
        warnings.append("distributions must be an array")

    return ValidationResult(tuple(errors), tuple(warnings))
