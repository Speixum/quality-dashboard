"""CSV / JSONL 质量规则引擎。

规则由 JSON 定义，支持 required / unique / range / regex / enum / length /
freshness / consistency 八种类型。评估结果直接产出 data-quality-report/1.0
所需的 dimensions / issues / summary 片段。

约定：
- 除 required 外，所有规则跳过空值（空值属于完整性维度，避免重复计分）。
- 每条规则对每一行计一次检查，checks = 行数；维度分 = 通过检查 / 总检查。
- 规则配置错误不会中断评估，只记录 warning 并跳过该规则。
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .jsonio import read_json
from .schema import (
    DASH,
    DEFAULT_WEIGHTS,
    DIMENSION_NAMES,
    ISSUE_STATUSES,
    RULES_SCHEMA,
    SEVERITIES,
    as_bool,
    as_int,
    as_number,
    as_text,
    grade_for,
    iso_utc,
    normalize_report,
    today_utc,
    utc_now,
    weighted_score,
)

RULE_TYPES: tuple[str, ...] = (
    "required",
    "unique",
    "range",
    "regex",
    "enum",
    "length",
    "freshness",
    "consistency",
)
TYPE_DIMENSION: dict[str, str] = {
    "required": "completeness",
    "unique": "uniqueness",
    "range": "validity",
    "regex": "validity",
    "enum": "validity",
    "length": "validity",
    "freshness": "timeliness",
    "consistency": "consistency",
}
REGEX_MODES: tuple[str, ...] = ("fullmatch", "match", "search")
DEFAULT_OWNER = "data-platform"


@dataclass
class Dataset:
    """加载后的表格数据：列名 + 行字典 + 解析警告。"""

    columns: list[str]
    rows: list[dict[str, Any]]
    source: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class RuleResult:
    """单条规则的执行结果（供 CLI 打印）。"""

    id: str
    type: str
    column: str
    dimension: str
    severity: str
    violations: int
    checks: int
    title: str


@dataclass
class RuleRunResult:
    """规则评估结果：报告 + 警告 + 每条规则统计。"""

    report: dict[str, Any]
    warnings: list[str]
    rule_results: list[RuleResult]


@dataclass
class RuleLoadResult:
    """规则文件加载结果。"""

    rules: list[dict[str, Any]]
    warnings: list[str]


# ---------------------------------------------------------------------------
# 数据集加载
# ---------------------------------------------------------------------------


def _load_csv(path: Path) -> Dataset:
    warnings: list[str] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            columns = [str(name) for name in (reader.fieldnames or []) if name is not None]
            if not columns:
                warnings.append("csv file has no header row")
                return Dataset([], [], str(path), warnings)
            rows: list[dict[str, Any]] = []
            for raw in reader:
                row: dict[str, Any] = {}
                for column in columns:
                    value = raw.get(column)
                    row[column] = "" if value is None else value
                rows.append(row)
    except OSError as exc:
        raise OSError(f"cannot read dataset: {exc}") from exc
    return Dataset(columns, rows, str(path), warnings)


def _load_jsonl(path: Path) -> Dataset:
    warnings: list[str] = []
    rows: list[dict[str, Any]] = []
    columns: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    item = json.loads(text)
                except json.JSONDecodeError as exc:
                    warnings.append(f"line {line_number}: invalid JSON skipped ({exc.msg})")
                    continue
                if not isinstance(item, Mapping):
                    warnings.append(f"line {line_number}: non-object row skipped")
                    continue
                row = dict(item)
                rows.append(row)
                for key in row:
                    if isinstance(key, str) and key not in seen:
                        seen.add(key)
                        columns.append(key)
    except OSError as exc:
        raise OSError(f"cannot read dataset: {exc}") from exc
    return Dataset(columns, rows, str(path), warnings)


def load_dataset(path: str | Path) -> Dataset:
    """按扩展名加载 CSV 或 JSONL；格式不支持时抛 ValueError。"""
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix == ".csv":
        return _load_csv(target)
    if suffix in (".jsonl", ".ndjson"):
        return _load_jsonl(target)
    raise ValueError(f"unsupported dataset format: {suffix or '<none>'}")


# ---------------------------------------------------------------------------
# 规则加载
# ---------------------------------------------------------------------------


def _clean_owner(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _consistency_columns(rule: Mapping[str, Any]) -> list[str]:
    raw_columns = rule.get("columns")
    columns: list[str] = []
    if isinstance(raw_columns, list):
        for item in raw_columns:
            if isinstance(item, str) and item.strip():
                columns.append(item.strip())
    if len(columns) >= 2:
        return columns
    left = rule.get("column")
    right = rule.get("compare")
    if isinstance(left, str) and isinstance(right, str) and left.strip() and right.strip():
        return [left.strip(), right.strip()]
    return []


def normalize_rule(raw: Any, index: int = 1) -> tuple[dict[str, Any] | None, str | None]:
    """校验并补齐一条规则；返回 (规则, 警告)。配置非法时规则为 None。"""
    if not isinstance(raw, Mapping):
        return None, f"rule #{index}: must be an object"
    rule_type = raw.get("type")
    if not isinstance(rule_type, str) or rule_type.strip().lower() not in RULE_TYPES:
        return None, f"rule #{index}: unsupported type {rule_type!r}"
    rule_type = rule_type.strip().lower()

    if rule_type == "consistency" and not _consistency_columns(raw):
        return None, f"rule #{index}: consistency needs two columns"
    column = raw.get("column")
    if rule_type != "consistency" and (not isinstance(column, str) or not column.strip()):
        return None, f"rule #{index}: missing column"
    if not isinstance(column, str):
        column = ""

    raw_id = raw.get("id")
    rule_id = raw_id.strip() if isinstance(raw_id, str) and raw_id.strip() else f"R-{index:03d}"

    dimension = raw.get("dimension")
    if not isinstance(dimension, str) or dimension.strip().lower() not in DIMENSION_NAMES:
        dimension = TYPE_DIMENSION[rule_type]
    else:
        dimension = dimension.strip().lower()

    severity = raw.get("severity")
    if not isinstance(severity, str) or severity.strip().lower() not in SEVERITIES:
        severity = "medium"
    else:
        severity = severity.strip().lower()

    status = raw.get("status")
    if not isinstance(status, str) or status.strip().lower() not in ISSUE_STATUSES:
        status = "open"
    else:
        status = status.strip().lower()

    raw_title = raw.get("title")
    title = raw_title.strip() if isinstance(raw_title, str) else ""

    normalized = dict(raw)
    normalized.update({
        "id": rule_id,
        "type": rule_type,
        "column": column.strip(),
        "dimension": dimension,
        "severity": severity,
        "status": status,
        "owner": _clean_owner(raw.get("owner")),
        "title": title,
    })
    return normalized, None


def load_rules(path: str | Path) -> RuleLoadResult:
    """读取 JSON 规则文件；支持顶层数组或 {schema, rules: []} 两种形式。"""
    data = read_json(path)
    warnings: list[str] = []
    raw_rules: Any
    if isinstance(data, list):
        raw_rules = data
    elif isinstance(data, Mapping):
        schema = data.get("schema")
        if schema is not None and schema != RULES_SCHEMA:
            warnings.append(f"unexpected rules schema {schema!r}, expected {RULES_SCHEMA!r}")
        raw_rules = data.get("rules")
        if raw_rules is None:
            return RuleLoadResult([], warnings + ["rules file has no 'rules' array"])
    else:
        return RuleLoadResult([], ["rules file must be an object or array"])

    if not isinstance(raw_rules, list):
        return RuleLoadResult([], warnings + ["'rules' must be an array"])

    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_rules, start=1):
        rule, warning = normalize_rule(raw, index)
        if warning is not None:
            warnings.append(warning)
            continue
        if rule is None:
            continue
        if rule["id"] in seen_ids:
            replacement = f"{rule['id']}-{index}"
            warnings.append(f"duplicate rule id {rule['id']!r}, renamed to {replacement!r}")
            rule["id"] = replacement
        seen_ids.add(rule["id"])
        rules.append(rule)
    return RuleLoadResult(rules, warnings)


# ---------------------------------------------------------------------------
# 单条规则实现
# ---------------------------------------------------------------------------


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    return isinstance(value, str) and value.strip() == ""


def _sample(value: Any, limit: int = 40) -> str:
    if _is_empty(value):
        return "--"
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    return text[:limit] if text else "--"


def _iter_values(rows: Sequence[Mapping[str, Any]], column: str) -> Iterator[Any]:
    for row in rows:
        yield row.get(column)


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
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
        moment = None
        for pattern in ("%Y/%m/%d", "%Y-%m-%d %H:%M:%S", "%Y%m%d"):
            try:
                moment = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
        if moment is None:
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _check_required(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            violations += 1
            sample = sample or "--"
    return violations, sample, None


def _check_unique(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    case_insensitive = as_bool(rule.get("case_insensitive"))
    counts: dict[str, int] = {}
    display: dict[str, Any] = {}
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        key = str(value).strip()
        if case_insensitive:
            key = key.lower()
        counts[key] = counts.get(key, 0) + 1
        display.setdefault(key, value)
    duplicates = 0
    sample = ""
    for key, count in counts.items():
        if count > 1:
            duplicates += count - 1
            if not sample:
                sample = _sample(display[key])
    return duplicates, sample, None


def _check_range(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    minimum = as_number(rule.get("min"))
    maximum = as_number(rule.get("max"))
    if minimum is None and maximum is None:
        return 0, "", "range needs 'min' or 'max'"
    if minimum is not None and maximum is not None and minimum > maximum:
        return 0, "", "range min is greater than max"
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        number = as_number(value)
        failed = number is None
        if number is not None:
            if minimum is not None and number < minimum:
                failed = True
            if maximum is not None and number > maximum:
                failed = True
        if failed:
            violations += 1
            sample = sample or _sample(value)
    return violations, sample, None


def _check_regex(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    pattern = rule.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return 0, "", "regex needs a non-empty 'pattern'"
    flags = 0
    raw_flags = rule.get("flags")
    if isinstance(raw_flags, str):
        flag_map = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
        for char in raw_flags.lower():
            if char not in flag_map:
                return 0, "", f"unsupported regex flag {char!r}"
            flags |= flag_map[char]
    mode = rule.get("mode", "fullmatch")
    if not isinstance(mode, str) or mode not in REGEX_MODES:
        return 0, "", "regex mode must be fullmatch, match or search"
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return 0, "", f"invalid regex: {exc}"
    matcher = getattr(compiled, mode)
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        text = value if isinstance(value, str) else str(value)
        if matcher(text) is None:
            violations += 1
            sample = sample or _sample(value)
    return violations, sample, None


def _check_enum(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    raw_values = rule.get("values")
    if not isinstance(raw_values, list) or not raw_values:
        return 0, "", "enum needs a non-empty 'values' array"
    allowed = {str(item) for item in raw_values if not isinstance(item, (Mapping, list))}
    case_insensitive = as_bool(rule.get("case_insensitive"))
    if case_insensitive:
        allowed = {item.lower() for item in allowed}
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        text = value if isinstance(value, str) else str(value)
        if case_insensitive:
            text = text.lower()
        if text not in allowed:
            violations += 1
            sample = sample or _sample(value)
    return violations, sample, None


def _check_length(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    minimum = as_number(rule.get("min"))
    maximum = as_number(rule.get("max"))
    if minimum is None and maximum is None:
        return 0, "", "length needs 'min' or 'max'"
    if minimum is not None and maximum is not None and minimum > maximum:
        return 0, "", "length min is greater than max"
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        size = len(value if isinstance(value, str) else str(value))
        failed = (minimum is not None and size < minimum) or (maximum is not None and size > maximum)
        if failed:
            violations += 1
            sample = sample or _sample(value)
    return violations, sample, None


def _check_freshness(
    rows: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    now: datetime,
) -> tuple[int, str, str | None]:
    column = str(rule["column"])
    max_days = as_number(rule.get("max_days"))
    if max_days is None or max_days < 0:
        return 0, "", "freshness needs a non-negative 'max_days'"
    allow_future_days = as_number(rule.get("allow_future_days"))
    if allow_future_days is None or allow_future_days < 0:
        allow_future_days = 0.0
    violations = 0
    sample = ""
    for value in _iter_values(rows, column):
        if _is_empty(value):
            continue
        moment = _parse_datetime(value)
        if moment is None:
            violations += 1
            sample = sample or _sample(value)
            continue
        age_days = (now - moment).total_seconds() / 86400.0
        if age_days > max_days or age_days < -allow_future_days:
            violations += 1
            sample = sample or _sample(value)
    return violations, sample, None


def _check_consistency(rows: Sequence[Mapping[str, Any]], rule: Mapping[str, Any]) -> tuple[int, str, str | None]:
    columns = _consistency_columns(rule)
    if len(columns) < 2:
        return 0, "", "consistency needs two columns"
    mode = rule.get("mode", "equal")
    if not isinstance(mode, str) or mode != "equal":
        return 0, "", "consistency mode currently supports 'equal' only"
    case_insensitive = as_bool(rule.get("case_insensitive"))
    violations = 0
    sample = ""
    for row in rows:
        values: list[str] = []
        empty = False
        for column in columns:
            value = row.get(column)
            if _is_empty(value):
                empty = True
                break
            text = str(value).strip()
            values.append(text.lower() if case_insensitive else text)
        if empty:
            continue
        if len(set(values)) > 1:
            violations += 1
            if not sample:
                sample = _sample(" != ".join(values))
    return violations, sample, None


def _apply_rule(
    rows: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    now: datetime,
) -> tuple[int, str, str | None]:
    rule_type = str(rule["type"])
    if rule_type == "required":
        return _check_required(rows, rule)
    if rule_type == "unique":
        return _check_unique(rows, rule)
    if rule_type == "range":
        return _check_range(rows, rule)
    if rule_type == "regex":
        return _check_regex(rows, rule)
    if rule_type == "enum":
        return _check_enum(rows, rule)
    if rule_type == "length":
        return _check_length(rows, rule)
    if rule_type == "freshness":
        return _check_freshness(rows, rule, now)
    if rule_type == "consistency":
        return _check_consistency(rows, rule)
    return 0, "", f"unsupported rule type {rule_type!r}"


def _rule_label(rule: Mapping[str, Any]) -> str:
    if rule.get("type") == "consistency":
        columns = _consistency_columns(rule)
        return " / ".join(columns) if columns else str(rule.get("column", DASH))
    return str(rule.get("column", DASH))


def _default_title(rule: Mapping[str, Any]) -> str:
    rule_type = str(rule.get("type"))
    label = _rule_label(rule)
    templates = {
        "required": f"{label} 存在空值",
        "unique": f"{label} 存在重复值",
        "range": f"{label} 超出允许范围",
        "regex": f"{label} 格式不匹配",
        "enum": f"{label} 取值不在枚举范围",
        "length": f"{label} 长度越界",
        "freshness": f"{label} 数据已过期",
        "consistency": f"{label} 不一致",
    }
    return templates.get(rule_type, f"{label} 未通过 {rule_type} 检查")


def _coerce_now(value: datetime | str | None) -> datetime:
    if value is None:
        return utc_now()
    if isinstance(value, datetime):
        moment = value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).replace(microsecond=0)
    if isinstance(value, str):
        parsed = _parse_datetime(value)
        if parsed is not None:
            return parsed.replace(microsecond=0)
    return utc_now()


def _issue_distributions(issues: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    severity_labels = {"high": "高", "medium": "中", "low": "低"}
    severity_buckets = [
        {"label": severity_labels[key], "value": sum(1 for issue in issues if issue.get("severity") == key)}
        for key in ("high", "medium", "low")
    ]
    dimension_buckets = [
        {
            "label": DIMENSION_NAMES[key],
            "value": sum(1 for issue in issues if issue.get("dimension") == key),
        }
        for key in DEFAULT_WEIGHTS
    ]
    return [
        {"name": "问题严重度分布", "buckets": severity_buckets},
        {"name": "问题维度分布", "buckets": dimension_buckets},
    ]


# ---------------------------------------------------------------------------
# 评估入口
# ---------------------------------------------------------------------------


def evaluate(
    dataset: Dataset,
    rules: Sequence[Mapping[str, Any]],
    *,
    subject: Mapping[str, Any] | None = None,
    now: datetime | str | None = None,
    generated_at: str | None = None,
) -> RuleRunResult:
    """执行规则并生成完整报告。

    - 空数据集不产生 issue，也不产生维度分（显示为 "—"）。
    - 规则配置错误只写 warning，不影响其他规则。
    """
    moment = _coerce_now(now)
    today = today_utc(moment)
    warnings: list[str] = list(dataset.warnings)
    subject_raw = subject if isinstance(subject, Mapping) else {}
    default_name = Path(dataset.source).stem if dataset.source else "dataset"
    subject_out = {
        "name": as_text(subject_raw.get("name"), default_name),
        "version": as_text(subject_raw.get("version"), "v0"),
        "owner": as_text(subject_raw.get("owner"), DEFAULT_OWNER),
    }

    row_count = len(dataset.rows)
    checks_by_dimension: dict[str, int] = {key: 0 for key in DEFAULT_WEIGHTS}
    violations_by_dimension: dict[str, int] = {key: 0 for key in DEFAULT_WEIGHTS}
    rule_results: list[RuleResult] = []
    issues: list[dict[str, Any]] = []
    checks_total = 0
    violations_total = 0

    for index, raw_rule in enumerate(rules, start=1):
        rule, warning = normalize_rule(raw_rule, index)
        if warning is not None:
            warnings.append(warning)
            continue
        if rule is None:
            continue
        violations, sample, config_warning = _apply_rule(dataset.rows, rule, moment)
        if config_warning is not None:
            warnings.append(f"rule {rule['id']}: {config_warning}")
            continue

        checks = row_count
        checks_total += checks
        violations_total += violations
        dimension = str(rule["dimension"])
        title = str(rule["title"]) or _default_title(rule)
        label = _rule_label(rule)
        checks_by_dimension[dimension] += checks
        violations_by_dimension[dimension] += violations
        rule_results.append(RuleResult(
            id=str(rule["id"]),
            type=str(rule["type"]),
            column=label,
            dimension=dimension,
            severity=str(rule["severity"]),
            violations=violations,
            checks=checks,
            title=title,
        ))
        if violations > 0:
            issue_owner = str(rule.get("owner") or subject_out["owner"])
            issues.append({
                "id": f"Q-{len(issues) + 1:03d}",
                "dimension": dimension,
                "severity": str(rule["severity"]),
                "title": title,
                "count": violations,
                "sample": sample or "--",
                "status": str(rule["status"]),
                "owner": issue_owner,
                "first_seen": today,
            })

    dimensions: list[dict[str, Any]] = []
    for key in DEFAULT_WEIGHTS:
        checks = checks_by_dimension[key]
        if checks > 0:
            score = round(100.0 * (checks - violations_by_dimension[key]) / checks, 1)
        else:
            score = None
        dimensions.append({
            "key": key,
            "name": DIMENSION_NAMES[key],
            "score": score,
            "weight": DEFAULT_WEIGHTS[key],
        })

    total_score = weighted_score(dimensions)
    passed_total = max(checks_total - violations_total, 0)
    issues_open = sum(1 for issue in issues if issue["status"] == "open")
    report = {
        "schema": "data-quality-report/1.0",
        "generated_at": generated_at or iso_utc(moment),
        "subject": subject_out,
        "summary": {
            "score": total_score,
            "grade": grade_for(total_score) or DASH,
            "checks_total": checks_total,
            "checks_passed": passed_total,
            "issues_total": len(issues),
            "issues_open": issues_open,
        },
        "dimensions": dimensions,
        "issues": issues,
        "distributions": _issue_distributions(issues),
        "lineage": None,
        "pii": None,
        "model_fitness": {"models": []},
        "trend": [],
    }
    return RuleRunResult(
        report=normalize_report(report),
        warnings=warnings,
        rule_results=rule_results,
    )
