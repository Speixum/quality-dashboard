"""单文件离线 HTML 报告渲染。

所有 CSS、JS、SVG 均在构建时内联，不引用任何外部资源；页面可直接通过
file:// 双击打开。渲染阶段只做只读展示，不执行报告中的任何数据内容。
"""

from __future__ import annotations

import html
import json
import math
import re
from collections import Counter, deque
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import schema as sc

TEMPLATE_PATH = Path(__file__).with_name("templates") / "report.html"
MAX_HTML_BYTES = 480 * 1024

SEVERITY_LABELS = {"high": "高", "medium": "中", "low": "低"}
STATUS_LABELS = {"open": "待处理", "fixed": "已修复", "ignored": "已忽略"}
LEVEL_LABELS = {"high_sensitive": "高敏", "sensitive": "敏感", "general": "一般"}
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低"}
# 兼容 pii-scan 的规则名与上游产物的短名（phone / id_card 等）
PII_TYPE_LABELS = {
    "cn_id_card": "身份证号",
    "id_card": "身份证号",
    "mobile_cn": "手机号",
    "phone": "手机号",
    "bank_card": "银行卡号",
    "email": "邮箱",
    "uscc": "统一社会信用代码",
    "ipv4": "IPv4 地址",
    "address": "地址",
}
STATUS_TEXT = {
    "success": "成功",
    "succeeded": "成功",
    "ok": "成功",
    "completed": "完成",
    "failed": "失败",
    "error": "失败",
    "running": "运行中",
    "skipped": "跳过",
    "warning": "告警",
    "warn": "告警",
    "pending": "等待",
}
SEVERITY_COLORS = {"high": "#dc2626", "medium": "#f59e0b", "low": "#0284c7"}
LEVEL_COLORS = {"high_sensitive": "#dc2626", "sensitive": "#f59e0b", "general": "#0284c7"}
VERDICT_LABELS = {"pass": "通过", "warn": "告警", "fail": "不通过"}

DEFAULT_LIMITS = {
    "issues": 200,
    "findings": 120,
    "nodes": 120,
    "trend": 90,
    "buckets": 40,
    "models": 24,
}
FALLBACK_LIMITS = (
    {"issues": 80, "findings": 60, "nodes": 80, "trend": 60, "buckets": 24, "models": 16},
    {"issues": 30, "findings": 25, "nodes": 40, "trend": 30, "buckets": 16, "models": 8},
    {"issues": 10, "findings": 10, "nodes": 20, "trend": 14, "buckets": 10, "models": 5},
)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _plain(value: Any) -> str:
    """把任意值转成用于展示的纯文本，并把 URL 协议拆开以避免外链误判。"""
    if value is None or value is sc.DASH:
        return sc.DASH
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    if not text:
        return sc.DASH
    text = text.replace("https://", "https:\u200b//").replace("http://", "http:\u200b//")
    return text


def _esc(value: Any) -> str:
    """文本转义，用于 HTML 内容与属性。"""
    return html.escape(_plain(value), quote=True)


def _raw_esc(value: Any) -> str:
    """不把空串替换为破折号的文本转义。"""
    if value is None:
        return sc.DASH
    return html.escape(str(value), quote=True).replace("https://", "https:\u200b//").replace("http://", "http:\u200b//")


def _clip(text: Any, limit: int = 18) -> str:
    """按字符数截断，超出部分用省略号表示。"""
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    if limit <= 1:
        return value[:limit]
    return value[: limit - 1] + "\u2026"


def _fmt_score(value: Any, digits: int = 1) -> str:
    """格式化分数，缺失值显示为破折号。"""
    number = sc.as_number(value)
    if number is None:
        return sc.DASH
    if digits <= 0:
        return str(int(round(number)))
    return f"{number:.{digits}f}"


def _fmt_int(value: Any) -> str:
    """格式化整数，缺失或非法值显示为破折号。"""
    number = sc.as_number(value)
    if number is None:
        return sc.DASH
    return str(int(round(number)))


def _fmt_duration(value: Any) -> str:
    """把毫秒格式化为易读的时长。"""
    number = sc.as_number(value)
    if number is None or number < 0:
        return sc.DASH
    if number < 1000:
        return f"{number:.0f} ms"
    seconds = number / 1000.0
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes = seconds / 60.0
    if minutes < 60:
        return f"{minutes:.1f} min"
    return f"{minutes / 60.0:.1f} h"


def _fmt_time(value: Any) -> str:
    """把 ISO 时间压缩为适合表头展示的短格式。"""
    text = sc.as_text(value, "")
    if not text:
        return sc.DASH
    text = text.replace("T", " ").rstrip("Z")
    return text[:19]


def _to_float(value: Any) -> float | None:
    """宽松转浮点，失败返回 None。"""
    number = sc.as_number(value)
    if number is None or not math.isfinite(number):
        return None
    return float(number)


def _safe_json(payload: Mapping[str, Any]) -> str:
    """生成可安全嵌入 script 标签的 JSON，并避免出现明文本外链协议。"""
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    text = text.replace("https://", "https:\\/\\/").replace("http://", "http:\\/\\/")
    return text


def _badge(value: Any, kind: str, label: str | None = None) -> str:
    """渲染状态徽标；未知类型退化为灰色 dash 样式。"""
    text = label if label is not None else str(value)
    css = kind if re.fullmatch(r"[A-Za-z0-9_-]+", kind or "") else "dash"
    return f'<span class="badge {html.escape(css, quote=True)}">{_esc(text)}</span>'


def _empty(text: str) -> str:
    """渲染空状态占位。"""
    return f'<div class="empty">{_esc(text)}</div>'


def _section(title: str, subtitle: str, body: str) -> str:
    """渲染带标题的内容区块。"""
    sub = f'<p class="section-sub">{_esc(subtitle)}</p>' if subtitle else ""
    return (
        '<section class="section">'
        '<div class="section-head">'
        f'<h2 class="section-title">{_esc(title)}</h2>{sub}'
        "</div>"
        f"{body}"
        "</section>"
    )


def _svg(width: int, height: int, body: str, label: str, extra: str = "") -> str:
    """包装内联 SVG。"""
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_esc(label)}"{extra}>'
        f"<title>{_esc(label)}</title>{body}</svg>"
    )


# ---------------------------------------------------------------------------
# 图表
# ---------------------------------------------------------------------------


def _dimension_chart(dimensions: Sequence[Mapping[str, Any]]) -> str:
    """绘制五个质量维度的柱状图。"""
    width, height = 640, 280
    left, right, top, bottom = 74, 22, 34, 58
    plot_w = width - left - right
    plot_h = height - top - bottom
    parts: list[str] = [
        "<defs>",
        '<linearGradient id="qdBarGrad" x1="0" y1="0" x2="0" y2="1">',
        '<stop offset="0" stop-color="#7dd3fc"/>',
        '<stop offset="1" stop-color="#1d4ed8"/>',
        "</linearGradient>",
        "</defs>",
    ]
    for tick in (0, 25, 50, 75, 100):
        y = top + plot_h - plot_h * tick / 100.0
        parts.append(f'<line class="grid-line" x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis-text" x="{left - 10}" y="{y + 4:.1f}" text-anchor="end">{tick}</text>')
    parts.append(f'<line class="axis-line" x1="{left}" y1="{top + plot_h}" x2="{width - right}" y2="{top + plot_h}"/>')
    count = max(1, len(dimensions))
    slot = plot_w / count
    bar_w = min(58.0, slot * 0.5)
    for index, dim in enumerate(dimensions):
        x = left + slot * index + (slot - bar_w) / 2.0
        value = _to_float(dim.get("score"))
        name = str(dim.get("name") or sc.dimension_name(dim.get("key")))
        center = x + bar_w / 2.0
        if value is None:
            parts.append(
                f'<rect class="bar-empty" x="{x:.1f}" y="{top + plot_h - 8}" width="{bar_w:.1f}" height="8" rx="4"/>'
            )
            parts.append(
                f'<text class="axis-text" x="{center:.1f}" y="{top + plot_h - 16}" text-anchor="middle">{sc.DASH}</text>'
            )
        else:
            clamped = max(0.0, min(100.0, value))
            bar_h = plot_h * clamped / 100.0
            y = top + plot_h - bar_h
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(2.0, bar_h):.1f}" rx="6" fill="url(#qdBarGrad)"/>'
            )
            parts.append(
                f'<text class="bar-value" x="{center:.1f}" y="{max(14.0, y - 8):.1f}" text-anchor="middle">{_fmt_score(value)}</text>'
            )
        parts.append(
            f'<text class="axis-strong" x="{center:.1f}" y="{top + plot_h + 24}" text-anchor="middle">{_esc(name)}</text>'
        )
        weight = sc.as_number(dim.get("weight"))
        if weight is not None:
            parts.append(
                f'<text class="axis-text" x="{center:.1f}" y="{top + plot_h + 40}" text-anchor="middle">{weight * 100:.0f}%</text>'
            )
    return _svg(width, height, "".join(parts), "五个质量维度得分柱状图", ' class="chart-svg"')


def _severity_entries(report: Mapping[str, Any]) -> list[tuple[str, int, str]]:
    """从分布或问题列表计算严重度构成。"""
    counts: Counter[str] = Counter()
    distributions = report.get("distributions")
    if isinstance(distributions, list):
        for dist in distributions:
            if not isinstance(dist, Mapping):
                continue
            if dist.get("name") not in ("问题严重度", "问题严重度分布", "issue_severity", "severity"):
                continue
            buckets = dist.get("buckets")
            if not isinstance(buckets, list):
                continue
            for bucket in buckets:
                if not isinstance(bucket, Mapping):
                    continue
                label = sc.as_text(bucket.get("label"), "")
                key = {"高": "high", "中": "medium", "低": "low"}.get(label, label)
                value = sc.as_int(bucket.get("value"))
                if key in SEVERITY_COLORS and value is not None:
                    counts[key] += max(0, value)
            break
    if not counts:
        issues = report.get("issues")
        if isinstance(issues, list):
            for issue in issues:
                if not isinstance(issue, Mapping):
                    continue
                severity = sc.as_text(issue.get("severity"), "medium")
                if severity in SEVERITY_COLORS:
                    count = sc.as_int(issue.get("count")) or 1
                    counts[severity] += max(1, count)
    entries: list[tuple[str, int, str]] = []
    for key in ("high", "medium", "low"):
        if counts.get(key):
            entries.append((SEVERITY_LABELS[key], counts[key], SEVERITY_COLORS[key]))
    return entries


def _donut_chart(entries: Sequence[tuple[str, int, str]], total: int) -> str:
    """绘制问题严重度环形图。"""
    width, height = 280, 250
    cx, cy, radius, stroke = width / 2.0, 116.0, 76.0, 28.0
    circumference = 2.0 * math.pi * radius
    parts: list[str] = [
        f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="#eef2f8" stroke-width="{stroke}"/>'
    ]
    if total > 0:
        offset = 0.0
        for _label, value, color in entries:
            fraction = max(0.0, min(1.0, value / float(total)))
            dash = circumference * fraction
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{color}" '
                f'stroke-width="{stroke}" stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += dash
    parts.append(f'<text class="donut-center" x="{cx}" y="{cy + 2}" text-anchor="middle">{total}</text>')
    parts.append(f'<text class="donut-caption" x="{cx}" y="{cy + 20}" text-anchor="middle">问题总数</text>')
    return _svg(width, height, "".join(parts), "问题严重度环形图")


def _legend(entries: Sequence[tuple[str, int, str]]) -> str:
    """绘制环形图图例。"""
    if not entries:
        return ""
    items = "".join(
        f'<span><i style="background:{color}"></i>{_esc(label)} {value}</span>'
        for label, value, color in entries
    )
    return f'<div class="legend">{items}</div>'


def _issue_card(report: Mapping[str, Any]) -> str:
    """渲染问题构成卡片。"""
    entries = _severity_entries(report)
    total = sum(value for _label, value, _color in entries)
    return (
        '<div class="card">'
        '<div class="section-head" style="margin:0 0 4px"><h3 class="section-title" style="font-size:15px">问题严重度</h3></div>'
        f'{_donut_chart(entries, total)}{_legend(entries)}'
        "</div>"
    )


def _trend_chart(trend: Sequence[Mapping[str, Any]], limit: int) -> str:
    """绘制得分趋势折线图。"""
    points_raw = [item for item in trend if isinstance(item, Mapping)]
    truncated = len(points_raw) > limit
    if truncated:
        points_raw = points_raw[-limit:]
    points: list[tuple[str, float]] = []
    for item in points_raw:
        date = sc.as_text(item.get("date"), "")
        score = _to_float(item.get("score"))
        if date and score is not None:
            points.append((date, max(0.0, min(100.0, score))))
    if not points:
        return _empty("暂无趋势数据")
    width, height = 640, 250
    left, right, top, bottom = 46, 20, 24, 42
    plot_w = width - left - right
    plot_h = height - top - bottom
    parts: list[str] = []
    for tick in (0, 25, 50, 75, 100):
        y = top + plot_h - plot_h * tick / 100.0
        parts.append(f'<line class="grid-line" x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis-text" x="{left - 10}" y="{y + 4:.1f}" text-anchor="end">{tick}</text>')
    step = plot_w / max(1, len(points) - 1)
    coords: list[tuple[float, float]] = []
    for index, (_date, score) in enumerate(points):
        x = left + (step * index if len(points) > 1 else plot_w / 2.0)
        y = top + plot_h - plot_h * score / 100.0
        coords.append((x, y))
    if len(coords) > 1:
        area = f"{left:.1f},{top + plot_h:.1f} " + " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
        area += f" {coords[-1][0]:.1f},{top + plot_h:.1f}"
        parts.append(f'<polygon points="{area}" fill="#dbeafe" opacity="0.75"/>')
        line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
        parts.append(f'<polyline points="{line}" fill="none" stroke="#2563eb" stroke-width="2.4" stroke-linejoin="round"/>')
    for x, y in coords:
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.4" fill="#ffffff" stroke="#2563eb" stroke-width="2"/>')
    label_indexes = sorted({0, len(points) // 2, len(points) - 1})
    for idx in label_indexes:
        x = coords[idx][0]
        parts.append(
            f'<text class="axis-text" x="{x:.1f}" y="{height - 14}" text-anchor="middle">{_esc(_clip(points[idx][0], 10))}</text>'
        )
    note = '<p class="note">仅展示最近 %d 个趋势点。</p>' % limit if truncated else ""
    return _svg(width, height, "".join(parts), "质量得分趋势折线图") + note


# ---------------------------------------------------------------------------
# 维度与指标
# ---------------------------------------------------------------------------


def _dimension_table(dimensions: Sequence[Mapping[str, Any]]) -> str:
    """渲染维度明细表。"""
    rows: list[str] = []
    for dim in dimensions:
        score = _to_float(dim.get("score"))
        weight = sc.as_number(dim.get("weight")) or 0.0
        contribution = sc.DASH if score is None else f"{score * weight:.1f}"
        bar = 0.0 if score is None else max(0.0, min(100.0, score))
        rows.append(
            "<tr>"
            f'<td>{_esc(dim.get("name") or sc.dimension_name(dim.get("key")))}</td>'
            f'<td class="num">{_fmt_score(score)}</td>'
            f'<td><div class="weight-bar"><span style="width:{bar:.0f}%"></span></div></td>'
            f'<td class="num">{weight * 100:.0f}%</td>'
            f'<td class="num">{contribution}</td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr class="empty-row"><td colspan="5">暂无维度数据</td></tr>')
    return (
        '<div class="table-wrap"><table class="dim-table">'
        "<thead><tr><th>维度</th><th>得分</th><th>得分条</th><th>权重</th><th>加权贡献</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _model_table(models: Sequence[Mapping[str, Any]], limit: int) -> str:
    """渲染模型适配评测表，指标与阈值逐行比较。"""
    if not models:
        return _empty("未提供模型适配评测数据")
    truncated = len(models) > limit
    shown = models[:limit]
    rows: list[str] = []
    for model in shown:
        name = sc.as_text(model.get("name"))
        verdict = sc.as_text(model.get("verdict"), "").lower()
        if verdict in VERDICT_LABELS:
            badge = _badge(verdict, verdict, VERDICT_LABELS[verdict])
        else:
            badge = _badge("", "dash", sc.DASH)
        metrics = model.get("metrics")
        thresholds = model.get("thresholds")
        metric_map = metrics if isinstance(metrics, Mapping) else {}
        threshold_map = thresholds if isinstance(thresholds, Mapping) else {}
        keys: list[str] = [str(key) for key in metric_map.keys()]
        for key in threshold_map.keys():
            if str(key) not in keys:
                keys.append(str(key))
        if not keys:
            rows.append(
                f'<tr><td rowspan="1"><strong>{_esc(name)}</strong><br>{badge}</td>'
                '<td colspan="4" class="muted">暂无指标</td></tr>'
            )
            continue
        for index, key in enumerate(keys):
            actual = _to_float(metric_map.get(key))
            threshold = _to_float(threshold_map.get(key))
            if actual is None or threshold is None:
                verdict_cell = _badge("", "dash", sc.DASH)
            else:
                result = sc.compare_verdict({key: actual}, {key: threshold})
                verdict_cell = _badge(result or "", result or "dash", VERDICT_LABELS.get(result or "", result or sc.DASH))
            first = (
                f'<td rowspan="{len(keys)}"><strong>{_esc(name)}</strong><br>{badge}</td>'
                if index == 0
                else ""
            )
            rows.append(
                f"<tr>{first}<td>{_esc(key)}</td>"
                f'<td class="num">{_fmt_score(actual)}</td>'
                f'<td class="num">{_fmt_score(threshold)}</td>'
                f"<td>{verdict_cell}</td></tr>"
            )
    note = (
        f'<p class="note">仅展示前 {limit} 个模型；判定口径为数值越高越好。</p>'
        if truncated
        else '<p class="note">判定口径：达到阈值通过；达到阈值九成告警；其余不通过。</p>'
    )
    return (
        '<div class="card pad-0"><div class="table-wrap" style="border:0;border-radius:0">'
        '<table><thead><tr><th>模型</th><th>指标</th><th>实际值</th><th>阈值</th><th>判定</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div></div>{note}"
    )


# ---------------------------------------------------------------------------
# 问题表
# ---------------------------------------------------------------------------


def _filter_select(select_id: str, label: str, options: Sequence[tuple[str, str]]) -> str:
    """渲染过滤下拉框。"""
    opts = '<option value="">全部</option>' + "".join(
        f'<option value="{html.escape(value, quote=True)}">{_esc(text)}</option>'
        for value, text in options
    )
    return f'<select id="{select_id}" aria-label="{_esc(label)}">{opts}</select>'


def _issue_table(issues: Sequence[Mapping[str, Any]], dimensions: Sequence[Mapping[str, Any]], limit: int) -> str:
    """渲染可排序、可过滤的问题表。"""
    shown = issues[:limit]
    severity_options: list[tuple[str, str]] = []
    status_options: list[tuple[str, str]] = []
    dimension_options: list[tuple[str, str]] = []
    seen_sev: set[str] = set()
    seen_status: set[str] = set()
    seen_dim: set[str] = set()
    for issue in issues:
        severity = sc.as_text(issue.get("severity"), "medium")
        if severity not in seen_sev:
            seen_sev.add(severity)
            severity_options.append((severity, SEVERITY_LABELS.get(severity, severity)))
        status = sc.as_text(issue.get("status"), "open")
        if status not in seen_status:
            seen_status.add(status)
            status_options.append((status, STATUS_LABELS.get(status, status)))
        dimension = sc.as_text(issue.get("dimension"), "")
        if dimension and dimension not in seen_dim:
            seen_dim.add(dimension)
            dimension_options.append((dimension, sc.dimension_name(dimension)))
    filters = (
        '<div class="filters">'
        + _filter_select("filter-severity", "严重度", severity_options)
        + _filter_select("filter-status", "状态", status_options)
        + _filter_select("filter-dimension", "维度", dimension_options)
        + '<input id="filter-q" type="search" placeholder="搜索标题 / 负责人 / 样本" aria-label="搜索问题">'
        + f'<span class="count" id="issues-count">显示 {len(shown)} / {len(shown)} 条</span>'
        + "</div>"
    )
    rows: list[str] = []
    for issue in shown:
        issue_id = sc.as_text(issue.get("id"))
        title = sc.as_text(issue.get("title"))
        dimension = sc.as_text(issue.get("dimension"), "")
        severity = sc.as_text(issue.get("severity"), "medium")
        status = sc.as_text(issue.get("status"), "open")
        owner = sc.as_text(issue.get("owner"))
        sample = sc.as_text(issue.get("sample"), "")
        count = max(0, sc.as_int(issue.get("count")) or 0)
        first_seen = sc.as_text(issue.get("first_seen"))
        search_blob = " ".join([issue_id, title, dimension, sc.dimension_name(dimension), severity, status, owner, sample]).lower()
        title_html = _esc(title)
        if sample:
            title_html += f'<div class="mono small muted">{_esc(_clip(sample, 60))}</div>'
        rows.append(
            f'<tr data-severity="{html.escape(severity, quote=True)}" '
            f'data-status="{html.escape(status, quote=True)}" '
            f'data-dimension="{html.escape(dimension, quote=True)}" '
            f'data-search="{html.escape(search_blob, quote=True)}">'
            f'<td class="mono" data-v="{_esc(issue_id)}">{_esc(issue_id)}</td>'
            f'<td class="title-cell" data-v="{_esc(title)}">{title_html}</td>'
            f'<td data-v="{_esc(dimension)}">{_esc(sc.dimension_name(dimension))}</td>'
            f'<td data-v="{_esc(severity)}">{_badge(severity, severity, SEVERITY_LABELS.get(severity, severity))}</td>'
            f'<td class="num" data-v="{count}">{count}</td>'
            f'<td data-v="{_esc(status)}">{_badge(status, status, STATUS_LABELS.get(status, status))}</td>'
            f'<td data-v="{_esc(owner)}">{_esc(owner)}</td>'
            f'<td class="mono" data-v="{_esc(first_seen)}">{_esc(first_seen)}</td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr class="empty-row"><td colspan="8">暂无问题记录</td></tr>')
    note = (
        f'<p class="note">共 {len(issues)} 条问题，为保证单文件体积仅渲染前 {limit} 条。</p>'
        if len(issues) > limit
        else ""
    )
    return (
        note
        + '<div class="table-wrap" id="issues-wrap">'
        + filters
        + '<table id="issues-table"><thead><tr>'
        '<th data-sort="0">编号</th>'
        '<th data-sort="1">标题</th>'
        '<th data-sort="2">维度</th>'
        '<th data-sort="3">严重度</th>'
        '<th data-sort="4" data-numeric="1">次数</th>'
        '<th data-sort="5">状态</th>'
        '<th data-sort="6">负责人</th>'
        '<th data-sort="7">首次发现</th>'
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


# ---------------------------------------------------------------------------
# 血缘
# ---------------------------------------------------------------------------


def _layer_nodes(lineage: Mapping[str, Any], limit: int) -> tuple[list[list[Mapping[str, Any]]], list[tuple[str, str, str]], bool, list[Mapping[str, Any]]]:
    """按边关系给血缘节点分层，返回层列表、边、是否截断、失败节点。"""
    nodes_raw = lineage.get("nodes")
    nodes: list[Mapping[str, Any]] = []
    if isinstance(nodes_raw, list):
        nodes = [node for node in nodes_raw if isinstance(node, Mapping)]
    edges_raw = lineage.get("edges")
    edges: list[tuple[str, str, str]] = []
    if isinstance(edges_raw, list):
        for edge in edges_raw:
            if not isinstance(edge, Mapping):
                continue
            source = sc.as_text(edge.get("from"), "")
            target = sc.as_text(edge.get("to"), "")
            if source and target:
                edges.append((source, target, sc.as_text(edge.get("label"), "")))
    truncated = len(nodes) > limit
    if truncated:
        nodes = nodes[:limit]
    ids: list[str] = []
    for index, node in enumerate(nodes):
        node_id = sc.as_text(node.get("id"), f"node-{index}")
        node["id"] = node_id
        ids.append(node_id)
    known = set(ids)
    edges = [edge for edge in edges if edge[0] in known and edge[1] in known]
    order = {node_id: index for index, node_id in enumerate(ids)}
    adjacency: dict[str, list[str]] = {node_id: [] for node_id in ids}
    indegree: dict[str, int] = {node_id: 0 for node_id in ids}
    for source, target, _label in edges:
        adjacency[source].append(target)
        indegree[target] = indegree.get(target, 0) + 1
    layer_of: dict[str, int] = {node_id: 0 for node_id in ids}
    queue: deque[str] = deque(sorted((node_id for node_id in ids if indegree[node_id] == 0), key=lambda value: order[value]))
    topo: list[str] = []
    while queue:
        current = queue.popleft()
        topo.append(current)
        for target in adjacency[current]:
            layer_of[target] = max(layer_of[target], layer_of[current] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    processed = set(topo)
    leftover = [node_id for node_id in ids if node_id not in processed]
    for node_id in leftover:
        predecessors = [source for source, target, _label in edges if target == node_id and source not in leftover]
        layer_of[node_id] = (max(layer_of[source] for source in predecessors) + 1) if predecessors else 0
    layers: dict[int, list[Mapping[str, Any]]] = {}
    by_id = {sc.as_text(node.get("id")): node for node in nodes}
    for node_id in ids:
        layers.setdefault(layer_of[node_id], []).append(by_id[node_id])
    ordered = [layers[key] for key in sorted(layers)]
    for layer in ordered:
        layer.sort(key=lambda node: (sc.as_int(node.get("seq")) if sc.as_int(node.get("seq")) is not None else 0))
    failed = [
        node
        for node in nodes
        if sc.as_text(node.get("status"), "").lower() in ("failed", "error")
        or (isinstance(node.get("error"), Mapping) and node.get("error"))
    ]
    return ordered, edges, truncated, failed


def _dag_svg(lineage: Mapping[str, Any], limit: int) -> tuple[str, bool, list[Mapping[str, Any]]]:
    """渲染分层 DAG；失败节点标红。"""
    layers, edges, truncated, failed = _layer_nodes(lineage, limit)
    if not layers:
        return _empty("血缘数据中没有节点"), False, []
    node_w, node_h, hgap, vgap, margin = 150, 56, 58, 16, 20
    max_rows = max(len(layer) for layer in layers)
    width = margin * 2 + len(layers) * node_w + max(0, len(layers) - 1) * hgap
    height = margin * 2 + max_rows * node_h + max(0, max_rows - 1) * vgap
    position: dict[str, tuple[float, float]] = {}
    parts: list[str] = []
    for layer_index, layer in enumerate(layers):
        x = margin + layer_index * (node_w + hgap)
        for row_index, node in enumerate(layer):
            y = margin + row_index * (node_h + vgap)
            node_id = sc.as_text(node.get("id"))
            position[node_id] = (x, y)
    for source, target, label in edges:
        if source not in position or target not in position:
            continue
        sx = position[source][0] + node_w
        sy = position[source][1] + node_h / 2.0
        tx = position[target][0]
        ty = position[target][1] + node_h / 2.0
        dx = max(28.0, (tx - sx) * 0.5)
        parts.append(
            f'<path class="dag-edge" d="M {sx:.1f} {sy:.1f} C {sx + dx:.1f} {sy:.1f}, {tx - dx:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"/>'
        )
        parts.append(f'<polygon points="{tx - 7:.1f},{ty - 4:.1f} {tx:.1f},{ty:.1f} {tx - 7:.1f},{ty + 4:.1f}" fill="#94a3b8"/>')
        if label:
            mx = (sx + tx) / 2.0
            my = (sy + ty) / 2.0
            parts.append(f'<text class="dag-label" x="{mx:.1f}" y="{my - 4:.1f}" text-anchor="middle">{_esc(_clip(label, 10))}</text>')
    for layer in layers:
        for node in layer:
            node_id = sc.as_text(node.get("id"))
            x, y = position[node_id]
            status = sc.as_text(node.get("status"), "").lower()
            unstable = bool(node.get("unstable"))
            if status in ("failed", "error"):
                css = "node-failed"
            elif status in ("warning", "warn", "running") or unstable:
                css = "node-warn"
            elif status in ("success", "succeeded", "ok", "completed", "done"):
                css = "node-ok"
            else:
                css = "node-unknown"
            step = sc.as_text(node.get("step"), node_id)
            duration = _fmt_duration(node.get("duration_ms"))
            status_text = STATUS_TEXT.get(status, status or sc.DASH)
            error = node.get("error")
            tooltip = ""
            if isinstance(error, Mapping):
                message = sc.as_text(error.get("message"), "")
                if message:
                    tooltip = f"<title>{_esc(message)}</title>"
            elif error:
                tooltip = f"<title>{_esc(error)}</title>"
            parts.append(
                f'<g class="dag-node {css}">{tooltip}'
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{node_w}" height="{node_h}" rx="10"/>'
                f'<text class="node-title" x="{x + 12:.1f}" y="{y + 22:.1f}">{_esc(_clip(step, 14))}</text>'
                f'<text class="node-meta" x="{x + 12:.1f}" y="{y + 40:.1f}">{_esc(duration)} / {_esc(status_text)}</text>'
                "</g>"
            )
    svg = _svg(width, height, "".join(parts), "数据处理血缘图", ' style="min-width:%dpx"' % min(width, 1100))
    legend = (
        '<div class="legend">'
        '<span><i style="background:#e0f2fe;border:1px solid #0369a1"></i>成功</span>'
        '<span><i style="background:#fef3c7;border:1px solid #b45309"></i>告警</span>'
        '<span><i style="background:#fdd;border:1px solid #b42318"></i>失败</span>'
        '<span><i style="background:#f1f5f9;border:1px solid #94a3b8"></i>未知</span>'
        "</div>"
    )
    return '<div class="chart">' + svg + "</div>" + legend, truncated, failed


def _lineage_card(lineage: Any, limit: int) -> str:
    """渲染血缘区块，包含运行信息、DAG 和失败原因。"""
    if not isinstance(lineage, Mapping):
        return _empty("未提供数据血缘信息")
    run_id = sc.as_text(lineage.get("run_id"))
    name = sc.as_text(lineage.get("name"))
    status = sc.as_text(lineage.get("status"))
    finished = _fmt_time(lineage.get("finished_at") or lineage.get("started_at"))
    env = lineage.get("env")
    env_text = ""
    if isinstance(env, Mapping) and env:
        env_text = " / ".join(f"{key}={value}" for key, value in list(env.items())[:6])
    meta = (
        f'<p class="section-sub">运行 <span class="mono">{_esc(run_id)}</span>'
        f' / 数据集 {_esc(name)} / 状态 {_esc(STATUS_TEXT.get(status.lower(), status))}'
        f' / 结束 {_esc(finished)}</p>'
    )
    if env_text:
        meta += f'<p class="note">环境：{_esc(env_text)}</p>'
    chart, truncated, failed = _dag_svg(lineage, limit)
    note = f'<p class="note">节点较多，仅渲染前 {limit} 个。</p>' if truncated else ""
    failures = ""
    if failed:
        items = []
        for node in failed[:12]:
            error = node.get("error")
            message = ""
            if isinstance(error, Mapping):
                message = sc.as_text(error.get("message"), "")
            elif error:
                message = sc.as_text(error, "")
            items.append(
                f'<li><strong>{_esc(node.get("step") or node.get("id"))}</strong>：{_esc(message or "未提供错误信息")}</li>'
            )
        failures = '<div class="card" style="margin-top:14px"><strong>失败原因</strong><ul class="small muted">' + "".join(items) + "</ul></div>"
    return '<div class="card">' + meta + chart + note + "</div>" + failures


# ---------------------------------------------------------------------------
# PII
# ---------------------------------------------------------------------------


def _pii_summary(pii: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]) -> tuple[dict[str, int], dict[str, int], dict[str, int], int]:
    """计算 PII 各级别、置信度与类型统计。"""
    by_level: dict[str, int] = {key: 0 for key in LEVEL_COLORS}
    by_confidence: dict[str, int] = {key: 0 for key in ("high", "medium", "low")}
    by_type: dict[str, int] = {}
    summary = pii.get("summary")
    if isinstance(summary, Mapping):
        raw_levels = summary.get("by_level")
        if isinstance(raw_levels, Mapping):
            for key in by_level:
                value = sc.as_int(raw_levels.get(key))
                if value is not None:
                    by_level[key] = max(0, value)
        raw_conf = summary.get("by_confidence")
        if isinstance(raw_conf, Mapping):
            for key in by_confidence:
                value = sc.as_int(raw_conf.get(key))
                if value is not None:
                    by_confidence[key] = max(0, value)
        raw_type = summary.get("by_type")
        if isinstance(raw_type, Mapping):
            for key, value in raw_type.items():
                number = sc.as_int(value)
                if number is not None:
                    by_type[str(key)] = max(0, number)
    if not any(by_level.values()) and findings:
        for finding in findings:
            level = sc.as_text(finding.get("level"), "general")
            if level in by_level:
                by_level[level] += 1
    if not any(by_confidence.values()) and findings:
        for finding in findings:
            confidence = sc.as_text(finding.get("confidence"), "low")
            if confidence in by_confidence:
                by_confidence[confidence] += 1
    if not by_type and findings:
        counter: Counter[str] = Counter()
        for finding in findings:
            counter[sc.as_text(finding.get("type"), "unknown")] += 1
        by_type = dict(counter)
    total: int | None = None
    if isinstance(summary, Mapping):
        raw_total = sc.as_number(summary.get("total"))
        if raw_total is not None:
            total = int(round(raw_total))
    if total is None:
        total = sum(by_level.values()) or len(findings)
    return by_level, by_confidence, by_type, max(0, total)


def _pii_type_label(key: str) -> str:
    """把 PII 命中类型映射成中文标签，未知类型原样返回。"""
    return PII_TYPE_LABELS.get(key.lower(), key)


def _pii_card(pii: Any, limit: int) -> str:
    """渲染 PII 汇总卡与命中明细。"""
    if not isinstance(pii, Mapping):
        return _empty("未提供 PII 扫描结果")
    findings_raw = pii.get("findings")
    findings = [item for item in findings_raw if isinstance(item, Mapping)] if isinstance(findings_raw, list) else []
    by_level, by_confidence, by_type, total = _pii_summary(pii, findings)
    ruleset = pii.get("ruleset") if isinstance(pii.get("ruleset"), Mapping) else {}
    source = sc.as_text(pii.get("source"))
    generated = _fmt_time(pii.get("generated_at"))
    level_rows: list[str] = []
    level_max = max([1] + list(by_level.values()))
    for key in ("high_sensitive", "sensitive", "general"):
        value = by_level.get(key, 0)
        level_rows.append(
            '<div class="level-row">'
            f"<span>{_esc(LEVEL_LABELS[key])}</span>"
            f'<div class="level-track"><div class="level-fill {key}" style="width:{value / level_max * 100:.0f}%"></div></div>'
            f'<span class="dist-value">{value}</span>'
            "</div>"
        )
    conf_text = " / ".join(
        f"{CONFIDENCE_LABELS.get(key, key)} {by_confidence.get(key, 0)}"
        for key in ("high", "medium", "low")
    )
    type_chips = "".join(
        f'<span class="type-chip">{_esc(_pii_type_label(key))} <strong>{value}</strong></span>'
        for key, value in sorted(by_type.items(), key=lambda item: (-item[1], item[0]))[:18]
    )
    if not type_chips:
        type_chips = '<span class="muted small">暂无命中类型</span>'
    rules_text = ""
    if ruleset:
        rules_text = (
            f'{sc.as_text(ruleset.get("name"))} {sc.as_text(ruleset.get("version"), "")}'
            f' / {sc.as_text(ruleset.get("file"), "")}'
        ).strip(" /")
    stats = (
        '<div class="pii-stats">'
        f'<div class="pii-stat"><div class="v">{total}</div><div class="k">命中总数</div></div>'
        f'<div class="pii-stat"><div class="v" style="color:#b42318">{by_level.get("high_sensitive", 0)}</div><div class="k">高敏级别</div></div>'
        f'<div class="pii-stat"><div class="v">{by_confidence.get("high", 0)}</div><div class="k">高置信度</div></div>'
        f'<div class="pii-stat"><div class="v">{len(by_type)}</div><div class="k">命中类型</div></div>'
        "</div>"
    )
    head = (
        f'<p class="section-sub">来源 {_esc(source)} / 生成 {_esc(generated)}'
        + (f' / 规则集 {_esc(rules_text)}' if rules_text else "")
        + "</p>"
    )
    rows: list[str] = []
    for finding in findings[:limit]:
        finding_type = sc.as_text(finding.get("type"))
        level = sc.as_text(finding.get("level"), "general")
        confidence = sc.as_text(finding.get("confidence"), "low")
        preview = sc.as_text(finding.get("preview"), "")
        line = _fmt_int(finding.get("line"))
        col = _fmt_int(finding.get("col"))
        position = f"{line}:{col}" if line != sc.DASH and col != sc.DASH else sc.DASH
        rows.append(
            "<tr>"
            f"<td>{_esc(_pii_type_label(finding_type))}</td>"
            f'<td><span class="badge {html.escape(level, quote=True)}">{_esc(LEVEL_LABELS.get(level, level))}</span></td>'
            f"<td>{_esc(CONFIDENCE_LABELS.get(confidence, confidence))}</td>"
            f'<td class="mono">{_esc(position)}</td>'
            f'<td class="sample-cell">{_esc(_clip(preview, 46))}</td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr class="empty-row"><td colspan="5">暂无命中记录</td></tr>')
    table = (
        '<div class="table-wrap"><table><thead><tr><th>类型</th><th>级别</th><th>置信度</th><th>位置</th><th>脱敏预览</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )
    note = (
        f'<p class="note">共 {len(findings)} 条命中，仅渲染前 {limit} 条。</p>'
        if len(findings) > limit
        else ""
    )
    cols = (
        '<div class="pii-cols">'
        '<div><strong class="small">级别分布</strong>' + "".join(level_rows) + "</div>"
        f'<div><strong class="small">置信度</strong><p class="muted small" style="margin:8px 0 14px">{_esc(conf_text)}</p>'
        f'<strong class="small">命中类型</strong><div class="type-list" style="margin-top:8px">{type_chips}</div></div>'
        "</div>"
    )
    return head + '<div class="card">' + stats + cols + "</div>" + '<div style="margin-top:14px">' + table + note + "</div>"


# ---------------------------------------------------------------------------
# 分布
# ---------------------------------------------------------------------------


def _distributions(distributions: Sequence[Mapping[str, Any]], limit: int) -> str:
    """渲染除严重度以外的分布条形图。"""
    blocks: list[str] = []
    for dist in distributions:
        if not isinstance(dist, Mapping):
            continue
        name = sc.as_text(dist.get("name"))
        if name in ("问题严重度", "问题严重度分布", "issue_severity", "severity"):
            continue
        buckets = dist.get("buckets")
        if not isinstance(buckets, list) or not buckets:
            continue
        clean = [bucket for bucket in buckets if isinstance(bucket, Mapping)]
        truncated = len(clean) > limit
        clean = clean[:limit]
        values = [max(0, sc.as_int(bucket.get("value")) or 0) for bucket in clean]
        peak = max([1] + values)
        rows = []
        for bucket, value in zip(clean, values):
            label = sc.as_text(bucket.get("label"))
            rows.append(
                '<div class="dist-row">'
                f"<span title=\"{_esc(label)}\">{_esc(_clip(label, 14))}</span>"
                f'<div class="dist-track"><div class="dist-fill" style="width:{value / peak * 100:.0f}%"></div></div>'
                f'<span class="dist-value">{value}</span>'
                "</div>"
            )
        extra = f'<p class="note">仅展示前 {limit} 个分桶。</p>' if truncated else ""
        blocks.append(f'<div class="dist"><div class="dist-name">{_esc(name)}</div>{"".join(rows)}{extra}</div>')
    if not blocks:
        return _empty("暂无分布数据")
    return '<div class="card">' + "".join(blocks) + "</div>"


# ---------------------------------------------------------------------------
# 页面骨架
# ---------------------------------------------------------------------------


def _hero(report: Mapping[str, Any]) -> str:
    """渲染页面头部、总分与关键指标。"""
    subject = report.get("subject") if isinstance(report.get("subject"), Mapping) else {}
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    name = sc.as_text(subject.get("name"))
    version = sc.as_text(subject.get("version"))
    owner = sc.as_text(subject.get("owner"))
    generated = _fmt_time(report.get("generated_at"))
    score = _to_float(summary.get("score"))
    grade = sc.as_text(summary.get("grade"), "")
    grade_class = f" grade-{grade}" if grade in sc.GRADES else ""
    checks_total = sc.as_int(summary.get("checks_total")) or 0
    checks_passed = sc.as_int(summary.get("checks_passed")) or 0
    pass_rate = (checks_passed / checks_total * 100.0) if checks_total else None
    issues_list = [item for item in (report.get("issues") or []) if isinstance(item, Mapping)]
    issues_total = sc.as_int(summary.get("issues_total"))
    if not issues_total and issues_list:
        issues_total = len(issues_list)
    issues_open = sc.as_int(summary.get("issues_open"))
    if not issues_open and issues_list:
        issues_open = sum(1 for issue in issues_list if sc.as_text(issue.get("status"), "open") == "open")
    high_open = sum(
        1
        for issue in issues_list
        if sc.as_text(issue.get("status"), "open") == "open"
        and sc.as_text(issue.get("severity"), "") == "high"
    )
    meta = " ".join(
        f"<span>{_esc(value)}</span>"
        for value in (
            f"版本 {version}",
            f"负责人 {owner}",
            f"生成时间 {generated}",
            f"检查项 {checks_passed}/{checks_total}",
        )
    )
    score_html = _fmt_score(score) if score is not None else sc.DASH
    grade_html = f'<span class="grade{grade_class}">{_esc(grade)}</span>' if grade else ""
    hero = (
        '<header class="hero">'
        '<div class="hero-top"><div>'
        '<p class="eyebrow">Data Quality Report / 1.0</p>'
        f"<h1>{_esc(name)}</h1>"
        f'<p class="meta">{meta}</p>'
        "</div>"
        '<div class="score-block">'
        f'<div class="score-value">{score_html}{grade_html}</div>'
        '<div class="score-label">加权总分 / 等级</div>'
        "</div></div>"
        "</header>"
    )
    kpis = (
        '<div class="kpi-grid">'
        f'<div class="kpi"><div class="kpi-label">检查项</div><div class="kpi-value">{checks_passed} / {checks_total}</div>'
        f'<div class="kpi-note">通过 / 总数</div></div>'
        f'<div class="kpi"><div class="kpi-label">检查通过率</div><div class="kpi-value">{sc.DASH if pass_rate is None else f"{pass_rate:.1f}%"}</div>'
        '<div class="kpi-note">按检查项计</div></div>'
        f'<div class="kpi"><div class="kpi-label">问题总数</div><div class="kpi-value">{issues_total}</div>'
        '<div class="kpi-note">去重后的问题条目</div></div>'
        f'<div class="kpi"><div class="kpi-label">待处理</div><div class="kpi-value">{issues_open}</div>'
        f'<div class="kpi-note">其中高严重度 {high_open}</div></div>'
        "</div>"
    )
    return hero + kpis


def _render_once(report: Mapping[str, Any], title: str, limits: Mapping[str, int]) -> str:
    """按给定截断上限渲染完整 HTML。"""
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    dimensions_raw = report.get("dimensions")
    dimensions = [item for item in dimensions_raw if isinstance(item, Mapping)] if isinstance(dimensions_raw, list) else []
    issues_raw = report.get("issues")
    issues = [item for item in issues_raw if isinstance(item, Mapping)] if isinstance(issues_raw, list) else []
    trend_raw = report.get("trend")
    trend = [item for item in trend_raw if isinstance(item, Mapping)] if isinstance(trend_raw, list) else []
    distributions_raw = report.get("distributions")
    distributions = [item for item in distributions_raw if isinstance(item, Mapping)] if isinstance(distributions_raw, list) else []
    model_fitness = report.get("model_fitness") if isinstance(report.get("model_fitness"), Mapping) else {}
    models_raw = model_fitness.get("models") if isinstance(model_fitness, Mapping) else []
    models = [item for item in models_raw if isinstance(item, Mapping)] if isinstance(models_raw, list) else []

    dim_body = (
        '<div class="grid two">'
        f'<div class="card">{_dimension_chart(dimensions)}</div>'
        f"<div>{_dimension_table(dimensions)}</div>"
        "</div>"
    )
    issues_body = _issue_table(issues, dimensions, limits["issues"])
    charts_body = '<div class="grid equal">' + _issue_card(report) + '<div class="card">'
    charts_body += '<div class="section-head" style="margin:0 0 10px"><h3 class="section-title" style="font-size:15px">得分趋势</h3></div>'
    charts_body += _trend_chart(trend, limits["trend"]) + "</div></div>"
    body = [
        _hero(report),
        _section("质量维度", "五个固定维度的得分与权重", dim_body),
        _section("问题清单", "支持按严重度、状态、维度过滤，点击表头排序", issues_body),
        _section("问题与趋势", "严重度构成与历史得分走势", charts_body),
        _section("数据血缘", "按依赖关系分层的处理步骤，失败节点以红色标记", _lineage_card(report.get("lineage"), limits["nodes"])),
        _section("PII 扫描", "敏感数据命中概览，预览均为脱敏结果", _pii_card(report.get("pii"), limits["findings"])),
        _section("模型适配评测", "模型指标与阈值逐项对照", _model_table(models, limits["models"])),
        _section("分布统计", "问题维度与其他分桶统计", _distributions(distributions, limits["buckets"])),
    ]
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    tokens = {"TITLE": html.escape(title, quote=True), "BODY": "".join(body), "DATA": _safe_json(report)}
    page = re.sub(r"@@(TITLE|BODY|DATA)@@", lambda match: tokens[match.group(1)], template)
    return page


def build_html(
    report: Mapping[str, Any],
    *,
    title: str | None = None,
    max_bytes: int = MAX_HTML_BYTES,
) -> str:
    """把报告字典渲染为单文件 HTML 字符串。

    参数:
        report: 报告数据；内部会先经过 schema.normalize_report 容错归一化。
        title: 页面标题；缺省时使用数据集名称。
        max_bytes: HTML 体积上限，超出时逐级收紧表格与图表数据量。

    返回:
        完整的 HTML 文本，所有资源均已内联。
    """
    normalized = sc.normalize_report(report)
    if title is None:
        subject = normalized.get("subject") if isinstance(normalized.get("subject"), Mapping) else {}
        name = sc.as_text(subject.get("name"))
        title = f"{name} 数据质量报告"
    attempts = [dict(DEFAULT_LIMITS)] + [dict(item) for item in FALLBACK_LIMITS]
    page = ""
    for limits in attempts:
        page = _render_once(normalized, title, limits)
        if len(page.encode("utf-8")) <= max_bytes:
            return page
    return page


def render_report(report: Mapping[str, Any], *, title: str | None = None) -> str:
    """build_html 的语义化别名。"""
    return build_html(report, title=title)


def write_html(path: str | Path, report: Mapping[str, Any], *, title: str | None = None) -> Path:
    """渲染报告并写入指定文件，返回实际路径。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_html(report, title=title), encoding="utf-8", newline="\n")
    return target
