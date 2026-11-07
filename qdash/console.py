"""控制台输出工具：UTF-8 安全配置与 ASCII 表格。"""

from __future__ import annotations

import sys
import unicodedata
from collections.abc import Sequence


def configure_stdout() -> None:
    """尽量把 stdout / stderr 切到 UTF-8，避免 Windows 控制台编码错误。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def display_width(text: object) -> int:
    """计算终端显示宽度：中日韩宽字符按 2 列，组合字符按 0 列。"""
    width = 0
    for char in str(text):
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _truncate(text: str, limit: int) -> str:
    if limit <= 3 or display_width(text) <= limit:
        return text
    out: list[str] = []
    used = 0
    for char in text:
        char_width = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        )
        if used + char_width > limit - 3:
            break
        out.append(char)
        used += char_width
    return "".join(out) + "..."


def _pad(text: str, width: int, align: str) -> str:
    gap = max(width - display_width(text), 0)
    if align == "r":
        return " " * gap + text
    return text + " " * gap


def format_table(
    headers: Sequence[object],
    rows: Sequence[Sequence[object]],
    *,
    max_width: int = 56,
    aligns: Sequence[str] | None = None,
) -> str:
    """生成纯 ASCII 边框表格（+ - |），单元格内容可含中文。"""
    clean_headers = [_truncate(str(item).replace("\r", " ").replace("\n", " "), max_width) for item in headers]
    clean_rows: list[list[str]] = []
    for row in rows:
        clean_rows.append([
            _truncate(str(item).replace("\r", " ").replace("\n", " "), max_width)
            for item in row
        ])
    columns = len(clean_headers)
    widths = [display_width(item) for item in clean_headers]
    for row in clean_rows:
        for index in range(min(columns, len(row))):
            widths[index] = max(widths[index], display_width(row[index]))
    if aligns is None:
        align_list = ["l"] * columns
    else:
        align_list = [aligns[index] if index < len(aligns) else "l" for index in range(columns)]

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [border]
    lines.append(
        "| " + " | ".join(
            _pad(clean_headers[index], widths[index], align_list[index])
            for index in range(columns)
        ) + " |"
    )
    lines.append(border)
    for row in clean_rows:
        cells = list(row) + [""] * (columns - len(row))
        lines.append(
            "| " + " | ".join(
                _pad(cells[index], widths[index], align_list[index])
                for index in range(columns)
            ) + " |"
        )
    if clean_rows:
        lines.append(border)
    return "\n".join(lines)


def human_size(num_bytes: int) -> str:
    """把字节数格式化成人类可读文本（ASCII 单位）。"""
    value = float(max(int(num_bytes), 0))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024.0 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"
