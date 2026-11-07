"""JSON 读写工具（UTF-8、ensure_ascii=False、缩进 2）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> Any:
    """读取 JSON 文件；失败时向上抛出 OSError / JSONDecodeError。

    使用 utf-8-sig 兼容 Windows 记事本产生的 BOM。
    """
    target = Path(path)
    with target.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: str | Path, payload: Any) -> Path:
    """写出 UTF-8 JSON：ensure_ascii=False、缩进 2、末尾换行。返回目标路径。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    target.write_text(text, encoding="utf-8", newline="\n")
    return target
