"""quality-dashboard: 零依赖的数据集质量评测与单文件离线看板。

公开入口：
- qdash.schema   报告 schema 定义 / 容错归一化 / 校验
- qdash.collect  扫描并合并 lineage 与 pii-hits 产物
- qdash.rules    CSV / JSONL 质量规则引擎
- qdash.render   单文件 HTML 看板渲染
- qdash.cli      命令行入口
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
