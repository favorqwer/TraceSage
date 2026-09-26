"""确定性粗筛（第 2 层内部）：规则表在 `pagent/rules/prefilter.json`，判定在 `core/edge_rules.py`。

这些路径在**六个场景的人工标注里零命中**（已逐条校验），且是每个进程启动都要读的系统例行文件。
**故意不列入**的：`/proc/cpuinfo`、`/proc/meminfo`、`/dev/zero`、`/dev/urandom`（标注里真实存在，
场景 5 的核心边就是它们）、`/etc/passwd`、`/etc/group`（标注里有）、`/etc/ld.so.preload`（可被劫持）。

第 1 层（事件级闭包引擎）已在遍历期用同一份规则把这类边挡在闭包之外；本层是**兜底**：
逐条核对有没有漏网的，命中就记理由。两层共用 `core/edge_rules.py` 的同一个函数。
"""

from __future__ import annotations

from typing import Any

from ...core.edge_rules import prefilter_reason  # noqa: F401 - 本层公开 API 沿用旧名

__all__ = ["prefilter_reason"]


def prefiltered_edge(edge: dict[str, Any]) -> bool:
    """这条边是否命中系统例行文件规则（给调用方用，避免重复判断语义）。"""
    return bool(prefilter_reason(edge))
