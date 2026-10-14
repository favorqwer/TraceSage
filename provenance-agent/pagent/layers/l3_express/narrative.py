"""叙述、入口点与自审（表达层内部）：当前全部是确定性渲染，未经模型改写。

阶段二会加"大模型只写叙述文字"（失败回落这里的时间线）。
"""

from __future__ import annotations

from typing import Any

from ...contracts import short, triple


def _short(text: Any, limit: int = 100) -> str:
    """本层的摘要长度默认 100 字符（与其他层的 120 不同，保持既有报告口径）。"""
    return short(text, limit)


def pick_entry_point(confirmed: list[dict[str, Any]]) -> str:
    """确定性入口点：最早出现的、不作为任何已确认边目标的 Process 端点（链根）。"""
    if not confirmed:
        return ""
    destinations = {str(e.get("dst") or "") for e in confirmed}
    roots = [e for e in confirmed
             if e.get("src_label") == "Process" and str(e.get("src") or "") not in destinations]
    pool = roots or confirmed
    edge = min(pool, key=lambda e: (int(e.get("t0") or 0), triple(e)))
    return (f"{edge['src']}（最早的上游端点，t={edge.get('t0')}，经 {edge['syscall']} 指向 {edge['dst']}）")


def render_narrative(edges: list[dict[str, Any]]) -> str:
    """确定性叙事：按首次发生时间排序的证据时间线。"""
    if not edges:
        return "（无已确认的攻击相关边）"
    lines = []
    for i, edge in enumerate(edges):
        note = f"，理由：{_short(edge.get('reason'))}" if edge.get("reason") else ""
        lines.append(
            f"{i + 1}. {edge['src']} --{edge['syscall']}--> {edge['dst']}"
            f"（实例 {edge.get('instances')}，字节 {edge.get('bytes')}"
            + note + "）"
        )
    return "攻击链（按首次发生时间排序，确定性渲染）：\n" + "\n".join(lines)


def build_reflection(stop_reason: str, expand_rounds: int) -> dict[str, Any]:
    """规则推导的自审结论（**无置信度字段**）。

    这里只输出规则推导出的结论。由“是否完整 + 是否缺相位”算出来的“把握”是个常数（停止原因只有
    一个、相位基本总缺 Initial Access），拿来当评估结果会误导，所以本层不输出任何数值。
    """
    sufficient = stop_reason == "frontier_exhausted"
    critique = ("前沿耗尽：所有未考察的候选顶点都已处理" if sufficient
                else f"非正常收尾（{stop_reason}）：前沿可能未走完，结论不完整")
    return {
        "sufficient": sufficient,
        "critique": critique,
        "expand_rounds": expand_rounds,
        "derived_by": "rules",
    }
