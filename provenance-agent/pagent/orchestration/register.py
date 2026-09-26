"""结论登记（编排）：把判定结论写进内存记录表（实体 + in-step / supports / refutes）。"""

from __future__ import annotations

from typing import Any


def register_conclusions(inv: Any) -> None:
    """按步骤登记已确认边（relevant=True），再登记全部已排除边（relevant=False）。"""
    by_step: dict[str, list[dict[str, Any]]] = {}
    for edge in inv.confirmed.values():
        by_step.setdefault(str(edge.get("step_key") or ""), []).append(edge)
    hypothesis = "POI" if any(h["key"] == "POI" for h in inv.hypotheses) else ""
    for step_key, edges in by_step.items():
        inv.register_edges(edges, relevant=True, step_key=step_key, hypothesis_key=hypothesis)
    if inv.excluded:
        inv.register_edges(list(inv.excluded.values()), relevant=False, hypothesis_key=hypothesis)
