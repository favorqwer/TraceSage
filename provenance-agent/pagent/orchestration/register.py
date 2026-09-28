"""结论登记（编排）：把判定结论写进内存记录表（实体 + supports / refutes）。"""

from __future__ import annotations

from typing import Any


def register_conclusions(inv: Any) -> None:
    """先登记全部已确认边（relevant=True），再登记全部已排除边（relevant=False）。"""
    hypothesis = "POI" if any(h["key"] == "POI" for h in inv.hypotheses) else ""
    if inv.confirmed:
        inv.register_edges(list(inv.confirmed.values()), relevant=True, hypothesis_key=hypothesis)
    if inv.excluded:
        inv.register_edges(list(inv.excluded.values()), relevant=False, hypothesis_key=hypothesis)
