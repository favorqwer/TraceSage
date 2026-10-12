"""报告装配（表达层内部）：**确认边全部保留**、按首次发生时间排序，不做任何挑选。

判定只有一轮：判为相关 → 确认（进 `edges`），判为无关 → 排除；没给结论 → 未判定（不进报告）。
模型在结论里多写的字段一律忽略：不进报告、不进日志、不参与任何判断（旧版那个“模型自报把握”的
通道已整体删除）。
报告字段与命名见 `provenance-agent/README.md`；评分口径只读 `edges` 的内容三元组。
"""

from __future__ import annotations

from typing import Any

from ...contracts import triple
from .narrative import _short, build_reflection, pick_entry_point, render_narrative


def _edge_record(edge: dict[str, Any]) -> dict[str, Any]:
    """一条边写进报告的形状：两端与操作名，加上证据与归属信息。

    **不写模型多写的数值字段**：写进报告只会被读成“把握”，而它没有校准、跨运行会变。
    """
    record = {"src": edge["src"], "syscall": edge["syscall"], "dst": edge["dst"]}
    record.update({
        "event_id": int((edge.get("event_ids") or [0])[0]),
        "instances": edge.get("instances"), "bytes": edge.get("bytes"),
        "reason": edge.get("reason"), "process_id": edge.get("process_id"),
    })
    return record


def build_report(inv: Any, *, poi: dict[str, Any], stats: dict[str, Any], stop_reason: str,
                 expand_rounds: int) -> dict[str, Any]:
    """把调查记录装配成报告。"""
    confirmed = [e for e in inv.confirmed.values() if e.get("judged") and e.get("event_ids")]
    confirmed.sort(key=lambda e: (int(e.get("t0") or 0), triple(e)))
    edges = [_edge_record(edge) for edge in confirmed]

    gaps: list[dict[str, Any]] = []
    gaps.extend({"label": g["label"], "next_action": g.get("next_action"), "status": g["status"]}
                for g in inv.gaps)

    stats = dict(stats)
    stats.update({
        "expand_rounds": expand_rounds,
        "processes_examined": len(inv.process_context),
        "confirmed_triples": len(edges),
        "excluded_triples": len(inv.excluded),
        "unjudged_triples": len(inv.unjudged),
        "state": inv.stats(),
    })
    return {
        "scenario": inv.scenario,
        "run_id": inv.run_id,
        "poi": poi,
        "edges": edges,
        "narrative": render_narrative(edges),
        "entry_point": pick_entry_point(confirmed),
        "gaps": gaps,
        "hypotheses": [{"key": h["key"], "label": h["label"], "status": h["status"]} for h in inv.hypotheses],
        "reflection": build_reflection(stop_reason, expand_rounds),
        "stop_reason": stop_reason,
        "selection_note": f"确定性报告：确认边 {len(edges)} 条全部保留（判为相关的边）",
        "generated_by": "deterministic_reporter",
        "stats": stats,
    }
