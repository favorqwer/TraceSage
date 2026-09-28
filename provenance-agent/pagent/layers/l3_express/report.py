"""报告装配（表达层内部）：**确认边全部保留**、按首次发生时间排序，不做任何挑选。

判定只有一轮：相关且达到阈值 → 确认（进 `edges`），否则排除；没给结论 → 未判定（不进报告）。
报告字段与命名见 `provenance-agent/README.md`；评分口径只读 `edges` 的内容三元组。
"""

from __future__ import annotations

from typing import Any

from ...contracts import triple
from .narrative import _short, build_reflection, pick_entry_point, render_narrative
from .phases import _PHASES, derive_phases


def _edge_record(edge: dict[str, Any]) -> dict[str, Any]:
    """一条边写进报告的形状：置信度同时给档位（high/medium/low）与**数值**。

    数值置信度是给人工复核与事后过滤用的：以前只写档位，置信度 0.2 的边与 0.79 的边
    在报告里长得一模一样。
    """
    confidence = float(edge.get("confidence") or 0.0)
    band = "high" if confidence >= 0.8 else ("medium" if confidence >= 0.5 else "low")
    record = {
        "src": edge["src"], "syscall": edge["syscall"], "dst": edge["dst"],
        "confidence": band,
        "confidence_value": round(confidence, 3),
        "event_id": int((edge.get("event_ids") or [0])[0]),
        "instances": edge.get("instances"), "bytes": edge.get("bytes"),
        "reason": edge.get("reason"), "process_id": edge.get("process_id"),
    }
    return record


def build_report(inv: Any, *, poi: dict[str, Any], stats: dict[str, Any], stop_reason: str,
                 expand_rounds: int) -> dict[str, Any]:
    """把调查记录装配成报告。"""
    confirmed = [e for e in inv.confirmed.values() if e.get("judged") and e.get("event_ids")]
    confirmed.sort(key=lambda e: (int(e.get("t0") or 0), triple(e)))
    edges = [_edge_record(edge) for edge in confirmed]

    phases = derive_phases(confirmed, inv.process_context)
    missing = [phase for phase in _PHASES if phase not in phases]

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
        "tactics": phases,
        "entry_point": pick_entry_point(confirmed),
        "gaps": gaps,
        "hypotheses": [{"key": h["key"], "label": h["label"], "status": h["status"]} for h in inv.hypotheses],
        "reflection": build_reflection(stop_reason, phases, missing, expand_rounds),
        "stop_reason": stop_reason,
        "selection_note": f"确定性报告：确认边 {len(edges)} 条全部保留（相关且达到判定阈值的边）",
        "generated_by": "deterministic_reporter",
        "stats": stats,
    }
