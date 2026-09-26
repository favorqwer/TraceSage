"""报告装配（第 5 层内部）：已确认边**全部保留**、按首次发生时间排序，不做任何挑选。

报告字段与命名见 `provenance-agent/README.md`；评分口径只读 `edges` 的内容三元组。
"""

from __future__ import annotations

from typing import Any

from ...contracts import triple
from .narrative import _short, build_reflection, pick_entry_point, render_narrative
from .phases import _PHASES, derive_phases


def build_report(inv: Any, *, poi: dict[str, Any], stats: dict[str, Any], stop_reason: str,
                 expand_rounds: int) -> dict[str, Any]:
    """把调查记录装配成报告。"""
    confirmed = [e for e in inv.confirmed.values() if e.get("judged") and e.get("event_ids")]
    confirmed.sort(key=lambda e: (int(e.get("t0") or 0), triple(e)))
    edges: list[dict[str, Any]] = []
    for edge in confirmed:
        confidence = float(edge.get("confidence") or 0.0)
        record = {
            "src": edge["src"], "syscall": edge["syscall"], "dst": edge["dst"],
            "confidence": "high" if confidence >= 0.8 else "medium",
            "event_id": int((edge.get("event_ids") or [0])[0]),
            "instances": edge.get("instances"), "bytes": edge.get("bytes"),
            "reason": edge.get("reason"), "step_key": edge.get("step_key"),
        }
        if edge.get("contested"):
            record["contested"] = True
        edges.append(record)

    phases = derive_phases(confirmed, inv.steps)
    missing = [phase for phase in _PHASES if phase not in phases]

    stats = dict(stats)
    stats.update({
        "expand_rounds": expand_rounds,
        "steps_examined": len(inv.steps),
        "confirmed_triples": len(edges),
        "excluded_triples": len(inv.excluded),
        "unjudged_triples": len(inv.unjudged),
        "prefiltered_triples": sum(1 for e in inv.excluded.values() if e.get("prefiltered")),
        "contested_triples": (sum(1 for e in confirmed if e.get("contested"))
                              + sum(1 for e in inv.excluded.values() if e.get("contested"))),
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
        "gaps": [{"label": g["label"], "next_action": g.get("next_action"), "status": g["status"]}
                 for g in inv.gaps],
        "hypotheses": [{"key": h["key"], "label": h["label"], "status": h["status"]} for h in inv.hypotheses],
        "reflection": build_reflection(stop_reason, phases, missing, expand_rounds),
        "stop_reason": stop_reason,
        "selection_note": f"确定性报告：已确认 {len(edges)} 条全部保留（无 LLM 选择、无剔除）",
        "generated_by": "deterministic_reporter",
        "stats": stats,
    }
