"""调查结果状态结构定义与调查报告导出。"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from domain.keys import process_content_or_na, split_process_key


@dataclass
class RouteOutcome:
    """一次调查或判定的最终三段式分区结果与审计信息。"""
    confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]]
    unexcluded: List[Dict[str, Any]]
    excluded: List[Dict[str, Any]]
    audit: Dict[str, Any] = field(default_factory=dict)


def report_endpoint(value: Any, label: Any) -> Any:
    """报告端点内容：进程取不到可执行文件时按官方口径写 `<NA>`。"""
    if str(label or "") == "Process" or not label:
        value = process_content_or_na(value)
    if split_process_key(value) is not None:
        raise ValueError(f"报告端点内容不能是进程主键：{value!r}")
    return value


def _report_edges(edges: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for edge in edges or []:
        rec = dict(edge)
        rec["src"] = report_endpoint(rec.get("src"), rec.get("src_label"))
        rec["dst"] = report_endpoint(rec.get("dst"), rec.get("dst_label"))
        out.append(rec)
    return out


def build_report(
    scenario_name: str,
    confirmed_edges: list,
    unexcluded_edges: list,
    excluded_edges: list = None,
    pruned_count: int = 0,
    promoted_count: int = 0,
    elapsed_seconds: float = 0.0,
    llm_calls: int = 0,
    llm_enabled: bool = False,
    anchor_confirmed_count: int = 0,
    promoted_by_motif: dict = None,
    mode: str = "hybrid",
    matcher_admitted_count: int = None,
    conf_filtered_count: int = 0,
    library: dict = None,
) -> dict:
    if excluded_edges is None:
        excluded_edges = []

    unique_confirmed = {}
    for e in confirmed_edges:
        key = (e.get("src"), e.get("syscall"), e.get("dst"))
        unique_confirmed[key] = e

    return {
        "scenario": scenario_name,
        "edges": _report_edges(unique_confirmed.values()),
        "unexcluded": _report_edges(unexcluded_edges),
        "excluded": _report_edges(excluded_edges),
        "stats": {
            "mode": mode,
            "confirmed_count": len(unique_confirmed),
            "unexcluded_count": len(unexcluded_edges),
            "excluded_count": len(excluded_edges),
            "pruned_noise_count": pruned_count,
            "promoted_count": promoted_count,
            "promoted_by_motif": promoted_by_motif or {},
            "matcher_admitted_count": matcher_admitted_count,
            "conf_filtered_count": int(conf_filtered_count),
            "anchor_confirmed_count": anchor_confirmed_count,
            "llm_enabled": bool(llm_enabled),
            "llm_calls": int(llm_calls),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "rules_library": library or {},
    }


def build_report_from_outcome(outcome: RouteOutcome, scenario_name: str, *,
                              elapsed_seconds: float = 0.0, llm_calls: int = 0,
                              llm_enabled: bool = False, library: dict = None) -> dict:
    audit = outcome.audit
    return build_report(
        scenario_name=scenario_name,
        confirmed_edges=list(outcome.confirmed.values()),
        unexcluded_edges=outcome.unexcluded,
        excluded_edges=outcome.excluded,
        pruned_count=audit.get("pruned_count", 0),
        promoted_count=audit.get("promoted_count", 0),
        elapsed_seconds=elapsed_seconds,
        llm_calls=llm_calls,
        llm_enabled=llm_enabled,
        anchor_confirmed_count=audit.get("anchor_confirmed_count", 0),
        promoted_by_motif=audit.get("promoted_by_motif", {}),
        mode=audit.get("mode", "hybrid"),
        matcher_admitted_count=audit.get("matcher_admitted_count"),
        conf_filtered_count=audit.get("conf_filtered_count", 0),
        library=library,
    )


def save_report(report: dict, out_path: str) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
