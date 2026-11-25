"""阶段 6：按现有证据整理确认边与待复核候选。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from domain.edge import edge_key
from domain.pool import CandidatePool
from core.axioms import collect_written_paths, is_passive_kernel_runtime_edge
from core.filters import DebrisPrune
from core.context import PipelineContext

_UNCONFIRMED_PROBE_SYSCALLS = frozenset({
    "ioctl", "stat", "lstat", "fstat", "access", "faccessat",
    "readlink", "getdents", "getdents64", "mmap",
})


def _drop_unconfirmed_reason(
    edge: Dict[str, Any],
    debris_prune: DebrisPrune,
    written_paths: Set[str],
) -> Optional[str]:
    """判定待复核候选是否应归入排除，返回原因或 None。"""
    if str(edge.get("verdict") or "").lower() == "none":
        return "模型已判整束无关"
    if str(edge.get("syscall") or "") in _UNCONFIRMED_PROBE_SYSCALLS:
        return "待复核纯只读元数据探测或被动内存映射，归入排除"
    if is_passive_kernel_runtime_edge(edge, written_paths=written_paths):
        return "待复核被动共享库或运行时只读伴随，归入排除"
    if debris_prune.is_operational_debris(edge):
        return "待复核包管理内部或基础设施伴生碎片，归入排除"
    return None


def run(
    ctx: PipelineContext,
    purified_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    pool: CandidatePool,
    unpromoted_ambiguous: List[Dict[str, Any]],
    pruned_background: List[Dict[str, Any]],
    remaining_ambiguous: List[Dict[str, Any]],
    excluded_edges: List[Dict[str, Any]],
) -> Tuple[
    Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    debris_prune = DebrisPrune(ctx.anchor_triples)
    final_confirmed_map, debris_pruned = debris_prune.apply(
        purified_confirmed, candidate_pool=pool.raw
    )

    if ctx.config.content_binding or ctx.config.split_evidence:
        for k, e in final_confirmed_map.items():
            ev = ctx.rule_evidence_map.get(k)
            if ev:
                e["evidence_motif_id"] = ev["motif_id"]

    rejected: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    stage_groups = (
        ("s4_llm_none", excluded_edges),
        ("s2_prefilter", pruned_background),
        ("s5_demoted", unpromoted_ambiguous),
        ("s6_debris", debris_pruned),
    )
    for default_stage, group in stage_groups:
        for edge in group:
            key = edge_key(edge)
            if key not in final_confirmed_map:
                rejected[key] = {
                    **edge,
                    "origin": "excluded",
                    "prune_stage": str(edge.get("prune_stage") or default_stage),
                }

    # 仅保留真正未决且非被动探测/包管理内部碎片的待复核候选。
    written_paths = collect_written_paths(list(final_confirmed_map.values()) + list(pool.raw))
    final_unexcluded: List[Dict[str, Any]] = []
    seen_unexcluded: set[Tuple[Any, Any, Any]] = set()
    for edge in remaining_ambiguous:
        key = edge_key(edge)
        if key in final_confirmed_map or key in seen_unexcluded:
            continue
        drop_reason = _drop_unconfirmed_reason(edge, debris_prune, written_paths)
        if drop_reason:
            p_stage = "s4_llm_none" if str(edge.get("verdict") or "").lower() == "none" else "s6_unconfirmed_filter"
            rejected[key] = {**edge, "origin": "excluded", "prune_stage": p_stage, "reason": drop_reason}
            continue
        seen_unexcluded.add(key)
        rec = {**edge, "origin": "kept"}
        rec.setdefault("decision_source", "unexcluded_kept")
        rec.pop("prune_stage", None)
        final_unexcluded.append(rec)
        rejected.pop(key, None)

    for edge in pool.raw:
        key = edge_key(edge)
        if key in final_confirmed_map or key in seen_unexcluded or key in rejected:
            continue
        drop_reason = _drop_unconfirmed_reason(edge, debris_prune, written_paths)
        if drop_reason:
            p_stage = "s4_llm_none" if str(edge.get("verdict") or "").lower() == "none" else "s6_unconfirmed_filter"
            rejected[key] = {**edge, "origin": "excluded", "prune_stage": p_stage, "reason": drop_reason}
            continue
        seen_unexcluded.add(key)
        rec = {**edge, "origin": "kept"}
        rec.setdefault("decision_source", "unexcluded_kept")
        rec.pop("prune_stage", None)
        final_unexcluded.append(rec)

    return final_confirmed_map, debris_pruned, final_unexcluded, list(rejected.values())
