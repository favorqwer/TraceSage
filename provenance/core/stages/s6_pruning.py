"""阶段 6：后置碎屑与噪声剪枝 (DebrisPrune)。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from domain.pool import CandidatePool
from core.filters import DebrisPrune
from core.context import PipelineContext


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
    final_confirmed_map, debris_pruned = DebrisPrune(ctx.anchor_triples).apply(
        purified_confirmed, candidate_pool=pool.raw
    )

    if ctx.config.content_binding or ctx.config.split_evidence:
        for k, e in final_confirmed_map.items():
            ev = ctx.rule_evidence_map.get(k)
            if ev:
                e["evidence_motif_id"] = ev["motif_id"]

    final_unexcluded = (
        list(unpromoted_ambiguous)
        + list(pruned_background)
        + list(debris_pruned)
        + [e for e in remaining_ambiguous if edge_key(e) not in final_confirmed_map]
    )

    final_excluded = [e for e in excluded_edges if edge_key(e) not in final_confirmed_map]

    return final_confirmed_map, debris_pruned, final_unexcluded, final_excluded
