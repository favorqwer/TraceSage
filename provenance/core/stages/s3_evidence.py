"""阶段 3：符号基模匹配、证据图谱索引与进程血缘拓扑表构建。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from domain.pool import CandidatePool
from rules.online import MatchIndex
from core.decoder import decode_motif
from core.context import PipelineContext


def run(
    ctx: PipelineContext,
    clean_unexcluded: List[Dict[str, Any]],
    raw_edges: List[Dict[str, Any]],
    pool: CandidatePool,
    tf: Any,
    rule_lib_tuple: Tuple[Any, Any, Any, Any],
    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
) -> Tuple[
    MatchIndex,
    Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    Dict[str, str],
    List[Dict[str, Any]],
]:
    patterns, admitted, audit, role_cuts = rule_lib_tuple

    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, tf, role_cuts=role_cuts)
    ctx.matcher = matcher

    matched = matcher.match(patterns or [], admitted=admitted, seed_edges=final_confirmed)

    motif_by_id = {str(m["id"]): m for m in audit["motifs"]}
    rule_evidence_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for k, pat in matched.items():
        mid = pat.get("id")
        full_m = motif_by_id.get(mid, pat)
        rule_evidence_map[k] = {
            "motif_id": mid,
            "motif_name": pat.get("name", ""),
            "decoded_desc": decode_motif(full_m, real_2hop=ctx.config.real_2hop),
            "support_scenarios": full_m.get("support_scenarios_list", []),
        }
    ctx.rule_evidence_map = rule_evidence_map

    # 进程血缘拓扑表构建
    parent_map: Dict[str, str] = {}
    for e in raw_edges:
        if e.get("syscall") in ("execve", "clone"):
            p_src = str(e.get("src", ""))
            p_dst = str(e.get("dst", ""))
            if p_src and p_dst and p_src != p_dst:
                parent_map[p_dst] = p_src
    ctx.parent_map = parent_map

    ambiguous_candidates = [e for e in clean_unexcluded if edge_key(e) not in final_confirmed]

    # 高精度符号通道直确认（可选）
    if ctx.config.anchor_pair_confirm:
        import llm.judge as judge_mod
        # 兼容 anchor_pair_confirm 逻辑
        pass

    return matcher, rule_evidence_map, parent_map, ambiguous_candidates
