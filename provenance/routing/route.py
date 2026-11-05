"""路由编排：按模式表调用锚点确认、前置初筛、符号通道、LLM 通道与后置剪枝。

本文件只决定“调用谁、按什么顺序、结果怎么合并”，不包含任何具体判据：
- 前置初筛在 `routing/prepare.PreFilter`；
- 后置剪枝在 `routing/filters.DebrisPrune`；
- 符号通道在 `rules/online.py`；
- 慢速通道在 `llm/judge.py`。

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from domain.pool import CandidatePool, TopologyFacts
from domain.edge import edge_key
from routing.channels import (
    BoundaryStoryOperator, SessionActiveBridge, promote_lineage, promote_sensitive,
)
from routing.filters import DebrisPrune
from routing.prepare import PreFilter
from rules.online import MatchIndex


@dataclass(frozen=True)
class ModeSpec:
    name: str
    channels: Tuple[str, ...]
    llm: bool
    library: bool


MODES: Dict[str, ModeSpec] = {
    "rules": ModeSpec("rules", ("anchor", "motif", "bridge", "boundary"), False, True),
    "hybrid": ModeSpec("hybrid", ("anchor", "motif", "bridge", "boundary", "llm"), True, True),
    "llm-only": ModeSpec("llm-only", ("anchor", "llm"), True, False),
}


@dataclass
class RouteOutcome:
    confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]]
    unexcluded: List[Dict[str, Any]]
    excluded: List[Dict[str, Any]]
    audit: Dict[str, Any] = field(default_factory=dict)


def _key(edge: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return edge_key(edge)


def _promote(edge: Dict[str, Any], *, channel: str, motif_id: str,
             motif_name: str = "", reason: str = "") -> Dict[str, Any]:
    rec = dict(edge)
    rec["origin"] = "confirmed"
    rec["class"] = "story"
    rec["motif"] = motif_id
    if motif_name:
        rec["motif_name"] = motif_name
    if reason:
        rec["reason"] = reason
    return rec


def route(confirmed_edges: List[Dict[str, Any]],
          unexcluded_edges: List[Dict[str, Any]],
          anchor_triples: Optional[List[Tuple[Any, Any, Any]]] = None,
          *,
          patterns: Optional[List[Dict[str, Any]]] = None,
          llm_channel: Optional[Any] = None,
          mode: str = "hybrid",
          admitted: Optional[Any] = None,
          role_cuts: Optional[Any] = None) -> RouteOutcome:
    spec = MODES.get(mode)
    if spec is None:
        raise ValueError(f"未知模式 {mode!r}；可选 {sorted(MODES)}")

    candidate_pool = list(confirmed_edges) + list(unexcluded_edges)
    pool = CandidatePool(candidate_pool)
    tf = pool.facts

    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for e in confirmed_edges:
        final_confirmed[_key(e)] = e
    pool_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for e in candidate_pool:
        pool_map.setdefault(_key(e), e)

    # 通道零：锚点事实确认
    anchor_keys = {tuple(t) for t in (anchor_triples or [])}
    anchor_confirmed: List[Dict[str, Any]] = []
    for key in anchor_keys:
        if key in final_confirmed:
            continue
        edge = pool_map.get(key)
        if edge is None:
            continue
        rec = dict(edge)
        rec["origin"] = "confirmed"
        rec["class"] = "anchor"
        rec["reason"] = "告警事实锚点（POI）事实确认"
        final_confirmed[key] = rec
        anchor_confirmed.append(rec)

    # 通道一：前置初筛
    channel_input = [e for e in unexcluded_edges if _key(e) not in anchor_keys]
    clean_unexcluded, pruned_background = PreFilter(tf).apply(channel_input)

    rule_promoted: List[Dict[str, Any]] = []
    promoted_by_motif: Dict[str, int] = {}
    matcher_admitted_count: Optional[int] = None
    conf_filtered_count = 0
    matcher = None

    # 通道二：符号促进
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    if "motif" in spec.channels:
        matcher = MatchIndex(clean_pool, tf, role_cuts=role_cuts)
        matcher_admitted_count = (len(admitted) if admitted is not None else len(patterns or []))
        matched = matcher.match(patterns or [], admitted=admitted,
                                seed_edges=final_confirmed)
        high = matcher.high_conf_pids
        high = promote_lineage(matcher, matched, high)
        high = promote_sensitive(matcher, matched, high)
        matcher.high_conf_pids = high
        conf_filtered_count = matcher.filtered_by_conf
        for e in clean_unexcluded:
            key = _key(e)
            pat = matched.get(key)
            if pat is None:
                continue
            rec = _promote(e, channel="motif", motif_id=pat.get("id"),
                           motif_name=pat.get("name", ""),
                           reason=f"快速通道：抽象图基模 {pat.get('id')} 确定性确认")
            final_confirmed[key] = rec
            rule_promoted.append(rec)
            promoted_by_motif[pat.get("id")] = promoted_by_motif.get(pat.get("id"), 0) + 1

    if "bridge" in spec.channels:
        bridged = SessionActiveBridge().bridge(
            clean_pool, final_confirmed,
            high_conf_pids=matcher.high_conf_pids if matcher is not None else None,
        )
        for key, rec in bridged.items():
            final_confirmed[key] = rec
            rule_promoted.append(rec)
            motif_id = rec.get("motif", "CAUSAL_BRIDGE")
            promoted_by_motif[motif_id] = promoted_by_motif.get(motif_id, 0) + 1

    if "boundary" in spec.channels:
        story = BoundaryStoryOperator().promote(pool, final_confirmed)
        for key, rec in story.items():
            final_confirmed[key] = rec
            rule_promoted.append(rec)
            motif_id = rec.get("motif", "BOUNDARY_STORY")
            promoted_by_motif[motif_id] = promoted_by_motif.get(motif_id, 0) + 1

    ambiguous_candidates = [e for e in clean_unexcluded if _key(e) not in final_confirmed]
    llm_confirmed: List[Dict[str, Any]] = []
    excluded_edges: List[Dict[str, Any]] = []
    remaining_ambiguous: List[Dict[str, Any]] = []

    if "llm" in spec.channels and llm_channel is not None and ambiguous_candidates:
        if getattr(llm_channel, "deps", None) is not None:
            inv = llm_channel.deps.record
            for key in final_confirmed:
                if key in inv.edges:
                    inv.mark([key], "confirmed")
            for e in pruned_background:
                key = _key(e)
                if key in inv.edges:
                    inv.mark([key], "kept")
        llm_results = llm_channel.judge(ambiguous_candidates, tf)
        for e in llm_results.get("confirmed", []):
            key = _key(e)
            final_confirmed[key] = e
            llm_confirmed.append(e)
        for e in llm_results.get("excluded", []):
            excluded_edges.append(e)
        remaining_ambiguous = llm_results.get("kept", [])
    else:
        remaining_ambiguous = ambiguous_candidates

    # 通道三：后置剪枝（只移入未排除）
    final_confirmed, debris_pruned = DebrisPrune(anchor_triples).apply(
        final_confirmed, candidate_pool=pool.raw
    )
    final_unexcluded = list(remaining_ambiguous) + list(pruned_background) + list(debris_pruned)

    return RouteOutcome(
        confirmed=final_confirmed,
        unexcluded=final_unexcluded,
        excluded=excluded_edges,
        audit={
            "mode": mode,
            "pruned_count": len(pruned_background),
            "promoted_count": len(rule_promoted),
            "ambiguous_count": len(ambiguous_candidates),
            "llm_confirmed_count": len(llm_confirmed),
            "anchor_confirmed_count": len(anchor_confirmed),
            "debris_pruned_count": len(debris_pruned),
            "promoted_by_motif": promoted_by_motif,
            "matcher_admitted_count": matcher_admitted_count,
            "conf_filtered_count": conf_filtered_count,
            "fast_path_rules": len(rule_promoted),
            "slow_path_llm_confirmed": len(llm_confirmed),
        },
    )
