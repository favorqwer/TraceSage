"""阶段 1：场景留一折规则库加载、反向因果闭包抽取与 POI 锚点事实确认。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from domain.pool import CandidatePool
from closure.intake import extract_raw_closure
from rules.library import load_library_file, _role_cuts
from core.context import PipelineContext


def run(ctx: PipelineContext) -> Tuple[
    List[Dict[str, Any]], Dict[str, Any], Any,
    Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    List[Tuple[Any, Any, Any]], Set[Tuple[Any, Any, Any]],
    CandidatePool, Any, Tuple[Any, Any, Any]
]:
    # 1. 读留一折规则库
    patterns, audit = load_library_file(ctx.fold_lib_path)
    admitted = audit.get("selected")
    role_cuts = _role_cuts(audit)
    rule_lib_tuple = (patterns, admitted, audit, role_cuts)

    # 2. 闭包抽取
    raw_edges, closure_stats, deps = extract_raw_closure(
        ctx.scenario, return_deps=True, log=lambda s: None
    )
    anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]
    anchor_keys = {tuple(t) for t in anchor_triples}

    # 3. 锚点事实确认
    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for e in raw_edges:
        k = edge_key(e)
        if k in anchor_keys:
            rec = dict(e)
            rec["origin"] = "confirmed"
            rec["class"] = "anchor"
            rec["reason"] = "告警事实锚点 (POI)"
            final_confirmed[k] = rec

    pool = CandidatePool(raw_edges)
    tf = pool.facts

    ctx.anchor_triples = anchor_triples
    ctx.anchor_keys = anchor_keys

    return (
        raw_edges, closure_stats, deps,
        final_confirmed, anchor_triples, anchor_keys,
        pool, tf, rule_lib_tuple
    )
