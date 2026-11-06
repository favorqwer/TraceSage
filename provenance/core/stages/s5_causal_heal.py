"""阶段 5：因果公理链路补全与伴随边纯化。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from core.axioms import heal_and_purify_causal_closure


def run(
    llm_confirmed: List[Dict[str, Any]],
    final_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    clean_unexcluded: List[Dict[str, Any]],
    excluded_edges: List[Dict[str, Any]],
    anchor_keys: Set[Tuple[Any, Any, Any]],
) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
    # 过滤未知执行体粗粒度泛化
    for e in llm_confirmed:
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")
        sc = str(e.get("syscall") or "")
        if (src == "<NA>" or dst == "<NA>") and sc in ("execve", "clone"):
            continue
        final_confirmed[edge_key(e)] = e

    purified_confirmed, unpromoted_ambiguous = heal_and_purify_causal_closure(
        initial_confirmed=final_confirmed,
        clean_unexcluded=clean_unexcluded,
        excluded_edges=excluded_edges,
        anchor_keys=anchor_keys,
    )
    return purified_confirmed, unpromoted_ambiguous
