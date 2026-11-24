"""阶段 2：静态只读与背景噪声前置初筛。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from domain.edge import edge_key
from core.prepare import PreFilter


def run(
    raw_edges: List[Dict[str, Any]],
    anchor_keys: Set[Tuple[Any, Any, Any]],
    tf: Any,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    channel_input = [e for e in raw_edges if edge_key(e) not in anchor_keys]
    clean_unexcluded, pruned_background = PreFilter(tf).apply(channel_input)
    return clean_unexcluded, pruned_background
