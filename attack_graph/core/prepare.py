"""判定前准备：静态只读初筛。"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from domain.pool import TopologyFacts
from domain.taxonomy import STATIC_READ_PREFIXES

# POSIX / Linux 标准系统调用：无物理数据载荷的纯只读元数据与目录探测
PROBE_SYSCALLS = {
    "stat", "lstat", "fstat", "access", "faccessat",
    "readlink", "getdents", "getdents64"
}


class PreFilter:
    """前置初筛：静态只读、无污染、无交付的系统读取。"""

    def __init__(self, topology_facts: TopologyFacts):
        self.tf = topology_facts

    def apply(self, edges: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        kept: List[Dict[str, Any]] = []
        moved: List[Dict[str, Any]] = []
        prefixes = STATIC_READ_PREFIXES
        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))
            if sc == "read" and any(src.startswith(p) for p in prefixes):
                if not self.tf.is_tainted(src):
                    rec = dict(e)
                    rec["origin"] = "kept"
                    rec["prune_stage"] = "s2_prefilter"
                    rec["reason"] = "因果初筛：系统只读静态资源且无前序写入污染，归入未排除"
                    moved.append(rec)
                    continue
            if sc in PROBE_SYSCALLS:
                if not self.tf.is_tainted(src):
                    rec = dict(e)
                    rec["origin"] = "kept"
                    rec["prune_stage"] = "s2_prefilter"
                    rec["reason"] = "因果初筛：无物理数据载荷的只读元数据探测且无前序污染，归入未排除"
                    moved.append(rec)
                    continue
            kept.append(e)
        return kept, moved
