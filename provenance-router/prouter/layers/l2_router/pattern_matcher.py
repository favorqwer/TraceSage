from typing import Any, Dict, List, Set
from prouter.offline.distiller import OfflineDistiller


class PatternMatcher:
    """
    第二级匹配器：
    执行由 OfflineDistiller 动态提炼出的抽象因果拓扑基模匹配。
    完全根据离线知识蒸馏器输出的高置信度基模清单进行确定性规则匹配。
    """
    def __init__(self, topology_facts, patterns: List[Dict[str, Any]] = None):
        self.tf = topology_facts
        self.patterns = patterns or []

    def match(self, candidate_pool: List[Dict[str, Any]]) -> Set[tuple]:
        matched_triples = set()
        if not self.patterns:
            return matched_triples

        for e in candidate_pool:
            src = str(e.get("src", ""))
            sc = str(e.get("syscall", ""))
            dst = str(e.get("dst", ""))

            for pat in self.patterns:
                if OfflineDistiller.match_motif(pat, e, self.tf):
                    matched_triples.add((src, sc, dst))
                    break

        return matched_triples
