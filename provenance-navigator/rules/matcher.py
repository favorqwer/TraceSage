"""在线模式匹配器（PatternMatcher）：

执行由 OfflineDistiller 统计筛选出的抽象因果拓扑基模匹配。
完全依据蒸馏器输出的入选基模清单进行确定性匹配，并记录每条命中边对应的基模编号（供查准归因）。
同时对命中的攻击进程执行因果骨架拉直（补齐其父子进程派生边）。
"""
from typing import Any, Dict, List
from closure.facts import TopologyFacts
from rules.motifs import match_motif

LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
)


class PatternMatcher:
    """
    确定性抽象图因果模式匹配器。
    """
    def __init__(self, topology_facts: TopologyFacts, patterns: List[Dict[str, Any]] = None):
        self.tf = topology_facts
        self.patterns = patterns or []

    def match(self, candidate_pool: List[Dict[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
        """返回 {内容三元组: 命中的基模}；同一候选边命中多个基模时取基模清单中的首个。
        同时对命中的攻击进程执行因果骨架拉直（补齐其父子进程派生边）。
        """
        matched: Dict[tuple, Dict[str, Any]] = {}
        if not self.patterns:
            return matched

        matched_pids = set()
        for e in candidate_pool:
            src, dst = str(e.get("src", "")), str(e.get("dst", ""))
            if src.startswith(LOGIN_MACHINERY_PREFIXES) or dst.startswith(LOGIN_MACHINERY_PREFIXES):
                continue
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            for pat in self.patterns:
                if match_motif(pat, e, self.tf):
                    matched[key] = pat
                    if e.get("process_id"):
                        matched_pids.add(e.get("process_id"))
                    break

        # 因果骨架拉直：对于命中的进程，将其对应的父子派生边一并确认为骨架
        if matched_pids:
            for e in candidate_pool:
                if e.get("syscall") == "execve" and e.get("process_id") in matched_pids:
                    key = (e.get("src"), e.get("syscall"), e.get("dst"))
                    if key not in matched:
                        matched[key] = {
                            "id": "BACKBONE_DERIVATION",
                            "name": "攻击进程父子派生骨架拉直",
                        }

        return matched
