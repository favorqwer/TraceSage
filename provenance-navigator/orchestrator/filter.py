"""混合调度编排中枢：因果初筛器（CausalFilter）

职责：
利用双向因果拓扑事实，毫秒级剥离无前序污染、无外部交付的自闭环系统读取。
"""
from typing import Any, Dict, List, Tuple
from closure.facts import TopologyFacts


class CausalFilter:
    """
    第一级初筛器：
    利用双向因果拓扑事实，毫秒级剥离无前序污染、无外部交付的自闭环系统读取。
    """
    def __init__(self, topology_facts: TopologyFacts):
        self.tf = topology_facts

    def filter(self, edges: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        kept = []
        pruned = []

        prefixes = (
            "/proc/", "/sys/", "/lib/", "/usr/lib/", "/usr/share/",
            "/etc/ld.so.", "/etc/locale", "/usr/include/", "/dev/urandom", "/dev/null"
        )

        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))

            # 若操作为 read，且源属于静态系统公共路径，且全图历史上从未被污染
            if sc == "read" and any(src.startswith(p) for p in prefixes):
                if not self.tf.is_tainted(src):
                    e_copy = dict(e)
                    e_copy["origin"] = "kept"
                    e_copy["reason"] = "因果初筛：系统只读静态资源且无前序写入污染，归入未排除"
                    pruned.append(e_copy)
                    continue

            kept.append(e)

        return kept, pruned
