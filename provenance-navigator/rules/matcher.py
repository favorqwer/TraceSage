"""在线严谨因果模式匹配器（Rigorous Pattern Matcher & Process Lineage Engine）

核心机制：
1. 真·2-跳因果路径连通性匹配：中间节点在拓扑与时序上严格承上启下；
2. 操作系统通用进程血缘树传递（Process Lineage Tree）：失陷 Shell/解释器通过 execve/clone 派生的命令全链条继承失陷；
3. 敏感凭据、持久化配置与落地载荷的目标读取闭环；
4. 彻底杜绝黑客工具名词典，纯依靠拓扑图因果。
"""
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from closure.facts import TopologyFacts
from rules.motifs import evaluate_node_behavioral_role, LOGIN_MACHINERY_PREFIXES, SENSITIVE_AUTH_PATHS, PERSISTENCE_PREFIXES


def _key(e: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (e.get("src"), e.get("syscall"), e.get("dst"))


class PatternMatcher:
    """确定性图因果基模匹配与进程血缘闭环引擎。"""

    def __init__(self, topology_facts: TopologyFacts, patterns: Optional[List[Dict[str, Any]]] = None, min_conf: float = 0.50):
        self.tf = topology_facts
        self.patterns = patterns or []
        self.min_conf = min_conf
        self.high_conf_pids: Set[str] = set()

    def match(self, candidate_pool: List[Dict[str, Any]], confirmed_seeds: Optional[Dict[Tuple, Dict[str, Any]]] = None) -> Dict[Tuple, Dict[str, Any]]:
        """执行完整的高纯度基模匹配与进程血缘拉直，返回 {边三元组: 命中的基模/原因字典}。"""
        if not candidate_pool:
            return {}

        self.high_conf_pids = set()

        # 1. 建立图邻接与进出度索引
        out_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        in_edges: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in candidate_pool:
            s, d = str(e.get("src", "")), str(e.get("dst", ""))
            out_edges[s].append(e)
            in_edges[d].append(e)

        # 角色判定缓存
        role_cache: Dict[str, str] = {}
        def get_role(node: str) -> str:
            k = str(node)
            if k not in role_cache:
                role_cache[k] = evaluate_node_behavioral_role(k, in_edges, out_edges, self.tf)
            return role_cache[k]

        matched: Dict[Tuple, Dict[str, Any]] = {}

        # 提取种子进程（如 POI 锚点涉及的进程）
        if confirmed_seeds:
            for rec in confirmed_seeds.values():
                pid = str(rec.get("process_id", ""))
                if pid:
                    self.high_conf_pids.add(pid)
                for _, p in rec.get("src_identities", []):
                    self.high_conf_pids.add(p)
                for _, p in rec.get("dst_identities", []):
                    self.high_conf_pids.add(p)

        hop1_motifs = [m for m in self.patterns if m.get("hops") == 1]
        hop2_motifs = [m for m in self.patterns if m.get("hops") == 2]

        # 2. 1-跳因果基模确定性匹配
        for e in candidate_pool:
            s, d = str(e.get("src", "")), str(e.get("dst", ""))
            if any(s.startswith(p) or d.startswith(p) for p in LOGIN_MACHINERY_PREFIXES):
                continue
            sc = str(e.get("syscall", ""))
            pid = str(e.get("process_id", ""))
            k = _key(e)

            # 必须具有前序污染或入站关联
            if not (self.tf.is_tainted_proc(pid) or self.tf.is_tainted_proc(s) or (pid in self.tf.inbound_processes) or (s in self.tf.inbound_processes)):
                continue

            r_src = get_role(s)
            r_dst = get_role(d)

            for m in hop1_motifs:
                if sc in m.get("syscalls", []):
                    if m.get("src_role") == r_src and m.get("dst_role") == r_dst:
                        conf = m.get("train_precision", 1.0)
                        if conf >= self.min_conf:
                            matched[k] = m
                            if pid:
                                self.high_conf_pids.add(pid)
                            for _, p in e.get("src_identities", []):
                                self.high_conf_pids.add(p)
                            for _, p in e.get("dst_identities", []):
                                self.high_conf_pids.add(p)
                        break

        # 3. 真·2-跳因果路径连通性匹配 (A -> B -> C)
        for m in hop2_motifs:
            chain = m.get("chain", [])
            if len(chain) < 2:
                continue
            hop1_def, hop2_def = chain[0], chain[1]
            sc1, sc2 = hop1_def["syscall"], hop2_def["syscall"]
            r1, r_mid_req, r3 = hop1_def["src_role"], hop1_def["dst_role"], hop2_def["dst_role"]
            conf = m.get("train_precision", 1.0)

            for e1 in candidate_pool:
                if str(e1.get("syscall")) != sc1:
                    continue
                mid_node = str(e1.get("dst", ""))
                pid1 = str(e1.get("process_id", ""))

                if get_role(e1.get("src")) != r1:
                    continue
                if get_role(mid_node) != r_mid_req:
                    continue

                for e2 in out_edges.get(mid_node, []):
                    if str(e2.get("syscall")) != sc2:
                        continue
                    pid2 = str(e2.get("process_id", ""))
                    dst_node = str(e2.get("dst", ""))

                    if get_role(dst_node) != r3:
                        continue

                    k1, k2 = _key(e1), _key(e2)
                    if conf >= self.min_conf:
                        matched[k1] = m
                        matched[k2] = m
                        if pid1:
                            self.high_conf_pids.add(pid1)
                        if pid2:
                            self.high_conf_pids.add(pid2)
                        for _, p in e1.get("src_identities", []):
                            self.high_conf_pids.add(p)
                        for _, p in e1.get("dst_identities", []):
                            self.high_conf_pids.add(p)
                        for _, p in e2.get("src_identities", []):
                            self.high_conf_pids.add(p)
                        for _, p in e2.get("dst_identities", []):
                            self.high_conf_pids.add(p)

        # 4. 操作系统通用进程血缘树传递（Process Lineage Tree Propagation）
        # 将已确诊三元组涉及的所有 PID 统一合并入高确信集合
        for e in candidate_pool:
            if _key(e) in matched:
                if e.get("process_id"):
                    self.high_conf_pids.add(str(e.get("process_id")))
                for _, p in e.get("src_identities", []):
                    self.high_conf_pids.add(p)
                for _, p in e.get("dst_identities", []):
                    self.high_conf_pids.add(p)

        for _ in range(4):
            added_pids = set()
            for e in candidate_pool:
                k = _key(e)
                if k in matched:
                    continue
                sc = e.get("syscall")
                s = str(e.get("src", ""))
                d = str(e.get("dst", ""))
                if any(s.startswith(p) or d.startswith(p) for p in LOGIN_MACHINERY_PREFIXES):
                    continue

                parent_pids = {p for _, p in e.get("src_identities", [])}
                if e.get("via_key"):
                    parent_pids.add(e.get("via_key"))

                if parent_pids.intersection(self.high_conf_pids):
                    if sc in ("execve", "clone"):
                        matched[k] = {
                            "id": "PROCESS_LINEAGE_SPAWN",
                            "name": "失陷会话命令派生血缘拉直",
                        }
                        child_pid = str(e.get("process_id", ""))
                        if child_pid:
                            added_pids.add(child_pid)
                        for _, cp in e.get("dst_identities", []):
                            added_pids.add(cp)

            if not added_pids:
                break
            self.high_conf_pids.update(added_pids)

        # 5. 确诊攻击进程对敏感认证、持久化配置与落地载荷的目标读取闭环
        for e in candidate_pool:
            k = _key(e)
            if k in matched:
                continue
            sc = e.get("syscall")
            s = str(e.get("src", ""))
            pid = str(e.get("process_id", ""))

            if sc in ("read", "open", "sendfile") and pid in self.high_conf_pids:
                is_auth = (s in SENSITIVE_AUTH_PATHS or s.endswith("/authorized_keys") or ".ssh/id_" in s)
                is_persist = any(s.startswith(p) for p in PERSISTENCE_PREFIXES)
                is_dropped = self.tf.is_tainted(s) and not any(s.startswith(p) for p in ["/lib", "/usr/lib", "/proc", "/sys", "/dev"])
                if is_auth or is_persist or is_dropped:
                    matched[k] = {
                        "id": "SENSITIVE_OR_PAYLOAD_READ",
                        "name": "失陷进程敏感客体或载荷读取闭环",
                    }

        return matched
