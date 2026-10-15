"""频繁因果子图自动挖掘算法 (Frequent Causal Subgraph Miner)

核心原理：
从给定的多个训练场景的攻击路径标准答案图（Ground Truth）中，全自动发现并提炼
跨场景频繁重复出现的多跳因果子图拓扑骨架，完全淘汰人工手写的工具字典模板。

算法流程：
1. 节点语义角色客观拓扑抽象 (abstract_node_role：Process, Socket, DroppedFile, SensitiveAuth, PersistenceConfig)；
2. 构造攻击因果有向多重图 (Causal Directed Multigraph)；
3. 遍历抽取 1-跳核心原子拓扑与 2-跳因果链条骨架；
4. 规范化图编码 (Canonical Graph Encoding) 与同构归一；
5. 计算跨场景支持度 (默认 min_support=1，不人为设置与数据集大小强绑定的剪枝门槛)；
6. 自动编译生成候选因果拓扑基模库 (Mined Motifs)。
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from rules.motifs import abstract_node_role

REPO_ROOT = Path(__file__).resolve().parents[2]


class FrequentSubgraphMiner:
    """频繁因果子图自动挖掘器。"""

    def __init__(self, min_support: int = 1):
        self.min_support = min_support

    def load_gt_graph(self, scenario: str) -> List[Dict[str, Any]]:
        gt_file = REPO_ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
        if not gt_file.exists():
            raise FileNotFoundError(f"未找到场景标准答案文件: {gt_file}")
        with open(gt_file, "r", encoding="utf-8") as f:
            gt = json.load(f)
        edges = []
        for phase in gt.get("attack_path", []):
            for e in phase.get("edges", []) or []:
                edges.append({
                    "src": str(e.get("src")),
                    "syscall": str(e.get("syscall")),
                    "dst": str(e.get("dst")),
                    "phase": phase.get("id"),
                })
        return edges

    def mine(self, train_scenarios: List[str]) -> List[Dict[str, Any]]:
        """从训练场景集中全自动挖掘高频子图模式。"""
        scenario_graphs: Dict[str, List[Dict[str, Any]]] = {}
        for sc in train_scenarios:
            scenario_graphs[sc] = self.load_gt_graph(sc)

        # 1. 抽取 1-跳原子因果拓扑边
        # 模式表示为元组：(src_role, syscall, dst_role)
        pattern_scenarios_1hop = defaultdict(set)
        for sc, edges in scenario_graphs.items():
            for e in edges:
                src_role = abstract_node_role(e["src"], edges)
                dst_role = abstract_node_role(e["dst"], edges)
                pat_key = (src_role, e["syscall"], dst_role)
                pattern_scenarios_1hop[pat_key].add(sc)

        # 2. 抽取 2-跳连续因果链拓扑
        # 模式表示为：(src_role, sc1, mid_role, sc2, dst_role)
        pattern_scenarios_2hop = defaultdict(set)
        for sc, edges in scenario_graphs.items():
            out_edges = defaultdict(list)
            for e in edges:
                out_edges[e["src"]].append(e)

            for e1 in edges:
                mid = e1["dst"]
                for e2 in out_edges.get(mid, []):
                    r_src = abstract_node_role(e1["src"], edges)
                    r_mid = abstract_node_role(mid, edges)
                    r_dst = abstract_node_role(e2["dst"], edges)
                    pat_2hop = (r_src, e1["syscall"], r_mid, e2["syscall"], r_dst)
                    pattern_scenarios_2hop[pat_2hop].add(sc)

        # 3. 统计跨场景支持度并编译候选基模
        mined_motifs: List[Dict[str, Any]] = []
        motif_counter = 1

        # 编译 1-跳高频拓扑
        for (r_src, sc, r_dst), scs in pattern_scenarios_1hop.items():
            if len(scs) >= self.min_support:
                # 过滤完全泛化的无鉴别力模式
                if r_src == "GENERIC_PROC_OR_FILE" and r_dst == "GENERIC_PROC_OR_FILE":
                    continue
                mined_motifs.append({
                    "id": f"MINED_{motif_counter:02d}_1HOP_{sc.upper()}",
                    "name": f"自动挖掘1跳骨架: {r_src} --{sc}--> {r_dst}",
                    "hops": 1,
                    "src_role": r_src,
                    "syscalls": [sc],
                    "dst_role": r_dst,
                    "mined_support_scenarios": len(scs),
                    "support_scenarios_list": sorted(list(scs)),
                })
                motif_counter += 1

        # 编译 2-跳高频拓扑链
        for (r_src, sc1, r_mid, sc2, r_dst), scs in pattern_scenarios_2hop.items():
            if len(scs) >= self.min_support:
                mined_motifs.append({
                    "id": f"MINED_{motif_counter:02d}_2HOP_CHAIN",
                    "name": f"自动挖掘2跳因果链: {r_src} --{sc1}--> {r_mid} --{sc2}--> {r_dst}",
                    "hops": 2,
                    "chain": [
                        {"src_role": r_src, "syscall": sc1, "dst_role": r_mid},
                        {"src_role": r_mid, "syscall": sc2, "dst_role": r_dst},
                    ],
                    "syscalls": [sc1, sc2],
                    "mined_support_scenarios": len(scs),
                    "support_scenarios_list": sorted(list(scs)),
                })
                motif_counter += 1

        return mined_motifs
