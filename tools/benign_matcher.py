#!/usr/bin/env python3
"""
benign_matcher.py
TraceSage 良性子图基模结构化检索接口
支持 R2 精确图匹配、R1 部分因果匹配、子图包含度评分与安全红线核验
"""

import os
import json
import time
from typing import Dict, List, Tuple, Optional, Any

class BenignMotifMatcher:
    def __init__(self, kg_path: str = "output/rule-kg/canonical_benign_kg.json"):
        self.kg_path = kg_path
        if not os.path.exists(kg_path):
            raise FileNotFoundError(f"基模知识库文件不存在: {kg_path}")
        
        with open(kg_path, "r", encoding="utf-8") as f:
            self.kg_data = json.load(f)
            
        self.canonical_motifs = self.kg_data.get("canonical_motifs", [])
        
        # 索引加速:
        # 1. R2 精确跳链索引: (src_role, action) -> list of (motif, dst_role)
        self.r2_index = {}
        # 2. 角色集合索引: role -> list of motif_ids
        self.role_index = {}
        
        self._build_indexes()

    def _build_indexes(self):
        for m in self.canonical_motifs:
            arch_id = m["archetype_id"]
            for r in m.get("core_roles", []):
                if r not in self.role_index:
                    self.role_index[r] = []
                self.role_index[r].append(arch_id)

            for hop in m.get("canonical_hop_chains", []):
                # 解析形如: "F.USER_DATA.READ --(read:sendfile)--> P.WEB_SERVER.USER.HOST"
                if "--(" in hop and ")-->" in hop:
                    parts = hop.split(" --(")
                    src = parts[0].strip()
                    rest = parts[1].split(")--> ")
                    act_call = rest[0].strip()
                    dst = rest[1].strip()
                    act = act_call.split(":")[0].strip()

                    key_exact = (src, act, dst)
                    if key_exact not in self.r2_index:
                        self.r2_index[key_exact] = []
                    self.r2_index[key_exact].append(m)

    # sysdig 系统调用名 -> 基模跳链里书写的动作名。第二项是方向条件：
    #   src = 该别名只在源角色是 Network 时成立（网络收包 read 实为 recv）
    #   dst = 该别名只在目标角色是 Network 时成立（网络发包 write 实为 send）
    #   any = 不限方向
    # 基模跳链只记录了动作名，未记录系统调用名，因此必须按方向补回这一层对应关系。
    ACTION_ALIASES: Dict[str, tuple] = {
        "read": (("src", "recv"),),
        "write": (("dst", "send"),),
        "sendto": (("any", "send"),),
        "recvfrom": (("any", "recv"),),
        "open": (("any", "create"),),
        "creat": (("any", "create"),),
        "mmap": (("any", "mmap_read"), ("any", "mmap_exec")),
        "execve": (("any", "exec"),),
    }

    @classmethod
    def candidate_actions(cls, src_role: str, action: str, dst_role: str) -> List[str]:
        """把系统调用名归一化为基模动作名候选集合。

        传入的系统调用名本身永远保留在候选里：文件读事件与网络收包事件都叫 read，
        只补充别名、不替换原名，否则会丢掉文件读方向的 R2 命中。
        """
        act = (action or "").strip().lower()
        out: List[str] = [act] if act else []
        src_is_net = str(src_role or "").startswith("N.")
        dst_is_net = str(dst_role or "").startswith("N.")
        for scope, alias in cls.ACTION_ALIASES.get(act, ()):
            if scope == "src" and not src_is_net:
                continue
            if scope == "dst" and not dst_is_net:
                continue
            if alias not in out:
                out.append(alias)
        return out

    def match_single_edge(self, src_role: str, action: str, dst_role: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        单条候选边/跳的快速检索 (模拟 TraceSage 两段证据的 R2/R1 契约)
        集成安全红线断言核验与父进程谱系上下文约束
        """
        # 1. 全局安全红线核验（否定事实优先原则）
        # 规则 A: 敏感私钥凭证严禁被常规系统工具 (cat/sed/awk) 或交互式 Shell 读取
        if src_role.startswith("F.AUTH_KEY") and action in ("read", "open", "mmap_read"):
            if "SYSTEM_UTILITY" in dst_role or "INTERACTIVE_SHELL" in dst_role:
                return {
                    "match_level": "SECURITY_VIOLATION",
                    "matched": False,
                    "confidence": 0.0,
                    "reason": "触碰安全红线: 敏感私钥凭证严禁由通用工具或交互式 Shell 直接读取",
                    "motifs": []
                }

        # 规则 B: 交互式 Shell 派生的进程严禁建立通向远程管理服务的隐蔽外传流
        if context:
            parent_role = context.get("parent_role", "")
            if "INTERACTIVE_SHELL" in parent_role and action == "write" and dst_role.startswith("F.IPC_SOCKET"):
                if context.get("is_pipe_to_admin", False):
                    return {
                        "match_level": "SECURITY_VIOLATION",
                        "matched": False,
                        "confidence": 0.0,
                        "reason": "触碰安全红线: 交互式 Shell 派生工具链向管理服务管道写入数据外传流",
                        "motifs": []
                    }

        actions = self.candidate_actions(src_role, action, dst_role)

        # 2. R2 精确匹配（按方向归一化后的动作名逐个别名查询）
        for act in actions:
            key = (src_role, act, dst_role)
            if key not in self.r2_index:
                continue
            matched_motifs = self.r2_index[key]
            # 过滤违反基模专有 forbidden_roles 的条目
            valid_motifs = []
            for m in matched_motifs:
                forbidden = m.get("forbidden_roles", [])
                if any(fb in src_role or fb in dst_role for fb in forbidden):
                    continue
                valid_motifs.append(m)

            if valid_motifs:
                return {
                    "match_level": "R2_EXACT",
                    "matched": True,
                    "confidence": 1.0,
                    "action_used": act,
                    "motifs": [
                        {
                            "archetype_id": m["archetype_id"],
                            "title": m["title"],
                            "category": m["category"],
                            "security_boundary": m["security_boundary"]
                        } for m in valid_motifs
                    ]
                }

        # 3. R1 部分匹配 (锚点收敛：动作一致，且匹配的一侧必须是核心锚点实体)
        # 拒绝粗放泛化：若涉及 AUTH_KEY 则禁止 R1 泛化匹配
        if "AUTH_KEY" in src_role or "AUTH_KEY" in dst_role:
            return {
                "match_level": "NONE",
                "matched": False,
                "confidence": 0.0,
                "motifs": []
            }

        r1_hits = []
        for (idx_src, idx_act, idx_dst), motifs in self.r2_index.items():
            if idx_act not in actions:
                continue
            src_ok = idx_src == src_role
            dst_ok = idx_dst == dst_role
            # 双侧锚点：至少一侧精确相等，另一侧必须落在该基模的核心角色集合里。
            # 只允许一侧对齐时，任意共享一个角色与动作的跳链都会被算成部分命中，
            # 目标端类型可以完全不同（例如写本地 socket 的跳链被拿去对齐写网络）。
            if not src_ok and not dst_ok:
                continue
            other_role = dst_role if src_ok else src_role
            for m in motifs:
                forbidden = m.get("forbidden_roles", [])
                if any(fb in src_role or fb in dst_role for fb in forbidden):
                    continue
                core_roles = m.get("core_roles", [])
                if other_role not in core_roles:
                    continue
                r1_hits.append({
                    "archetype_id": m["archetype_id"],
                    "title": m["title"],
                    "aligned_hop": f"{idx_src} -({idx_act})-> {idx_dst}",
                    "action_used": idx_act,
                    "exact_side": "src" if src_ok else "dst",
                    "other_role": other_role,
                    "security_boundary": m["security_boundary"]
                })

        if r1_hits:
            return {
                "match_level": "R1_PARTIAL",
                "matched": True,
                "confidence": 0.65,
                "motifs": r1_hits[:3]
            }

        return {
            "match_level": "NONE",
            "matched": False,
            "confidence": 0.0,
            "motifs": []
        }

    def match_subgraph(self, edges: List[Tuple[str, str, str]]) -> Dict[str, Any]:
        """
        多跳因果子图检索与重合度打分
        edges: list of (src_role, action, dst_role)
        """
        if not edges:
            return {"matched": False, "score": 0.0, "reason": "空输入子图"}

        arch_scores = {}

        for m in self.canonical_motifs:
            arch_id = m["archetype_id"]
            canonical_hops = m.get("canonical_hop_chains", [])
            
            # 解析基模所有标准跳
            motif_hop_set = set()
            for hop in canonical_hops:
                if "--(" in hop and ")-->" in hop:
                    parts = hop.split(" --(")
                    src = parts[0].strip()
                    rest = parts[1].split(")--> ")
                    act = rest[0].split(":")[0].strip()
                    dst = rest[1].strip()
                    motif_hop_set.add((src, act, dst))

            if not motif_hop_set:
                continue

            # 计算交集命中
            hit_exact = [e for e in edges if e in motif_hop_set]
            hit_roles = set([e[0] for e in edges] + [e[2] for e in edges]).intersection(set(m.get("core_roles", [])))

            # Jaccard 相似度加权
            edge_recall = len(hit_exact) / len(edges)
            role_overlap = len(hit_roles) / len(set([e[0] for e in edges] + [e[2] for e in edges]))

            total_score = round(0.7 * edge_recall + 0.3 * role_overlap, 3)

            if total_score > 0.2:
                arch_scores[arch_id] = {
                    "archetype_id": arch_id,
                    "title": m["title"],
                    "category": m["category"],
                    "score": total_score,
                    "hit_exact_edges": len(hit_exact),
                    "total_query_edges": len(edges),
                    "matched_edges": hit_exact,
                    "security_boundary": m["security_boundary"]
                }

        # 排序取最优
        sorted_results = sorted(arch_scores.values(), key=lambda x: x["score"], reverse=True)

        return {
            "matched": len(sorted_results) > 0,
            "best_match": sorted_results[0] if sorted_results else None,
            "all_matches": sorted_results[:3]
        }

if __name__ == "__main__":
    # 接口自测
    matcher = BenignMotifMatcher()
    
    print("--- 测试 1: 单边 R2 精确检索 ---")
    res1 = matcher.match_single_edge("N.INBOUND_SERVICE.TCP", "accept", "P.WEB_SERVER.USER.HOST")
    print(json.dumps(res1, indent=2, ensure_ascii=False))

    print("\n--- 测试 2: 动态 Web 业务子图检索 ---")
    query_subgraph = [
        ("N.INBOUND_SERVICE.TCP", "accept", "P.WEB_SERVER.USER.HOST"),
        ("F.IPC_SOCKET.READ", "read", "P.WEB_SERVER.USER.HOST"),
        ("F.BIN_LIB.READ", "read", "P.WEB_SERVER.USER.HOST")
    ]
    res2 = matcher.match_subgraph(query_subgraph)
    print(json.dumps(res2, indent=2, ensure_ascii=False))

    print("\n--- 测试 3: 恶意行为检测 (安全红线校验) ---")
    # 模拟攻击场景 1: Web 进程派生交互式 bash 并写临时文件
    malicious_subgraph = [
        ("P.WEB_SERVER.USER.HOST", "clone", "P.INTERACTIVE_SHELL.USER.HOST"),
        ("P.INTERACTIVE_SHELL.USER.HOST", "write", "F.USER_DATA.WRITE")
    ]
    res3 = matcher.match_subgraph(malicious_subgraph)
    print(json.dumps(res3, indent=2, ensure_ascii=False))
