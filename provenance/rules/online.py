"""规则模式（在线）：匹配谓词与促进通道。

阶段 3 第一步：先把旧 `PatternMatcher.match` 与 `PoolContext.match_single` 的两份谓词
合并成一个 `MatchIndex`。旧类暂不删除，先做逐边对拍；对拍一致后再切换。

本文件只依赖 `domain` 与 `rules`，不导入 `routing`、`llm`、`closure`。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from domain.network import find_local_ips, get_external_ips, is_loopback_dns_resolver
from domain.pool import TopologyFacts
from domain.taxonomy import (
    LOGIN_MACHINERY_PREFIXES,
    PERSISTENCE_PREFIXES,
    PSEUDO_DEV_EXACT,
    PSEUDO_PREFIXES,
    READ_SC,
    SENSITIVE_AUTH_PATHS,
    SHARED_DAEMONS,
    SPAWN_SC,
    WRITE_SC,
)
from domain.keys import path_part, process_identity_variants

_SENSITIVE_SYSCALLS = ("read", "open", "sendfile")
_SPAWN_SYSCALLS = ("execve", "clone", "fork")
_UPWARD_BLOCK_PREFIXES = (
    "/lib", "/usr/lib", "/usr/sbin/sshd", "/usr/sbin/nginx", "/usr/lib/systemd/systemd",
)


class MatchIndex:
    """在线匹配的索引视图：复用 CandidatePool，补充角色编码与按角色分桶。"""

    def __init__(self, pool: Any, tf: Optional[TopologyFacts] = None,
                 role_cuts: Optional[Any] = None):
        from domain.pool import CandidatePool
        self.index = pool if isinstance(pool, CandidatePool) else CandidatePool(pool, tf)
        self.pool = self.index.raw
        self.tf = self.index.facts
        self.edges = self.index.edges
        self.out = self.index.out
        self.inn = self.index.inn
        self.by_syscall = self.index.by_syscall
        self.by_key = self.index.by_key
        self._parent_index = self.index.parent_index
        self._child_index = self.index.child_index
        self._sens_index = self.index.sens_index
        self._role_cache: Dict[str, str] = {}
        self.by_sys_role: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
        self.filtered_by_conf = 0
        self.high_conf_pids: Set[str] = set()

        from rules.roles import build_context, role_map
        self._ctx = build_context(self.pool)
        self._cuts = role_cuts if role_cuts is not None else self._ctx.to_cuts()
        self._roles = role_map(self._ctx, self._cuts)

        from rules.roles import profile_role as _profile_role
        for pe in self.edges:
            self._role_cache.setdefault(
                pe.s, self._roles.get(pe.s) or _profile_role(pe.s, self._ctx, self._cuts))
            self._role_cache.setdefault(
                pe.d, self._roles.get(pe.d) or _profile_role(pe.d, self._ctx, self._cuts))
        for pe in self.edges:
            self.by_sys_role[(pe.sc, self._role_cache.get(pe.s, ""))].append(pe)

    def role_of(self, node: Any) -> str:
        s = str(node)
        role = self._role_cache.get(s)
        if role is None:
            from rules.roles import profile_role
            role = self._roles.get(s) or profile_role(s, self._ctx, self._cuts)
            self._role_cache[s] = role
        return role

    @staticmethod
    def is_motif_admitted(motif: Dict[str, Any], *,
                          admitted: Optional[Set[str]] = None) -> bool:
        """基模准入：由规则库的 selected 名单决定，不含任何数值阈值。

        `admitted` 为 None 表示不筛选，用于离线覆盖表构建（等价于旧的 min_conf=0.0）。
        """
        if admitted is None:
            return True
        return str(motif.get("id") or "") in admitted

    # --- 匹配 ---
    def match(self, motifs: List[Dict[str, Any]], *,
              admitted: Optional[Set[str]] = None,
              seed_edges: Optional[Dict[Tuple, Dict[str, Any]]] = None,
              return_all: bool = False) -> Dict[Tuple, Any]:
        """执行 1 跳 / 2 跳基模、进程血缘、敏感读取闭环，返回 {边三元组: 命中来源}。

        `return_all=False`（默认）时每条边只保留最后一个命中基模，保持历史行为；
        `return_all=True` 时返回该边命中的全部基模列表，供精确检索评测使用。
        """
        self.filtered_by_conf = 0
        matched: Dict[Tuple, Any] = {}
        high: Set[str] = set()

        def record(key: Tuple, motif: Dict[str, Any]) -> None:
            if return_all:
                bucket = matched.setdefault(key, [])
                if motif not in bucket:
                    bucket.append(motif)
            else:
                matched[key] = motif

        if seed_edges:
            for rec in seed_edges.values():
                pid = str(rec.get("process_id") or "")
                if pid:
                    high |= process_identity_variants(pid)
                for _, p in rec.get("src_identities", []):
                    high |= process_identity_variants(p)
                for _, p in rec.get("dst_identities", []):
                    high |= process_identity_variants(p)

        # 1 跳
        for motif in motifs:
            if motif.get("hops") != 1:
                continue
            admitted_flag = self.is_motif_admitted(motif, admitted=admitted)
            src_role = motif.get("src_role")
            dst_role = motif.get("dst_role")
            for sc in motif.get("syscalls") or []:
                for pe in self.by_syscall.get(str(sc), ()):
                    if pe.login_skip or not pe.taint_ok:
                        continue
                    if self.role_of(pe.s) == src_role and self.role_of(pe.d) == dst_role:
                        if admitted_flag:
                            record(pe.key, motif)
                            high |= pe.all_id_vars
                        else:
                            self.filtered_by_conf += 1

        # 2 跳
        for motif in motifs:
            if motif.get("hops") != 2:
                continue
            chain = motif.get("chain") or []
            if len(chain) < 2:
                continue
            hop1, hop2 = chain[0], chain[1]
            sc1, sc2 = str(hop1.get("syscall")), str(hop2.get("syscall"))
            r1, r_mid, r3 = hop1.get("src_role"), hop1.get("dst_role"), hop2.get("dst_role")
            admitted_flag = self.is_motif_admitted(motif, admitted=admitted)
            for pe1 in self.by_sys_role.get((sc1, r1), ()):
                mid = pe1.d
                if self.role_of(mid) != r_mid:
                    continue
                t0_1 = pe1.e.get("t0") or 0
                for pe2 in self.out.get(mid, ()):
                    if pe2.sc != sc2:
                        continue
                    if self.role_of(pe2.d) != r3:
                        continue
                    t1_2 = pe2.e.get("t1") or 0
                    if t0_1 > 0 and t1_2 > 0 and t0_1 > t1_2:
                        continue
                    if admitted_flag:
                        record(pe1.key, motif)
                        record(pe2.key, motif)
                        high |= pe1.all_id_vars
                        high |= pe2.all_id_vars
                    else:
                        self.filtered_by_conf += 2

        self.high_conf_pids = high
        return matched


# ==== 兼容键函数 ====

def _key(edge: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (edge.get("src"), edge.get("syscall"), edge.get("dst"))
