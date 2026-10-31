"""规则模式（在线）：匹配谓词与促进通道。

阶段 3 第一步：先把旧 `PatternMatcher.match` 与 `PoolContext.match_single` 的两份谓词
合并成一个 `MatchIndex`。旧类暂不删除，先做逐边对拍；对拍一致后再切换。

本文件只依赖 `common`，不导入 `routing`、`llm`、`closure`。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from common.facts import (
    LOGIN_MACHINERY_PREFIXES,
    PERSISTENCE_PREFIXES,
    PSEUDO_DEV_EXACT,
    PSEUDO_PREFIXES,
    READ_SC,
    SENSITIVE_AUTH_PATHS,
    SHARED_DAEMONS,
    SPAWN_SC,
    WRITE_SC,
    TopologyFacts,
    evaluate_node_behavioral_role,
    find_local_ips,
    get_external_ips,
    is_loopback_dns_resolver,
)
from common.graph import path_part, process_identity_variants

_SENSITIVE_SYSCALLS = ("read", "open", "sendfile")
_SPAWN_SYSCALLS = ("execve", "clone", "fork")
_UPWARD_BLOCK_PREFIXES = (
    "/lib", "/usr/lib", "/usr/sbin/sshd", "/usr/sbin/nginx", "/usr/lib/systemd/systemd",
)


class _PreparedEdge:
    __slots__ = ("idx", "e", "key", "s", "d", "sc", "pid", "login_skip", "taint_ok",
                 "pid_vars", "parent_vars", "child_vars", "all_id_vars", "sens_vars",
                 "upward_blocked", "is_auth", "is_persist", "is_dropped")

    def get(self, key: str, default: Any = None) -> Any:
        return self.e.get(key, default)


class MatchIndex:
    """一个候选池的预计算索引：邻接、角色、进程标识变体、系统调用分桶。

    在线匹配与离线试模共用这一份谓词；`match()` 返回 {边三元组: 命中的基模或来源字典}。
    """

    def __init__(self, pool: List[Dict[str, Any]], tf: TopologyFacts,
                 role_cuts: Optional[Any] = None):
        self.pool = pool
        self.tf = tf
        self.out: Dict[str, List[_PreparedEdge]] = defaultdict(list)
        self.inn: Dict[str, List[_PreparedEdge]] = defaultdict(list)
        self._role_cache: Dict[str, str] = {}
        self.edges: List[_PreparedEdge] = []
        self.by_syscall: Dict[str, List[_PreparedEdge]] = defaultdict(list)
        self.by_sys_role: Dict[Tuple[str, str], List[_PreparedEdge]] = defaultdict(list)
        self.by_key: Dict[Tuple, List[_PreparedEdge]] = defaultdict(list)
        self._parent_index: Dict[str, Set[int]] = defaultdict(set)
        self._child_index: Dict[str, Set[int]] = defaultdict(set)
        self._sens_index: Dict[str, Set[int]] = defaultdict(set)
        self.filtered_by_conf = 0
        self.high_conf_pids: Set[str] = set()

        from common.roles import RoleCuts, build_context, role_map
        self._ctx = build_context(pool)
        self._cuts = role_cuts if role_cuts is not None else self._ctx.to_cuts()
        self._roles = role_map(self._ctx, self._cuts)

        prepared: List[_PreparedEdge] = []
        for idx, e in enumerate(pool):
            pe = _PreparedEdge()
            pe.idx = idx
            pe.e = e
            pe.s = str(e.get("src") or "")
            pe.d = str(e.get("dst") or "")
            pe.sc = str(e.get("syscall") or "")
            pe.pid = str(e.get("process_id") or "")
            pe.key = (pe.s, pe.sc, pe.d)
            pe.login_skip = any(path_part(pe.s).startswith(p) or path_part(pe.d).startswith(p)
                                for p in LOGIN_MACHINERY_PREFIXES)
            pe.taint_ok = bool(tf.is_tainted_proc(pe.pid) or tf.is_tainted_proc(pe.s)
                               or pe.pid in tf.inbound_processes or pe.s in tf.inbound_processes)
            pe.upward_blocked = any(pe.s.startswith(p) for p in _UPWARD_BLOCK_PREFIXES)

            pe.pid_vars = process_identity_variants(pe.pid)
            src_ids = {str(v) for _, v in (e.get("src_identities") or [])}
            dst_ids = {str(v) for _, v in (e.get("dst_identities") or [])}
            src_vars: Set[str] = set()
            for v in src_ids:
                src_vars |= process_identity_variants(v)
            dst_vars: Set[str] = set()
            for v in dst_ids:
                dst_vars |= process_identity_variants(v)
            pe.parent_vars = src_vars | process_identity_variants(e.get("via_key"))
            pe.child_vars = pe.pid_vars | dst_vars
            pe.all_id_vars = pe.pid_vars | src_vars | dst_vars
            pe.sens_vars = pe.pid_vars | dst_vars

            pe.is_auth = pe.is_persist = pe.is_dropped = False
            if pe.sc in _SENSITIVE_SYSCALLS:
                s_path = path_part(pe.s)
                pe.is_auth = bool(
                    s_path in SENSITIVE_AUTH_PATHS
                    or s_path.endswith("/authorized_keys")
                    or ".ssh/id_" in s_path
                    or s_path.endswith((".env", "wp-config.php", "credentials.ini", "settings.py"))
                )
                pe.is_persist = any(s_path.startswith(p) for p in PERSISTENCE_PREFIXES)
                pe.is_dropped = bool(tf.is_tainted(pe.s) and not any(
                    s_path.startswith(p) for p in ("/lib", "/usr/lib", "/proc", "/sys", "/dev")))

            prepared.append(pe)
            self.out[pe.s].append(pe)
            self.inn[pe.d].append(pe)
            self.by_syscall[pe.sc].append(pe)
            self.by_key[pe.key].append(pe)
            for v in pe.parent_vars:
                self._parent_index[v].add(idx)
            for v in pe.child_vars:
                self._child_index[v].add(idx)
            if pe.sc in _SENSITIVE_SYSCALLS:
                for v in pe.sens_vars:
                    self._sens_index[v].add(idx)
        self.edges = prepared

        from common.roles import profile_role as _profile_role
        for pe in prepared:
            self._role_cache.setdefault(
                pe.s, self._roles.get(pe.s) or _profile_role(pe.s, self._ctx, self._cuts))
            self._role_cache.setdefault(
                pe.d, self._roles.get(pe.d) or _profile_role(pe.d, self._ctx, self._cuts))
        for pe in prepared:
            self.by_sys_role[(pe.sc, self._role_cache.get(pe.s, ""))].append(pe)

    def role_of(self, node: Any) -> str:
        s = str(node)
        role = self._role_cache.get(s)
        if role is None:
            from common.roles import profile_role
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
              seed_edges: Optional[Dict[Tuple, Dict[str, Any]]] = None) -> Dict[Tuple, Dict[str, Any]]:
        """执行 1 跳 / 2 跳基模、进程血缘、敏感读取闭环，返回 {边三元组: 命中来源}。"""
        self.filtered_by_conf = 0
        matched: Dict[Tuple, Dict[str, Any]] = {}
        high: Set[str] = set()

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
                            matched[pe.key] = motif
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
                        matched[pe1.key] = motif
                        matched[pe2.key] = motif
                        high |= pe1.all_id_vars
                        high |= pe2.all_id_vars
                    else:
                        self.filtered_by_conf += 2

        # 进程血缘
        for _ in range(6):
            added: Set[str] = set()
            cand: Set[int] = set()
            for pid in high:
                cand |= self._parent_index.get(pid, set())
                cand |= self._child_index.get(pid, set())
            for idx in sorted(cand):
                pe = self.edges[idx]
                if pe.key in matched or pe.login_skip:
                    continue
                is_downward = bool(pe.parent_vars & high)
                is_upward = (bool(pe.child_vars & high) and pe.sc in _SPAWN_SYSCALLS
                             and not pe.upward_blocked)
                if (is_downward or is_upward) and pe.sc in _SPAWN_SYSCALLS:
                    matched[pe.key] = {
                        "id": "PROCESS_LINEAGE_SPAWN",
                        "name": "失陷会话命令派生血缘拉直",
                    }
                    added |= pe.child_vars
                    added |= pe.parent_vars
            if not added:
                break
            high |= added

        # 敏感读取闭环
        cand = set()
        for pid in high:
            cand |= self._sens_index.get(pid, set())
        for idx in sorted(cand):
            pe = self.edges[idx]
            if pe.key in matched:
                continue
            if pe.is_auth or pe.is_persist or pe.is_dropped:
                matched[pe.key] = {
                    "id": "SENSITIVE_OR_PAYLOAD_READ",
                    "name": "失陷进程敏感客体或载荷读取闭环",
                }

        self.high_conf_pids = high
        return matched


# ==== 兼容层：旧 matcher 的类名与函数名 ====

def _key(edge: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (edge.get("src"), edge.get("syscall"), edge.get("dst"))


class PatternMatcher:
    """旧在线匹配器的兼容入口：内部走 MatchIndex。"""

    def __init__(self, topology_facts: TopologyFacts,
                 patterns: Optional[List[Dict[str, Any]]] = None,
                 admitted: Optional[Set[str]] = None,
                 role_cuts: Optional[Any] = None):
        self.tf = topology_facts
        self.patterns = patterns or []
        self.admitted = set(admitted) if admitted is not None else None
        self.role_cuts = role_cuts
        self.high_conf_pids: Set[str] = set()
        self.filtered_by_conf = 0

    def match(self, candidate_pool: List[Dict[str, Any]],
              confirmed_seeds: Optional[Dict[Tuple, Dict[str, Any]]] = None
              ) -> Dict[Tuple, Dict[str, Any]]:
        index = MatchIndex(candidate_pool, self.tf, role_cuts=self.role_cuts)
        matched = index.match(
            self.patterns,
            admitted=self.admitted,
            seed_edges=confirmed_seeds,
        )
        self.filtered_by_conf = index.filtered_by_conf
        self.high_conf_pids = index.high_conf_pids
        return matched


class PoolContext:
    """旧训练期池上下文的兼容入口：预计算一次，按单个基模求值。"""

    def __init__(self, pool: List[Dict[str, Any]], tf: TopologyFacts,
                 role_cuts: Optional[Any] = None):
        self.pool = pool
        self.tf = tf
        self.index = MatchIndex(pool, tf)

    def match_single(self, motif: Dict[str, Any]) -> Dict[Tuple, Dict[str, Any]]:
        return self.index.match([motif], admitted=None)


def match_single_legacy(pool: List[Dict[str, Any]], tf: TopologyFacts,
                        motif: Dict[str, Any]) -> Dict[Tuple, Dict[str, Any]]:
    return PatternMatcher(tf, [motif], admitted=None).match(pool)


def same_matched(a: Dict[Tuple, Dict[str, Any]], b: Dict[Tuple, Dict[str, Any]]) -> bool:
    if set(a) != set(b):
        return False
    for key in a:
        if str((a[key] or {}).get("id")) != str((b[key] or {}).get("id")):
            return False
    return True


# ==== 会话级网络桥接 ====

READONLY_MECHANISM_PREFIXES = (
    "/lib",
    "/usr/lib",
    "/usr/share",
    "/proc",
    "/sys",
    "/dev",
)


def _key(e: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (e.get("src"), e.get("syscall"), e.get("dst"))



def is_readonly_system_mechanism(src: Any, syscall: Any, dst: Any) -> bool:
    """操作系统只读机制与系统套接字调用（防依赖爆炸）。"""
    s, d = str(src), str(dst)
    if any(s.startswith(p) or d.startswith(p) for p in LOGIN_MACHINERY_PREFIXES):
        return True
    # 排除系统内部本地 DNS 解析器 (如 127.0.0.53:53) 的伪连接
    if (":53" in s and "127." in s) or (":53" in d and "127." in d):
        return True
    if str(syscall) in ("read", "recvfrom"):
        if any(s.startswith(p) or d.startswith(p) for p in READONLY_MECHANISM_PREFIXES):
            return True
        if s.startswith("unix:[/run/systemd/") or d.startswith("unix:[/run/systemd/"):
            return True
    return False


class SessionActiveBridge:
    """真·会话级活跃网络连接桥接器。"""

    def __init__(self, local_ips: Optional[Set[str]] = None):
        self.local_ips = local_ips

    def bridge(
        self,
        candidate_pool: List[Dict[str, Any]],
        confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
        high_conf_pids: Optional[Set[str]] = None,
    ) -> Dict[Tuple[Any, Any, Any], Dict[str, Any]]:
        if not candidate_pool or not confirmed_map:
            return {}

        local_ips = self.local_ips or find_local_ips(candidate_pool)
        newly_bridged: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}

        # 1. 收集确诊的外部攻击源 IP 与明确产生攻击派生的活跃 Socket 端点
        active_session_sockets: Set[str] = set()
        conf_ext_ips: Set[str] = set()
        conf_nodes: Set[str] = set()
        conf_pids: Set[str] = set()
        for p in (high_conf_pids or []):
            conf_pids.update(process_identity_variants(p))

        for k, e in confirmed_map.items():
            s, sc, d = str(e.get("src")), str(e.get("syscall")), str(e.get("dst"))
            if not is_readonly_system_mechanism(s, sc, d):
                conf_nodes.add(s)
                conf_nodes.add(d)
            for node in (s, d):
                if "->" in node:
                    active_session_sockets.add(node)
                for ext_ip in get_external_ips(node, local_ips):
                    conf_ext_ips.add(ext_ip)
            if e.get("process_id"):
                conf_pids.update(process_identity_variants(str(e.get("process_id"))))
            for _, p in e.get("src_identities", []):
                conf_pids.update(process_identity_variants(p))
            for _, p in e.get("dst_identities", []):
                conf_pids.update(process_identity_variants(p))

        # 2. 识别真正派生了攻击子进程的入站会话套接字
        # 逻辑：外部端点 S -> 守护进程 P (或直接作为父进程/服务) 派生攻击子进程 C
        for e in candidate_pool:
            s, sc, d = str(e.get("src")), str(e.get("syscall")), str(e.get("dst"))
            pid = str(e.get("process_id", ""))
            pid_vars = process_identity_variants(pid)
            if sc in ("accept", "recvfrom") and "->" in s:
                if pid_vars.intersection(conf_pids):
                    active_session_sockets.add(s)

        # 3. 严格受限的会话网络桥接
        for e in candidate_pool:
            k = _key(e)
            if k in confirmed_map or k in newly_bridged:
                continue
            s, sc, d = str(e.get("src")), str(e.get("syscall")), str(e.get("dst"))
            if is_readonly_system_mechanism(s, sc, d):
                continue

            edge_ext_ips = get_external_ips(s, local_ips) | get_external_ips(d, local_ips)
            hit_ips = edge_ext_ips & conf_ext_ips
            if not hit_ips:
                continue

            endpoint = s if "->" in s else d
            other = d if "->" in s else s
            other_name = other.split("/")[-1]

            # 核心约束：
            # 如果对端是共享多租户守护进程（sshd/nginx），必须在 active_session_sockets 明确激活！
            # 绝不桥接未产生命令执行的闲置/扫描端点！
            if other_name in SHARED_DAEMONS:
                if endpoint not in active_session_sockets:
                    continue

            # 如果对端是确诊的攻击节点或确诊外联工具，予以闭环
            pid_vars = process_identity_variants(str(e.get("process_id", "")))
            for _, p in e.get("src_identities", []):
                pid_vars.update(process_identity_variants(p))
            for _, p in e.get("dst_identities", []):
                pid_vars.update(process_identity_variants(p))

            if other in conf_nodes or pid_vars.intersection(conf_pids):
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["motif"] = "REFINED_ACTIVE_BRIDGE"
                rec["motif_name"] = "活跃会话精细化网络桥接"
                rec["reason"] = "快速通道：活跃攻击会话网络连接精细化闭环"
                newly_bridged[k] = rec
                conf_nodes.add(s)
                conf_nodes.add(d)

        # 4. 强因果双端实体诱导子图闭环（严格过滤守护进程自环）
        for e in candidate_pool:
            k = _key(e)
            if k in confirmed_map or k in newly_bridged:
                continue
            s, sc, d = str(e.get("src")), str(e.get("syscall")), str(e.get("dst"))
            if is_readonly_system_mechanism(s, sc, d):
                continue
            if s == d and s.split("/")[-1] in SHARED_DAEMONS:
                continue

            if s in conf_nodes and d in conf_nodes:
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["motif"] = "STRICT_INDUCED_CLOSURE"
                rec["motif_name"] = "双端确诊实体因果闭环"
                rec["reason"] = "快速通道：双端确诊实体因果交互闭环"
                newly_bridged[k] = rec

        return newly_bridged




# ==== 边界穿越故事通道 ====

HIGH_PRECISION_MOTIFS = frozenset({'REFINED_ACTIVE_BRIDGE'})


def _pid(edge):
    return str(edge.get('process_id') or '')


def _is_socket(node):
    return '->' in str(node)


def _socket_ips(node):
    """从连接对象字符串 'a:1->b:2' 里取出两端的 IP。"""
    s = str(node)
    out = set()
    if '->' not in s:
        return out
    for part in s.split('->'):
        ip = part.split(':')[0] if ':' in part else part
        if ip and not ip.startswith(('unix:', 'pipe:', 'socket:')):
            out.add(ip)
    return out


def _program(node):
    """可执行程序名（跨程序判据用）。"""
    s = str(node)
    return s.split('/')[-1] if '/' in s else s


def _is_pseudo_object(obj):
    """内核按需生成、不承载内容的伪对象？"""
    o = str(obj)
    if o.startswith(PSEUDO_PREFIXES):
        return True
    if o.startswith('/dev/'):
        return (o in PSEUDO_DEV_EXACT) or o.startswith('/dev/pts/') or o.startswith('/dev/fd/')
    return False


def _key(edge):
    return (edge.get('src'), edge.get('syscall'), edge.get('dst'))


class BoundaryStoryOperator:
    """边界穿越故事通道（见模块 docstring）。默认参数即离线验证过的配置。"""

    def __init__(self, fresh_only=True, chain_rounds=2):
        self.fresh_only = fresh_only          # 指纹来源限定为「涉及窗口内新造对象的确认边」
        self.chain_rounds = chain_rounds

    # ── 索引 ─────────────────────────────────────────────────────────────────────
    @staticmethod
    def _index(pool):
        idx = {'writers_pid': defaultdict(set), 'writers_prog': defaultdict(set),
               'fresh': set(), 'local_ip_counts': defaultdict(int)}
        for e in pool:
            sc = e.get('syscall')
            if sc in WRITE_SC:
                dst = str(e.get('dst'))
                if not _is_pseudo_object(dst):
                    idx['fresh'].add(dst)
                if dst.startswith('pipe:'):
                    idx['writers_pid'][dst].add(_pid(e))
                    idx['writers_prog'][dst].add(_program(e.get('src')))
                if sc in ('rename', 'symlink'):
                    src = str(e.get('src'))
                    if not _is_pseudo_object(src):
                        idx['fresh'].add(src)
            for node in (e.get('src'), e.get('dst')):
                for ip in _socket_ips(node):
                    if not ip.startswith(('127.', '0.0.')):
                        idx['local_ip_counts'][ip] += 1
        idx['local_ip'] = (max(idx['local_ip_counts'].items(), key=lambda kv: kv[1])[0]
                           if idx['local_ip_counts'] else None)
        return idx

    @staticmethod
    def _boundary_sockets(pool):
        """对端在观测窗口之外的连接对象：connect/accept 只出现其一。"""
        has_accept, has_connect = set(), set()
        for e in pool:
            if e.get('syscall') == 'accept' and _is_socket(e.get('src')):
                has_accept.add(str(e.get('src')))
            if e.get('syscall') == 'connect' and _is_socket(e.get('dst')):
                has_connect.add(str(e.get('dst')))
        return (has_accept - has_connect) | (has_connect - has_accept)

    @staticmethod
    def _reach_to(pool, target):
        """在 src->dst 有向图上，求能到达 target 的节点集合（锚点祖先链）。"""
        frontier = {target}
        for _ in range(60):
            added = set()
            for e in pool:
                if e.get('dst') in frontier and e.get('src') not in frontier:
                    added.add(str(e.get('src')))
            if not added:
                break
            frontier |= added
        return frontier

    # ── 主流程 ───────────────────────────────────────────────────────────────────
    def promote(self, pool, confirmed_map):
        """返回 { (src, syscall, dst): 提升边记录 }；不修改入参。"""
        if not pool:
            return {}
        promoted = {}
        idx = self._index(pool)
        local_ip = idx['local_ip']
        boundary = self._boundary_sockets(pool)

        anchors = [e for e in confirmed_map.values() if e.get('class') == 'anchor']
        anchor_t1 = int((anchors[0].get('t1') or 0)) if anchors else 0
        anc_node = str(anchors[0].get('src')) if anchors else None
        ancestry = self._reach_to(pool, anc_node) if anc_node else set()

        def learn_fingerprints(source_keys):
            ips = set()
            for e in pool:
                k = _key(e)
                if k not in source_keys:
                    continue
                dst = str(e.get('dst'))
                if self.fresh_only and e.get('class') != 'anchor':
                    touches_fresh = ((e.get('syscall') in WRITE_SC and dst in idx['fresh'])
                                     or (e.get('syscall') in READ_SC and str(e.get('src')) in idx['fresh']))
                    if not touches_fresh:
                        continue
                for node in (e.get('src'), e.get('dst')):
                    for ip in _socket_ips(node):
                        if ip != local_ip and not ip.startswith(('127.', '0.0.')):
                            ips.add(ip)
            return ips

        def is_fingerprint_source(e):
            if e.get('class') == 'anchor':
                return True
            motif = str(e.get('motif') or '')
            return motif.startswith('MINED') or motif in HIGH_PRECISION_MOTIFS

        source_keys = {_key(e) for e in confirmed_map.values() if is_fingerprint_source(e)}

        for _round in range(1):
            fp_ips = learn_fingerprints(source_keys)
            # ③ 攻击主体：与带指纹对端的连接打过交道的进程
            actors = set()
            for e in pool:
                src, dst = e.get('src'), e.get('dst')
                if ((_is_socket(src) and (_socket_ips(src) & fp_ips))
                        or (_is_socket(dst) and (_socket_ips(dst) & fp_ips))):
                    p = _pid(e)
                    if p:
                        actors.add(p)
            # 攻击产物 + 链条继续
            for _ in range(self.chain_rounds):
                products = {str(e['dst']) for e in pool
                            if e.get('syscall') in WRITE_SC and _pid(e) in actors
                            and not _is_pseudo_object(e['dst'])}
                if not products:
                    break
                new_actors = set()
                for e in pool:
                    p = _pid(e)
                    if not p or p in actors:
                        continue
                    if e.get('syscall') in READ_SC and str(e.get('src')) in products:
                        new_actors.add(p)
                    elif e.get('syscall') in SPAWN_SC:
                        if any(p.startswith(x) or x.startswith(p) for x in actors) or str(e.get('dst')) in products:
                            new_actors.add(p)
                if not new_actors:
                    break
                actors |= new_actors
            products = {str(e['dst']) for e in pool
                        if e.get('syscall') in WRITE_SC and _pid(e) in actors
                        and not _is_pseudo_object(e['dst'])}

            # ④ 严格成因判定
            for e in pool:
                k = _key(e)
                if k in confirmed_map or k in promoted:
                    continue
                sc = e.get('syscall')
                src, dst = str(e.get('src')), str(e.get('dst'))
                if anchor_t1:
                    t0 = int(e.get('t0') or 0)
                    if t0 and t0 > anchor_t1:
                        continue
                reason = None
                # (a) 走在带指纹对端的连接上
                if _is_socket(src) and (_socket_ips(src) & fp_ips):
                    local_side = dst
                    if local_side in ancestry:
                        reason = 'BOUNDARY_FP_SOCKET'
                elif _is_socket(dst) and (_socket_ips(dst) & fp_ips):
                    local_side = src
                    if local_side in ancestry:
                        reason = 'BOUNDARY_FP_SOCKET'
                # (b) 攻击产物被写出 / 被执行
                elif sc in WRITE_SC and dst in products:
                    reason = 'BOUNDARY_PRODUCT_WRITE'
                elif sc in SPAWN_SC and dst in products:
                    reason = 'BOUNDARY_PRODUCT_EXEC'
                elif sc in READ_SC:
                    if src in products:
                        reason = 'BOUNDARY_PRODUCT_READ'
                    elif src.startswith('pipe:'):
                        # (c) 跨程序（不是跨进程号）的管道交接
                        writers_pid = idx['writers_pid'].get(src, set())
                        writers_prog = idx['writers_prog'].get(src, set())
                        if (writers_pid & actors) and _pid(e) and _pid(e) not in writers_pid:
                            if any(wp != _program(dst) for wp in writers_prog):
                                reason = 'BOUNDARY_HANDOFF_PIPE'
                    elif _pid(e) in actors and src in idx['fresh']:
                        reason = 'BOUNDARY_ACTOR_READ_FRESH'
                if not reason:
                    continue
                rec = dict(e)
                rec['origin'] = 'confirmed'
                rec['class'] = 'story'
                rec['motif'] = reason
                rec['motif_name'] = '边界穿越故事通道'
                rec['reason'] = f"边界穿越故事通道：{reason}（对手指纹 {sorted(fp_ips)}）"
                promoted[k] = rec


        return promoted


# 兼容旧类名
CausalBridge = SessionActiveBridge
