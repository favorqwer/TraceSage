"""路由促进通道：活跃会话网络桥接与边界穿越故事。"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from domain.keys import path_part, process_identity_variants
from domain.network import find_local_ips, get_external_ips, is_loopback_dns_resolver
from domain.taxonomy import (
    LOGIN_MACHINERY_PREFIXES,
    PSEUDO_DEV_EXACT,
    PSEUDO_PREFIXES,
    READ_SC,
    SHARED_DAEMONS,
    SPAWN_SC,
    WRITE_SC,
)

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

        if hasattr(candidate_pool, "raw"):
            local_ips = self.local_ips or candidate_pool.local_ips
            candidate_pool = candidate_pool.raw
        else:
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
        if hasattr(pool, "raw"):
            idx = pool.story_index()
            pool = pool.raw
        else:
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



# ==== 符号促进：进程血缘与敏感读取 ====

def promote_lineage(index: Any, matched: Dict[Tuple, Dict[str, Any]],
                    high: Set[str]) -> Set[str]:
    """从已命中边出发扩展派生血缘，最多 6 轮。"""
    for _ in range(6):
        added: Set[str] = set()
        cand: Set[int] = set()
        for pid in high:
            cand |= index._parent_index.get(pid, set())
            cand |= index._child_index.get(pid, set())
        for idx in sorted(cand):
            pe = index.edges[idx]
            if pe.key in matched or pe.login_skip:
                continue
            is_downward = bool(pe.parent_vars & high)
            is_upward = (bool(pe.child_vars & high) and pe.sc in SPAWN_SC
                         and not pe.upward_blocked)
            if (is_downward or is_upward) and pe.sc in SPAWN_SC:
                matched[pe.key] = {
                    "id": "PROCESS_LINEAGE_SPAWN",
                    "name": "失陷会话命令派生血缘拉直",
                }
                added |= pe.child_vars
                added |= pe.parent_vars
        if not added:
            break
        high |= added
    return high


def promote_sensitive(index: Any, matched: Dict[Tuple, Dict[str, Any]],
                      high: Set[str]) -> Set[str]:
    """已确认进程读取认证、持久化或落地载荷对象时提升该边。"""
    cand: Set[int] = set()
    for pid in high:
        cand |= index._sens_index.get(pid, set())
    for idx in sorted(cand):
        pe = index.edges[idx]
        if pe.key in matched:
            continue
        if pe.is_auth or pe.is_persist or pe.is_dropped:
            matched[pe.key] = {
                "id": "SENSITIVE_OR_PAYLOAD_READ",
                "name": "失陷进程敏感客体或载荷读取闭环",
            }
    return high
