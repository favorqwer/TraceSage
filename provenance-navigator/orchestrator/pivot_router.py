"""因果拓扑枢纽路由器与信息流死端剪枝器 (CausalPivotRouter / CPR-v2)

职责：
1. 载荷跨程序管道交接保护 (Payload Handoff Pipe Protection):
   当管道写入端主体具备外部网络出入站行为 (或为网络传输工具)，且读出端为命令执行主体时，
   判定为合法的“无文件载荷执行管道”，绝对保护！
2. 交互式会话终端回显与交互式派生命令保护 (Interactive Session Protection):
   当进程是由已失陷的交互式会话解释器 (Shell/终端) 直接派生时，无论是敏感配置读取还是子命令派生
   (如 head/cut/tar/id 等侦察或打包动作)，物理上均受攻击者交互式控制，绝对保护！
3. 死端敏感认证/配置读取剪枝 (Dead-End Read Pruning):
   非交互式会话派生的后台静默进程读取敏感配置，若前向无任何状态突变或网络外发，判定为无害死端读取。
4. 本地 DNS 解析器伪连接排除 (Local Stub DNS Resolver Filter):
   排除系统内部 127.0.0.0/8:53 (如 systemd-resolved 127.0.0.53:53) 本地名字解析伪桥接。
5. 冗余自派生空转边清理 (Self-Spawn Pruning):
   清理 src == dst 且无实际环境/程序变更的空转执行边。
6. 安全底线：所有被剪枝的死端边均标记为 origin='kept' 转移至未排除 (unexcluded) 池，绝不静默丢弃。
"""
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

PKG_MANAGERS = frozenset({
    "dpkg", "dpkg-deb", "dpkg-split", "dpkg-preconfigure", "mandb", "ldconfig", "ldconfig.real"
})

PKG_INTERNAL_SINKS = (
    ".dpkg-new", ".dpkg-tmp", ".triggers",
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/",
    "/var/cache/man/", "/var/cache/apt/", "/var/lib/apt/lists/"
)

PSEUDO_PREFIXES = ('/sys/', '/proc/', 'pipe:', 'memfd:', 'tmpfile:', 'socket:', 'unix:', 'anon:', '/dev/')
SYSTEM_LIB_PREFIXES = ('/lib', '/usr/lib', '/usr/share')

AUTH_OR_CONFIG = frozenset({
    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers',
    '/etc/subuid', '/etc/subgid', '/etc/nshadow', '/etc/shadow+', '/etc/passwd+'
})

PERSISTENCE_PREFIXES = (
    '/etc/systemd/system',
    '/lib/systemd/system',
    '/etc/init.d',
    '/etc/cron',
    '/var/spool/cron',
    '/etc/rc.local',
)


def _key(e: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (e.get("src"), e.get("syscall"), e.get("dst"))


def is_loopback_dns_resolver(node: str) -> bool:
    """严格判定是否为系统内部本地存根 DNS 解析器 (如 127.0.0.53:53 或 127.0.0.1:53)。"""
    s = str(node)
    if "->" not in s:
        return False
    for part in s.split("->"):
        if part.startswith("127.") and part.endswith(":53"):
            return True
    return False


class CausalPivotRouter:
    """因果枢纽路由器：消除死端汇流、无害管道及包管理伴生碎片 (CPR-v2)。"""

    def __init__(self, poi_anchors: Optional[List[Tuple[Any, Any, Any]]] = None):
        self.poi_dirs: Set[str] = set()
        self.anchor_keys: Set[Tuple[Any, Any, Any]] = set()
        if poi_anchors:
            for item in poi_anchors:
                s, sc, d = item[0], item[1], item[2]
                self.anchor_keys.add((s, sc, d))
                for node in (str(s), str(d)):
                    if "/" in node and not node.startswith("unix:"):
                        self.poi_dirs.add("/".join(node.split("/")[:-1]))

    def is_operational_debris(self, edge: Dict[str, Any]) -> bool:
        """判定一条边是否属于包管理器内部的死端伴生碎片。"""
        s = str(edge.get("src", ""))
        d = str(edge.get("dst", ""))
        sc = str(edge.get("syscall", ""))
        prog_s = s.split("/")[-1]

        # 1. 保护具有命令执行或后门安装属性的实体（如场景 4 中的 postinst）
        if "postinst" in s or "postinst" in d or sc == "execve":
            return False

        # 2. 保护与调查起点（POI）同目录的受害客体（如场景 1 勒索受害文件）
        if any(d.startswith(p_dir) for p_dir in self.poi_dirs if len(p_dir) > 4):
            return False

        # 3. 识别包管理内部辅助进程向系统缓存/文档/临时包文件的读写
        if prog_s in PKG_MANAGERS:
            if any(sink in d for sink in PKG_INTERNAL_SINKS) or d.startswith("pipe:"):
                return True
            if any(sink in d for sink in (".dpkg-new", ".dpkg-tmp", "/usr/share/doc/", "/var/cache/man/")):
                return True

        # 4. 识别 apt-get 自身的包列表索引与缓存读写
        if prog_s == "apt-get" and sc in ("read", "write"):
            if any(d.startswith(p) for p in ("/var/lib/apt/", "/var/cache/apt/", "pipe:")):
                return True

        return False

    def route_confirmed(
        self,
        confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
        candidate_pool: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
        """对已确认边进行物理因果信息流守恒与死端剪枝过滤。

        返回:
            (filtered_confirmed_map, pruned_debris_edges)
        """
        filtered_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        pruned_debris: List[Dict[str, Any]] = []

        if not candidate_pool:
            # 兼容无全量候选池输入时的轻量级过滤
            for key, edge in confirmed_map.items():
                if edge.get("class") == "anchor" or key in self.anchor_keys:
                    filtered_confirmed[key] = edge
                    continue
                if self.is_operational_debris(edge):
                    e_pruned = dict(edge)
                    e_pruned["origin"] = "kept"
                    e_pruned["reason"] = "因果路由器：包管理内部死端伴生碎片，归入未排除"
                    pruned_debris.append(e_pruned)
                else:
                    filtered_confirmed[key] = edge
            return filtered_confirmed, pruned_debris

        # 1. 基于全量候选池建立行为拓扑画像
        proc_has_net_inbound: Set[str] = set()
        proc_has_net_outbound: Set[str] = set()
        proc_has_high_impact_mutation: Set[str] = set()
        parent_of: Dict[str, Set[str]] = defaultdict(set)
        children_of: Dict[str, Set[str]] = defaultdict(set)
        pipe_io: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {"writers": set(), "readers": set()})

        for e in candidate_pool:
            sc = str(e.get("syscall") or "")
            pid = str(e.get("process_id") or "")
            s, d = str(e.get("src") or ""), str(e.get("dst") or "")

            if sc == "write" and d.startswith("pipe:"):
                if pid: pipe_io[d]["writers"].add(pid)
                if s: pipe_io[d]["writers"].add(s)
            if sc in ("read", "open") and s.startswith("pipe:"):
                if pid: pipe_io[s]["readers"].add(pid)
                if d: pipe_io[s]["readers"].add(d)

            if sc in ("connect", "sendto", "write") and "->" in d:
                if not is_loopback_dns_resolver(d):
                    if pid: proc_has_net_outbound.add(pid)
                    if s: proc_has_net_outbound.add(s)
            if sc in ("accept", "recvfrom", "read") and "->" in s:
                if not is_loopback_dns_resolver(s):
                    if pid: proc_has_net_inbound.add(pid)
                    if d: proc_has_net_inbound.add(d)

            if sc in ("write", "create", "rename", "chmod", "chown", "symlink"):
                is_pseudo = any(d.startswith(p) for p in PSEUDO_PREFIXES) or d.startswith("/dev/")
                is_persist = any(d.startswith(p) for p in PERSISTENCE_PREFIXES)
                is_auth = (d in AUTH_OR_CONFIG or "authorized_keys" in d)
                if not is_pseudo or is_persist or is_auth:
                    if pid: proc_has_high_impact_mutation.add(pid)
                    if s: proc_has_high_impact_mutation.add(s)

            if sc in ("execve", "clone", "fork"):
                for _, p in e.get("src_identities", []):
                    if pid: parent_of[pid].add(p)
                    if d: parent_of[d].add(p)
                    if pid: children_of[p].add(pid)
                    if d: children_of[p].add(d)
                if s and d and s != d:
                    parent_of[d].add(s)
                    children_of[s].add(d)

        # 2. 识别受污染的交互式会话解释器 (Shell/终端)
        interactive_session_procs: Set[str] = set()
        for e in confirmed_map.values():
            s = str(e.get("src") or "")
            d = str(e.get("dst") or "")
            pid = str(e.get("process_id") or "")
            if any(term in s for term in ("bash", "sh", "sshd")):
                interactive_session_procs.add(s)
                if pid: interactive_session_procs.add(pid)
            if any(term in d for term in ("bash", "sh")):
                interactive_session_procs.add(d)
                if pid: interactive_session_procs.add(pid)

        # 3. 递归标记具备前向交付能力的主体
        proc_has_any_delivery = set(proc_has_net_outbound | proc_has_high_impact_mutation)
        for _ in range(3):
            for p, ch_set in list(children_of.items()):
                if any(c in proc_has_any_delivery for c in ch_set):
                    proc_has_any_delivery.add(p)

        # 4. 执行因果流物理守恒剪枝
        for key, edge in confirmed_map.items():
            if edge.get("class") == "anchor" or key in self.anchor_keys:
                filtered_confirmed[key] = edge
                continue

            s = str(edge.get("src") or "")
            sc = str(edge.get("syscall") or "")
            d = str(edge.get("dst") or "")
            pid = str(edge.get("process_id") or "")
            motif = edge.get("motif", "")

            # 判据 A: 系统内部存根 DNS 解析器过滤 (127.0.0.53:53)
            if is_loopback_dns_resolver(s) or is_loopback_dns_resolver(d):
                e_dem = dict(edge)
                e_dem["origin"] = "kept"
                e_dem["reason"] = "因果路由器：排除系统内部本地DNS存根解析伪桥接"
                pruned_debris.append(e_dem)
                continue

            # 判据 B: 管道两端语义判定（保护 curl | bash 无文件管道，降噪内部辅助管道）
            if s.startswith("pipe:") or d.startswith("pipe:"):
                p_id = s if s.startswith("pipe:") else d
                pipe_info = pipe_io.get(p_id, {"writers": set(), "readers": set()})
                has_net_writer = any(w in proc_has_net_outbound or w in proc_has_net_inbound or "curl" in w or "wget" in w for w in pipe_info["writers"])
                has_exec_reader = any("bash" in r or "sh" in r or "python" in r for r in pipe_info["readers"])
                if has_net_writer and (has_exec_reader or sc == "write"):
                    # 保护合法的攻击载荷无文件交接
                    filtered_confirmed[key] = edge
                    continue

                if motif in ("STRICT_INDUCED_CLOSURE", "REFINED_ACTIVE_BRIDGE"):
                    e_dem = dict(edge)
                    e_dem["origin"] = "kept"
                    e_dem["reason"] = "因果路由器：辅助工具内部无害管道降噪"
                    pruned_debris.append(e_dem)
                    continue

            # 判据 C: 敏感认证/配置死端读取判定与交互式终端回显保护
            if sc in ("read", "open", "sendfile") and s in AUTH_OR_CONFIG:
                reader_has_delivery = (pid in proc_has_any_delivery or d in proc_has_any_delivery)
                is_sshd_auth = ("authorized_keys" in s and "sshd" in d)
                parents = parent_of.get(pid, set()) | parent_of.get(d, set())
                is_interactive_recon = any(p in interactive_session_procs for p in parents) or (pid in interactive_session_procs or d in interactive_session_procs)

                if not reader_has_delivery and not is_sshd_auth and not is_interactive_recon:
                    e_dem = dict(edge)
                    e_dem["origin"] = "kept"
                    e_dem["reason"] = "因果路由器：死端认证读取 (无信息流交付且非会话侦察)"
                    pruned_debris.append(e_dem)
                    continue

            # 判据 D: 冗余自派生空转边清理 (P -> P)
            if sc == "execve" and s == d and motif == "PROCESS_LINEAGE_SPAWN":
                e_dem = dict(edge)
                e_dem["origin"] = "kept"
                e_dem["reason"] = "因果路由器：冗余自派生空转边"
                pruned_debris.append(e_dem)
                continue

            # 判据 E: 包管理器底层临时文件与缓存死端伴生碎片
            if self.is_operational_debris(edge):
                e_dem = dict(edge)
                e_dem["origin"] = "kept"
                e_dem["reason"] = "因果路由器：包管理内部死端伴生碎片，归入未排除"
                pruned_debris.append(e_dem)
                continue

            filtered_confirmed[key] = edge

        return filtered_confirmed, pruned_debris
