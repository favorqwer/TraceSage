"""真·会话级活跃网络连接桥接与强因果实体诱导闭环器（SessionActiveBridge）：

核心法则：
1. 共享守护进程（sshd/nginx）严禁按外部 IP 盲目桥接所有端口；
   仅桥接真正派生了已确诊攻击子进程（Socket -> Daemon -> Child）、
   或被确诊外联工具直接使用的有效活跃网络会话！
2. 空转握手、扫描试探端口严禁桥接！
3. 对确诊攻击实体之间的强因果交互执行诱导子图闭环，排除守护进程自环干扰。
零大模型调用，纯图拓扑确定性因果推理。
"""
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from closure.facts import process_identity_variants

LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
    "/snap/snapd-desktop-integration",
    "/etc/profile.d",
    "/etc/default",
    "/var/run/motd",
)

SHARED_DAEMONS = frozenset({
    "sshd",
    "nginx",
    "apache2",
    "httpd",
    "systemd",
    "cron",
    "dbus-daemon",
    "rsyslogd",
    "mysqld",
    "mariadb",
    "redis-server",
    "postgres",
    "mongod",
    "slapd",
    "java",
})

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


def find_local_ips(edges: List[Dict[str, Any]]) -> Set[str]:
    """通过图上全量网络边自适应推断内网受害主机 IP 集合（支持单机与多主机拓扑，无单 IP 假设）。"""
    local_ips = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
    ip_counter = Counter()
    server_ips = set()

    for e in edges:
        sc = str(e.get("syscall") or "")
        src = str(e.get("src") or "")
        dst = str(e.get("dst") or "")

        # 服务端接收外部请求 (accept/recvfrom)：其目标端是受害主机本地 IP
        if sc in ("accept", "recvfrom") and "->" in src:
            _, _, right = src.partition("->")
            ip = right.split(":")[0] if ":" in right else right
            if ip and not ip.startswith("127.") and not ip.startswith("0.0."):
                server_ips.add(ip)

        for node in (src, dst):
            if node and "->" in str(node):
                left, _, right = str(node).partition("->")
                for part in (left, right):
                    ip = part.split(":")[0] if ":" in part else part
                    if ip and not ip.startswith("127.") and not ip.startswith("0.0."):
                        ip_counter[ip] += 1

    local_ips.update(server_ips)
    if ip_counter:
        most_common_ip, _ = ip_counter.most_common(1)[0]
        local_ips.add(most_common_ip)
    return local_ips


def get_external_ips(endpoint_str: Any, local_ips: Set[str]) -> Set[str]:
    """从网络端点字符串中提取对端外部 IP 地址（严格排除 RFC 1122 环回网络 127.0.0.0/8 与 ::1）。"""
    ext = set()
    if endpoint_str and "->" in str(endpoint_str):
        left, _, right = str(endpoint_str).partition("->")
        for part in (left, right):
            ip = part.split(":")[0] if ":" in part else part
            if ip and ip not in local_ips and not ip.startswith("127.") and ip != "::1":
                ext.add(ip)
    return ext


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


# 别名以保证向后完全兼容
CausalBridge = SessionActiveBridge
