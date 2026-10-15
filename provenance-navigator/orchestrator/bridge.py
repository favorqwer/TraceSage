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

LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
    "/snap/snapd-desktop-integration",
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
    """通过图上全量网络边统计单机的主机内网 IP（客观自适应推断，无任何硬编码）。"""
    ip_counter = Counter()
    for e in edges:
        for node in (e.get("src"), e.get("dst")):
            if node and "->" in str(node):
                left, _, right = str(node).partition("->")
                for part in (left, right):
                    ip = part.split(":")[0] if ":" in part else part
                    if ip and not ip.startswith("127.") and not ip.startswith("0.0."):
                        ip_counter[ip] += 1
    if not ip_counter:
        return {"127.0.0.1", "0.0.0.0", "localhost"}
    most_common_ip, _ = ip_counter.most_common(1)[0]
    return {most_common_ip, "127.0.0.1", "0.0.0.0", "localhost"}


def get_external_ips(endpoint_str: Any, local_ips: Set[str]) -> Set[str]:
    """从网络端点字符串中提取对端外部 IP 地址。"""
    ext = set()
    if endpoint_str and "->" in str(endpoint_str):
        left, _, right = str(endpoint_str).partition("->")
        for part in (left, right):
            ip = part.split(":")[0] if ":" in part else part
            if ip and ip not in local_ips:
                ext.add(ip)
    return ext


def is_readonly_system_mechanism(src: Any, syscall: Any, dst: Any) -> bool:
    """操作系统只读机制与系统套接字调用（防依赖爆炸）。"""
    s, d = str(src), str(dst)
    if any(s.startswith(p) or d.startswith(p) for p in LOGIN_MACHINERY_PREFIXES):
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
        conf_pids: Set[str] = set(high_conf_pids or [])

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
                conf_pids.add(str(e.get("process_id")))
            for _, p in e.get("src_identities", []):
                conf_pids.add(p)
            for _, p in e.get("dst_identities", []):
                conf_pids.add(p)

        # 2. 识别真正派生了攻击子进程的入站会话套接字
        # 逻辑：外部端点 S -> 守护进程 P (或直接作为父进程/服务) 派生攻击子进程 C
        for e in candidate_pool:
            s, sc, d = str(e.get("src")), str(e.get("syscall")), str(e.get("dst"))
            pid = str(e.get("process_id", ""))
            if sc in ("accept", "recvfrom") and "->" in s:
                if pid in conf_pids:
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
            if other in conf_nodes or str(e.get("process_id")) in conf_pids:
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
