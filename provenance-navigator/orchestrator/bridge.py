"""神经符号因果网络会话桥接与强因果实体诱导子图闭环器（CausalBridge）：

核心能力：
1. 动态自适应识别受害主机本地 IP 与已知外部攻击者 IP；
2. 基于确诊攻击进程识别入站攻击源；
3. 将外部已知攻击源与主机确诊实体之间的交互边确定性闭环桥接；
4. 对确诊攻击实体之间的强因果交互执行诱导子图闭环。
零大模型调用，纯图拓扑确定性因果推理。
"""
from collections import Counter
from typing import Any, Dict, List, Set, Tuple


LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
)

SYSTEM_DAEMON_NAMES = {
    "systemd",
    "cron",
    "dbus-daemon",
    "rsyslogd",
}

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


def is_login_machinery(node_str: Any) -> bool:
    """系统登录提示信息子树（操作系统自带基础设施，无攻击判别力）。"""
    return str(node_str).startswith(LOGIN_MACHINERY_PREFIXES)


def is_readonly_system_mechanism(src: Any, syscall: Any, dst: Any) -> bool:
    """操作系统只读机制与系统套接字调用（防依赖爆炸）。"""
    if is_login_machinery(src) or is_login_machinery(dst):
        return True
    if str(syscall) in ("read", "recvfrom"):
        if str(src).startswith(READONLY_MECHANISM_PREFIXES) or str(dst).startswith(READONLY_MECHANISM_PREFIXES):
            return True
        if str(src).startswith("unix:[/run/systemd/") or str(dst).startswith("unix:[/run/systemd/"):
            return True
    return False


class CausalBridge:
    """
    神经符号因果网络会话桥接与强因果实体诱导子图闭环器。
    """

    def __init__(self, local_ips: Set[str] = None):
        self.local_ips = local_ips

    def bridge(
        self,
        candidate_pool: List[Dict[str, Any]],
        confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    ) -> Dict[Tuple[Any, Any, Any], Dict[str, Any]]:
        if not candidate_pool or not confirmed_map:
            return {}

        local_ips = self.local_ips or find_local_ips(candidate_pool)
        newly_confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}

        # 1. 提取初始确诊实体与已确诊的外部攻击 IP
        conf_nodes: Set[str] = set()
        conf_ext_ips: Set[str] = set()

        for k, e in confirmed_map.items():
            s, sc, d = e.get("src"), e.get("syscall"), e.get("dst")
            if not is_readonly_system_mechanism(s, sc, d):
                conf_nodes.add(str(s))
                conf_nodes.add(str(d))
            for node in (s, d):
                for ext_ip in get_external_ips(node, local_ips):
                    conf_ext_ips.add(ext_ip)

        # 2. 识别攻击者入站网络来源：若确诊攻击进程（非基础系统守护进程）直接接收了外部入站网络连接，则该外部来源确认为攻击源 IP
        for e in candidate_pool:
            s, sc, d = e.get("src"), e.get("syscall"), e.get("dst")
            if sc in ("accept", "recvfrom") and str(d) in conf_nodes:
                d_name = str(d).split("/")[-1]
                if d_name not in SYSTEM_DAEMON_NAMES:
                    for ext_ip in get_external_ips(s, local_ips):
                        conf_ext_ips.add(ext_ip)

        # 3. 外部已知攻击源网络会话桥接
        for e in candidate_pool:
            k = _key(e)
            if k in confirmed_map or k in newly_confirmed:
                continue
            s, sc, d = e.get("src"), e.get("syscall"), e.get("dst")
            if is_login_machinery(s) or is_login_machinery(d):
                continue
            edge_ext_ips = get_external_ips(s, local_ips) | get_external_ips(d, local_ips)
            hit_ips = edge_ext_ips & conf_ext_ips
            if hit_ips:
                other = d if (get_external_ips(s, local_ips) & conf_ext_ips) else s
                if str(other) in conf_nodes:
                    rec = dict(e)
                    rec["origin"] = "confirmed"
                    rec["class"] = "story"
                    rec["motif"] = "CAUSAL_NET_BRIDGE"
                    rec["motif_name"] = "外部已知攻击源通信会话桥接"
                    rec["reason"] = "快速通道：外部攻击源与确诊实体网络交互确定性桥接"
                    newly_confirmed[k] = rec
                    if not is_readonly_system_mechanism(s, sc, d):
                        conf_nodes.add(str(s))
                        conf_nodes.add(str(d))

        # 4. 强因果双端实体诱导子图闭环
        for e in candidate_pool:
            k = _key(e)
            if k in confirmed_map or k in newly_confirmed:
                continue
            s, sc, d = e.get("src"), e.get("syscall"), e.get("dst")
            if is_readonly_system_mechanism(s, sc, d):
                continue
            if str(s) in conf_nodes and str(d) in conf_nodes:
                rec = dict(e)
                rec["origin"] = "confirmed"
                rec["class"] = "story"
                rec["motif"] = "INDUCED_SUBGRAPH_CLOSURE"
                rec["motif_name"] = "确诊实体强因果诱导子图闭环"
                rec["reason"] = "快速通道：双端确诊实体因果交互闭环"
                newly_confirmed[k] = rec

        return newly_confirmed
