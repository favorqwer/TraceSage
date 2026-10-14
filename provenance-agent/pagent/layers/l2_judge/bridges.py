"""因果拓扑桥接（判定层内部，纯代码、零额外模型调用）：

在大模型完成首轮/前向评审后、数据结算之前执行：
1. 外部已确认攻击源通信桥接：从已确认主线中提取被实锤的外部恶意 IP，将其与本机受害服务之间的
   网络进出通信边自动提升为已确认主线；
2. 优化版强因果双端实体闭环：在核心攻击实体之间扫描，将夹在中间被闸门跳过的系统调用边自动提升为
   已确认主线；严格排除动态链接库与内核伪文件的只读操作，隔离主守护进程私有套接字。
"""

from __future__ import annotations

from collections import Counter
from typing import Any

# 系统只读机制类前缀：只读操作不作为双端实体闭环的攻击实体
MECH_PREFIXES = ("/lib", "/usr/lib", "/usr/share", "/proc", "/sys", "/dev")


def find_local_ips(edges: dict[Any, dict[str, Any]]) -> set[str]:
    """自动从网络端点中统计出现频率最高的 IP 作为本机内网 IP（纯统计，零硬编码）。"""
    ip_counter: Counter[str] = Counter()
    for e in edges.values():
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


def get_external_ips(endpoint_str: Any, local_ips: set[str]) -> set[str]:
    """从网络四元组提取非本机外部 IP。"""
    ext: set[str] = set()
    if endpoint_str and "->" in str(endpoint_str):
        left, _, right = str(endpoint_str).partition("->")
        for part in (left, right):
            ip = part.split(":")[0] if ":" in part else part
            if ip and ip not in local_ips:
                ext.add(ip)
    return ext


def is_readonly_system_mechanism(src: Any, syscall: Any, dst: Any) -> bool:
    """判断是否为只读系统机制类边（动态库读取、系统内部套接字心跳等）。"""
    if str(syscall) in ("read", "recvfrom"):
        if str(src).startswith(MECH_PREFIXES) or str(dst).startswith(MECH_PREFIXES):
            return True
        if str(src).startswith("unix:[/run/systemd/") or str(dst).startswith("unix:[/run/systemd/"):
            return True
    return False


def promote_causal_bridges(inv: Any) -> int:
    """在未排除集合中执行因果拓扑桥接，返回提升的边数。

    在大模型评审完成后、inv.settle() 之前调用：
    1. 提取当前已确认边中的非只读核心实体与外部恶意 IP；
    2. 机制一：提升与外部恶意 IP 的受害服务网络交互边；
    3. 机制二：提升两端均已被确认为核心实体的强因果连接边（排除机制类只读）。
    """
    # 1. 提取基线已确认节点与恶意 IP
    local_ips = find_local_ips(inv.edges)
    conf_nodes: set[str] = set()
    conf_ext_ips: set[str] = set()

    for key, edge in inv.edges.items():
        if inv.origin.get(key) != "confirmed":
            continue
        s, sc, d = edge["src"], edge.get("syscall"), edge["dst"]
        if not is_readonly_system_mechanism(s, sc, d):
            conf_nodes.add(str(s))
            conf_nodes.add(str(d))
        for node in (s, d):
            for ext_ip in get_external_ips(node, local_ips):
                conf_ext_ips.add(ext_ip)

    promoted = 0

    # 2. 机制一：外部已确认攻击源通信桥接
    for key, edge in inv.edges.items():
        if inv.origin.get(key) == "confirmed":
            continue
        s, sc, d = edge["src"], edge.get("syscall"), edge["dst"]
        edge_ext_ips = get_external_ips(s, local_ips) | get_external_ips(d, local_ips)
        hit_ips = edge_ext_ips & conf_ext_ips
        if hit_ips:
            other = d if (get_external_ips(s, local_ips) & conf_ext_ips) else s
            if str(other) in conf_nodes:
                inv.mark([key], "confirmed")
                inv.edges[key]["verdict_reason"] = f"外部已知攻击IP通信桥接 ({', '.join(hit_ips)})"
                promoted += 1
                if not is_readonly_system_mechanism(s, sc, d):
                    conf_nodes.add(str(s))
                    conf_nodes.add(str(d))

    # 3. 机制二：优化版强因果双端实体闭环
    for key, edge in inv.edges.items():
        if inv.origin.get(key) == "confirmed":
            continue
        s, sc, d = edge["src"], edge.get("syscall"), edge["dst"]
        if is_readonly_system_mechanism(s, sc, d):
            continue
        if str(s) in conf_nodes and str(d) in conf_nodes:
            inv.mark([key], "confirmed")
            inv.edges[key]["verdict_reason"] = f"强因果双端实体闭环 ({s} -> {d})"
            promoted += 1

    return promoted
