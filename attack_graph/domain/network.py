"""网络端点字符串解析与本地/外部地址判定。"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

# ==== 4. 网络端点 ====

def parse_endpoint(value: Any) -> Tuple[str, str]:
    """连接对象 `lip:lport->rip:rport` →（左端, 右端）；不是连接对象返回空串。"""
    s = str(value or "")
    if "->" not in s:
        return "", ""
    left, _, right = s.partition("->")
    return left, right


def socket_ips(value: Any) -> Set[str]:
    left, right = parse_endpoint(value)
    out: Set[str] = set()
    for part in (left, right):
        if not part:
            continue
        ip = part.split(":")[0] if ":" in part else part
        if ip and not ip.startswith(("unix:", "pipe:", "socket:")):
            out.add(ip)
    return out


def find_local_ips(edges: List[Dict[str, Any]]) -> Set[str]:
    """原 bridge.find_local_ips：accept/recvfrom 的目标 IP + 出现最多的 IP。"""
    from collections import Counter

    local_ips = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
    counter: Counter = Counter()
    server_ips: Set[str] = set()
    for e in edges:
        sc = str(e.get("syscall") or "")
        for node in (e.get("src"), e.get("dst")):
            left, right = parse_endpoint(node)
            for part in (left, right):
                if not part:
                    continue
                ip = part.split(":")[0] if ":" in part else part
                if ip and not ip.startswith("127.") and not ip.startswith("0.0."):
                    counter[ip] += 1
        if sc in ("accept", "recvfrom"):
            left, right = parse_endpoint(e.get("src"))
            ip = right.split(":")[0] if ":" in right else right
            if ip and not ip.startswith("127.") and not ip.startswith("0.0."):
                server_ips.add(ip)
    local_ips.update(server_ips)
    if counter:
        local_ips.add(counter.most_common(1)[0][0])
    return local_ips


def get_external_ips(endpoint: Any, local_ips: Set[str]) -> Set[str]:
    out: Set[str] = set()
    for part in parse_endpoint(endpoint):
        if not part:
            continue
        ip = part.split(":")[0] if ":" in part else part
        if ip and ip not in local_ips and not ip.startswith("127.") and ip != "::1":
            out.add(ip)
    return out


def is_loopback_dns_resolver(node: Any) -> bool:
    s = str(node)
    if "->" not in s:
        return False
    return any(part.startswith("127.") and part.endswith(":53") for part in s.split("->"))

