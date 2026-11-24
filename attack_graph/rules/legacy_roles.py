"""旧节点角色口径（兼容层；仅离线挖掘兜底与旧测试使用）。"""
from __future__ import annotations

from typing import Any, Dict, List

from domain.keys import path_part
from domain.pool import TopologyFacts
from domain.taxonomy import (
    PERSISTENCE_PREFIXES,
    SYSTEM_LIB_PREFIXES,
    is_sensitive_object,
)

# ==== 6. 节点角色（迁移期保留两份行为，供差异清单对比） ====

def abstract_node_role(node_str: str, graph_edges: List[Dict[str, Any]]) -> str:
    """旧离线口径：只看全边列表，不看污染事实。"""
    s = str(node_str)
    p = path_part(s)
    if "->" in s:
        return "SOCKET_ENDPOINT"
    if any(p.startswith(prefix) for prefix in PERSISTENCE_PREFIXES):
        return "PERSISTENCE_CONFIG"
    if is_sensitive_object(p):
        return "SENSITIVE_AUTH_FILE"

    is_written = any(str(e.get("dst")) == s and e.get("syscall") in ("write", "create", "rename", "symlink") for e in graph_edges)
    if is_written and not any(p.startswith(prefix) for prefix in SYSTEM_LIB_PREFIXES):
        return "DROPPED_OBJECT"

    actor_scs = {e.get("syscall") for e in graph_edges if str(e.get("src")) == s and e.get("syscall") not in ("read", "accept", "recvfrom", "sendfile")}
    is_dst_exec = any(str(e.get("dst")) == s and e.get("syscall") == "execve" for e in graph_edges)

    is_proc = bool(actor_scs) or is_dst_exec
    if is_proc:
        is_server = any(str(e.get("dst")) == s and e.get("syscall") == "accept" for e in graph_edges)
        if is_server:
            return "INBOUND_SERVER_PROC"
        if any(sc in ("connect", "sendto") for sc in actor_scs):
            return "OUTBOUND_NET_PROC"
        if "chmod" in actor_scs or "chown" in actor_scs:
            return "PRIV_MUTATOR_PROC"
        if "clone" in actor_scs or "execve" in actor_scs:
            return "INTERPRETER_OR_SPAWNER_PROC"
        if is_dst_exec and not actor_scs.intersection({"write", "connect", "sendto", "chmod", "clone", "execve"}):
            return "RECON_LEAF_PROC"
        return "INTERPRETER_OR_SPAWNER_PROC"

    return "GENERIC_PROC_OR_FILE"
