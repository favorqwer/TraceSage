"""因果基模库与实体拓扑角色抽象器（Motif Library & Behavioral Role Evaluator）

设计准则：
1. 语义角色抽象不含“恶意工具名／良性工具名”判定表，纯按客观拓扑属性判定；
   但本模块仍含固定字面量常量（系统敏感认证路径、持久化路径前缀、系统库前缀、共享守护进程名、
   以及 Ubuntu 特有的登录机制路径前缀），它们是跨发行版泛化的已知风险点；
   系统全部残留字面量的清单与用途（含 `closure/facts.py` 的 12 项可执行名）见
   `provenance-navigator/README.md` 第 2.1 节「残留字面量知识」；
2. 严格遵循 Linux/POSIX 标准系统领域常识（认证凭据、持久化服务路径、守护进程标识）；
3. 严格遵循 Sysdig 系统调用因果流向与执行主体/客体分离。
"""
from typing import Any, Dict, List, Optional, Set, Tuple
from closure.facts import TopologyFacts

# Linux 标准系统领域本体常识（POSIX/FHS 规范不变式）
SENSITIVE_AUTH_PATHS = frozenset([
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
])

PERSISTENCE_PREFIXES = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/etc/init.d",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/rc.local",
)

SYSTEM_LIB_PREFIXES = (
    "/lib",
    "/usr/lib",
    "/usr/share",
    "/proc",
    "/sys",
    "/dev",
)

LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
    "/snap/snapd-desktop-integration",
)

SHARED_DAEMONS = frozenset({
    "sshd", "nginx", "apache2", "httpd", "systemd", "cron", "dbus-daemon", "rsyslogd"
})


def abstract_node_role(node_str: str, graph_edges: List[Dict[str, Any]]) -> str:
    """基于图内拓扑客观属性抽象节点角色（严格遵循 Sysdig 因果流向与主体/客体语义）。"""
    s = str(node_str)
    if "->" in s:
        return "SOCKET_ENDPOINT"
    if any(s.startswith(p) for p in PERSISTENCE_PREFIXES):
        return "PERSISTENCE_CONFIG"
    if s in SENSITIVE_AUTH_PATHS or s.endswith("/authorized_keys") or ".ssh/id_" in s:
        return "SENSITIVE_AUTH_FILE"
    
    # 区分是否为被写入/创建的落地载荷客体
    is_written = any(str(e.get("dst")) == s and e.get("syscall") in ("write", "create", "rename", "symlink") for e in graph_edges)
    if is_written and not any(s.startswith(p) for p in SYSTEM_LIB_PREFIXES):
        return "DROPPED_OBJECT"
    
    # 判定是否为进程实体：是执行客体或为主动动作的主体
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


def evaluate_node_behavioral_role(node: str,
                                  in_edges: Dict[str, List[Dict[str, Any]]],
                                  out_edges: Dict[str, List[Dict[str, Any]]],
                                  tf: TopologyFacts) -> str:
    """在线候选图节点客观角色判定器（彻底杜绝工具词表硬编码）。"""
    s = str(node)
    if "->" in s:
        return "SOCKET_ENDPOINT"
    if any(s.startswith(p) for p in PERSISTENCE_PREFIXES):
        return "PERSISTENCE_CONFIG"
    if s in SENSITIVE_AUTH_PATHS or s.endswith("/authorized_keys") or ".ssh/id_" in s:
        return "SENSITIVE_AUTH_FILE"

    is_written = tf.is_tainted(s) or any(e.get("syscall") in ("write", "create", "rename", "symlink") for e in in_edges.get(s, []))
    if is_written and not any(s.startswith(p) for p in SYSTEM_LIB_PREFIXES):
        return "DROPPED_OBJECT"

    actor_evts = out_edges.get(s, [])
    actor_scs = {e.get("syscall") for e in actor_evts if e.get("syscall") not in ("read", "accept", "recvfrom", "sendfile")}
    is_dst_exec = any(e.get("syscall") == "execve" for e in in_edges.get(s, []))

    is_proc = bool(actor_scs) or is_dst_exec or (s in tf.inbound_processes) or tf.is_tainted_proc(s)
    if is_proc:
        is_server = any(e.get("syscall") == "accept" for e in in_edges.get(s, [])) or (s in tf.inbound_processes)
        if is_server:
            return "INBOUND_SERVER_PROC"
        if any(sc in ("connect", "sendto") for sc in actor_scs) or tf.has_delivery(s):
            return "OUTBOUND_NET_PROC"
        if "chmod" in actor_scs or "chown" in actor_scs:
            return "PRIV_MUTATOR_PROC"
        if "clone" in actor_scs or "execve" in actor_scs:
            return "INTERPRETER_OR_SPAWNER_PROC"
        if is_dst_exec and not actor_scs.intersection({"write", "connect", "sendto", "chmod", "clone", "execve"}):
            return "RECON_LEAF_PROC"
        return "INTERPRETER_OR_SPAWNER_PROC"

    return "GENERIC_PROC_OR_FILE"
