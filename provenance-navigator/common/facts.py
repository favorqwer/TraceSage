"""图语义事实：路径本体、系统调用分类、污染传播、对象/网络/角色查询。

本模块只回答“图上有什么事实”，不回答“这条边是否确认”。
规则模式、LLM 模式、剪枝共用这里的查询；判定策略留在各自模块。

阶段 2 说明：
- 本文件先建立，旧代码暂未切换；差异清单脚本用它和旧实现逐项对比。
- `abstract_node_role` 与 `evaluate_node_behavioral_role` 暂时保留两份行为，
  差异清单为空后再决定是否合并。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from common.graph import path_part, process_identity_variants

# ==== 1. 路径本体常量（每项标注来源） ====

# POSIX/FHS 认证凭据
SENSITIVE_AUTH_PATHS = frozenset([
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/group",
    "/etc/gshadow",
    "/etc/subuid",
    "/etc/subgid",
    "/etc/security/opasswd",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
])

# POSIX/FHS 持久化位置
PERSISTENCE_PREFIXES = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/etc/init.d",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/rc.local",
)

# 系统库与内核伪文件
SYSTEM_LIB_PREFIXES = (
    "/lib",
    "/usr/lib",
    "/usr/share",
    "/proc",
    "/sys",
    "/dev",
)

# 登录机制与发行版自带脚本；Ubuntu 22.04 特有项需随发行版核对
LOGIN_MACHINERY_PREFIXES = (
    "/etc/update-motd.d",
    "/usr/lib/update-notifier",
    "/usr/lib/ubuntu-release-upgrader",
    "/snap/snapd-desktop-integration",
    "/etc/profile.d",
    "/etc/default",
    "/var/run/motd",
)

# 共享多租户守护进程（会话桥接用，不是恶意判定表）
SHARED_DAEMONS = frozenset({
    "sshd", "nginx", "apache2", "httpd", "systemd", "cron", "dbus-daemon", "rsyslogd",
    "mysqld", "mariadb", "redis-server", "postgres", "mongod", "slapd", "java",
})

# 内核按需生成、不承载内容的伪对象；/dev/shm、/run/shm、/tmp、/var/tmp 故意保留
PSEUDO_PREFIXES = ("/sys/", "/proc/", "pipe:", "memfd:", "tmpfile:", "socket:", "unix:", "anon:")
PSEUDO_DEV_EXACT = frozenset({
    "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full",
    "/dev/tty", "/dev/ptmx", "/dev/console",
})

# 静态只读背景：进入符号通道前剥离，保留原 CausalFilter 的精确前缀集合
STATIC_READ_PREFIXES = (
    "/proc/", "/sys/", "/lib/", "/usr/lib/", "/usr/share/",
    "/etc/ld.so.", "/etc/locale", "/usr/include/", "/dev/urandom", "/dev/null",
)

# ==== 2. 系统调用分类 ====

WRITE_SC = frozenset({"write", "create", "mkdir", "rename", "chmod", "chown", "symlink"})
READ_SC = frozenset({"read", "open", "sendfile", "recvfrom"})
SPAWN_SC = frozenset({"execve", "clone", "fork"})
SENSITIVE_READ_SC = frozenset({"read", "open", "sendfile"})

# 入站会话派生的常见解释器/工具名；与 SHARED_DAEMONS 分开，用途不同
INTERPRETER_NAMES = frozenset({
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "php",
    "tar", "curl", "wget", "socat", "nc", "netcat", "ncat", "busybox",
    "awk", "sed", "ruby", "lua",
})

# ==== 3. 对象分类 ====

def is_pseudo_object(obj: Any) -> bool:
    """内核按需生成、不承载内容的伪对象（保留 /dev/shm 等可写内存文件系统）。"""
    o = str(obj)
    if o.startswith(PSEUDO_PREFIXES):
        return True
    if o.startswith("/dev/"):
        return (o in PSEUDO_DEV_EXACT) or o.startswith("/dev/pts/") or o.startswith("/dev/fd/")
    return False


def is_pivot_pseudo(obj: Any) -> bool:
    """旧 pivot 路由器的伪对象口径（把整个 /dev/ 都排除），只用于差异清单。"""
    o = str(obj)
    return o.startswith(PSEUDO_PREFIXES) or o.startswith("/dev/")


def is_sensitive_object(path: Any) -> bool:
    p = path_part(path)
    return bool(
        p in SENSITIVE_AUTH_PATHS
        or p.endswith("/authorized_keys")
        or ".ssh/id_" in p
        or p.endswith((".env", "wp-config.php", "credentials.ini", "settings.py"))
    )


def classify_path(path: Any) -> str:
    """路径的单一主类别；顺序即优先级。"""
    p = path_part(path)
    if is_pseudo_object(p):
        return "pseudo"
    if p in SENSITIVE_AUTH_PATHS or p.endswith("/authorized_keys") or ".ssh/id_" in p:
        return "auth"
    if p.endswith((".env", "wp-config.php", "credentials.ini", "settings.py")):
        return "auth"
    if any(p.startswith(prefix) for prefix in PERSISTENCE_PREFIXES):
        return "persistence"
    if any(p.startswith(prefix) for prefix in LOGIN_MACHINERY_PREFIXES):
        return "login"
    if any(p.startswith(prefix) for prefix in SYSTEM_LIB_PREFIXES):
        return "system_lib"
    if p.startswith("/dev/"):
        return "device"
    return "carrier"


def is_static_read_background(edge: Dict[str, Any], taint: "TopologyFacts") -> bool:
    """原 CausalFilter 的判据：read + 静态系统路径 + 全图无写入污染。"""
    if str(edge.get("syscall") or "") != "read":
        return False
    src = str(edge.get("src") or "")
    return any(src.startswith(prefix) for prefix in STATIC_READ_PREFIXES) and not taint.is_tainted(src)


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


def story_local_ip(edges: List[Dict[str, Any]]) -> str | None:
    """原 boundary_story 的本地 IP 口径：只取出现最多的 IP。"""
    from collections import Counter

    counter: Counter = Counter()
    for e in edges:
        for node in (e.get("src"), e.get("dst")):
            for ip in socket_ips(node):
                if not ip.startswith(("127.", "0.0.")):
                    counter[ip] += 1
    return counter.most_common(1)[0][0] if counter else None


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


# ==== 5. 污染传播与交付事实 ====

class TopologyFacts:
    """图拓扑的客观交付事实：写入、外部接收、外发、污染传播固定点。

    与旧 `closure.facts.TopologyFacts` 同语义；只把进程标识变体与路径拆分改为调用
    `common.graph`，不再各自实现。
    """

    def __init__(self, edges: List[Dict[str, Any]]):
        self.written_objects: Set[str] = set()
        self.net_dropped_objects: Set[str] = set()
        self.process_written_targets: Dict[str, Set[str]] = {}
        self.process_has_outbound_delivery: Set[str] = set()
        self.inbound_net_endpoints: Set[str] = set()
        self.inbound_processes: Set[str] = set()
        self.process_modifies_batch: Dict[str, int] = {}
        self.tainted_processes: Set[str] = set()

        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))
            dst = str(e.get("dst", ""))
            pid = str(e.get("process_id", ""))

            if sc in ["write", "create", "mkdir", "rename", "chmod", "unlink", "symlink"]:
                if not path_part(dst).startswith("/proc/") and not path_part(dst).startswith("/sys/") and not path_part(dst).startswith("pipe:"):
                    self.written_objects.add(dst)
                if sc in ["rename", "symlink"]:
                    if not path_part(src).startswith("/proc/") and not path_part(src).startswith("/sys/") and not path_part(src).startswith("pipe:"):
                        self.written_objects.add(src)
                if pid:
                    self.process_written_targets.setdefault(pid, set()).add(dst)
                    if sc in ["rename", "unlink"]:
                        self.process_modifies_batch[pid] = self.process_modifies_batch.get(pid, 0) + 1

            if sc in ["accept", "recvfrom"] and "->" in src:
                self.inbound_net_endpoints.add(src)
                if dst:
                    self.inbound_processes.update(process_identity_variants(dst))
                if pid:
                    self.inbound_processes.update(process_identity_variants(pid))

            if sc in ["write", "sendto", "connect"] and ("->" in dst or "pipe:" in dst):
                if pid:
                    self.process_has_outbound_delivery.update(process_identity_variants(pid))

            if sc in ["clone", "fork", "execve"]:
                if pid:
                    self.process_has_outbound_delivery.update(process_identity_variants(pid))

        for _ in range(30):
            changed = False
            for e in edges:
                sc = e.get("syscall", "")
                src = str(e.get("src", ""))
                dst = str(e.get("dst", ""))
                pid = str(e.get("process_id", ""))
                pid_vars = process_identity_variants(pid)
                src_vars = process_identity_variants(src)
                dst_vars = process_identity_variants(dst)

                if (pid_vars.intersection(self.tainted_processes) or src_vars.intersection(self.tainted_processes)):
                    if sc in ["write", "create", "rename", "symlink"]:
                        if dst not in self.net_dropped_objects and not path_part(dst).startswith("/proc/") and not path_part(dst).startswith("/dev/"):
                            self.net_dropped_objects.add(dst)
                            changed = True

                if sc in ("execve", "clone", "fork"):
                    if src in self.written_objects or src in self.net_dropped_objects:
                        new_taints = (pid_vars | dst_vars) - self.tainted_processes
                        if new_taints:
                            self.tainted_processes.update(new_taints)
                            changed = True

                    if (src_vars.intersection(self.inbound_processes) or pid_vars.intersection(self.inbound_processes)):
                        name = dst.split("/")[-1]
                        is_known_tool = name in INTERPRETER_NAMES
                        is_topological_spawn = (
                            not path_part(dst).startswith(("/lib/", "/usr/lib/", "/usr/share/"))
                            and name not in ("sshd", "systemd", "dbus-daemon", "rsyslogd")
                        )
                        if is_known_tool or is_topological_spawn:
                            new_taints = (pid_vars | dst_vars) - self.tainted_processes
                            if new_taints:
                                self.tainted_processes.update(new_taints)
                                changed = True

                    if (src_vars.intersection(self.tainted_processes) or pid_vars.intersection(self.tainted_processes)):
                        new_taints = (dst_vars | pid_vars) - self.tainted_processes
                        if new_taints:
                            self.tainted_processes.update(new_taints)
                            changed = True
            if not changed:
                break

    def is_tainted(self, target_path: str) -> bool:
        return target_path in self.written_objects or target_path in self.net_dropped_objects

    def has_delivery(self, pid: str) -> bool:
        return bool(process_identity_variants(pid).intersection(self.process_has_outbound_delivery))

    def is_tainted_proc(self, pid: str) -> bool:
        vars_set = process_identity_variants(pid)
        return bool(vars_set.intersection(self.tainted_processes) or vars_set.intersection(self.inbound_processes))


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


def evaluate_node_behavioral_role(node: str,
                                  in_edges: Dict[str, List[Dict[str, Any]]],
                                  out_edges: Dict[str, List[Dict[str, Any]]],
                                  tf: TopologyFacts) -> str:
    """旧在线口径：邻接表 + 污染事实。"""
    s = str(node)
    p = path_part(s)
    if "->" in s:
        return "SOCKET_ENDPOINT"
    if any(p.startswith(prefix) for prefix in PERSISTENCE_PREFIXES):
        return "PERSISTENCE_CONFIG"
    if is_sensitive_object(p):
        return "SENSITIVE_AUTH_FILE"

    is_written = tf.is_tainted(s) or any(e.get("syscall") in ("write", "create", "rename", "symlink") for e in in_edges.get(s, []))
    if is_written and not any(p.startswith(prefix) for prefix in SYSTEM_LIB_PREFIXES):
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
