"""系统知识：路径、程序名、系统调用分类与对象谓词。"""
from __future__ import annotations

from typing import Any, Dict

from domain.keys import path_part

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

# 动态共享库：进程启动期读入的这些对象视为环境初始化依赖（与“未受篡改”条件配合使用）
DYNAMIC_LIB_PREFIXES = ("/lib/", "/usr/lib/")
DYNAMIC_LIB_SUFFIX = ".so"

# 前向补链的载体判定：这些前缀不是可写入后供其它进程读取的常规磁盘文件。
# 注意：它与 PSEUDO_PREFIXES 不是同一个集合（后者还含 memfd:/tmpfile:/socket:/anon:），
# 也与 closure_rules.json 的 no_expand 集合不同，不能互相替代。
NON_CARRIER_PREFIXES = ("unix:", "pipe:", "/dev/", "/proc/", "/sys/")

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


def is_dynamic_library(path: Any) -> bool:
    """是否为标准动态共享库路径（前缀 + 后缀，判定口径只此一份）。"""
    p = str(path)
    return DYNAMIC_LIB_SUFFIX in p or p.startswith(DYNAMIC_LIB_PREFIXES)


def is_forward_carrier(path: Any) -> bool:
    """是否为可能承载跨进程内容交付的常规磁盘文件路径（排除套接字、管道与内核伪文件）。"""
    return not str(path).startswith(NON_CARRIER_PREFIXES)


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


