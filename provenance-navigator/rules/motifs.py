"""因果基模库（Motif Library）：去字面化抽象因果拓扑基模定义与实体角色匹配器。

纯符号因果拓扑，绝不硬编码任何具体业务文件名、文件路径或网络地址。
供离线知识蒸馏器（distiller）与在线模式匹配器（matcher）共同调用。
"""
from typing import Any, Dict, List
from closure.facts import TopologyFacts

CANDIDATE_MOTIFS: List[Dict[str, Any]] = [
    {
        "id": "DIST_01_INBOUND_SESSION_EXEC",
        "name": "入站会话派生解释器或工具",
        "syscalls": ["execve"],
        "proc_role": "INBOUND_PROC",
        "dst_role": "INTERPRETER_OR_TOOL",
        "scope": "horizontal",
    },
    {
        "id": "DIST_02_EXEC_DROPPED_PAYLOAD",
        "name": "受污染进程派生执行写入落地的客体",
        "syscalls": ["execve"],
        "src_role": "DROPPED_OR_WRITTEN",
        "proc_role": "TAINTED_PROC",
        "scope": "horizontal",
    },
    {
        "id": "DIST_03_TAINTED_NET_TOOL",
        "name": "受污染进程执行网络外联工具",
        "syscalls": ["execve"],
        "dst_role": "NET_TOOL",
        "proc_role": "TAINTED_PROC",
        "require_delivery": True,
        "scope": "horizontal",
    },
    {
        "id": "DIST_04_TAINTED_PRIV_TOOL",
        "name": "受污染进程执行权限提升工具",
        "syscalls": ["execve"],
        "dst_role": "PRIV_TOOL",
        "proc_role": "TAINTED_PROC",
        "scope": "horizontal",
    },
    {
        "id": "DIST_05_TAINTED_RECON_TOOL",
        "name": "受污染进程执行系统探测侦察工具",
        "syscalls": ["execve"],
        "dst_role": "RECON_TOOL",
        "proc_role": "TAINTED_PROC",
        "scope": "horizontal",
    },
    {
        "id": "DIST_06_TAINTED_TEMP_CHMOD",
        "name": "对临时目录或写入客体赋予权限",
        "syscalls": ["chmod"],
        "dst_role": "TEMP_OR_WRITTEN",
        "proc_role": "TAINTED_PROC",
        "scope": "horizontal",
    },
    {
        "id": "DIST_07_SENSITIVE_AUTH_MUTATION",
        "name": "受污染进程修改敏感认证凭据",
        "syscalls": ["write", "rename", "symlink"],
        "dst_role": "SENSITIVE_AUTH",
        "proc_role": "TAINTED_PROC",
        "scope": "vertical",
    },
    {
        "id": "DIST_08_PERSISTENCE_MUTATION",
        "name": "受污染进程修改开机自启或服务单元",
        "syscalls": ["write", "symlink", "create"],
        "dst_role": "PERSISTENCE",
        "proc_role": "TAINTED_PROC",
        "scope": "vertical",
    },
    {
        "id": "DIST_09_INTERPRETER_READ_DROPPED",
        "name": "解释器或工具读取落地的脚本与客体",
        "syscalls": ["read", "open"],
        "src_role": "DROPPED_OR_WRITTEN",
        "dst_role": "INTERPRETER_OR_TOOL",
        "scope": "horizontal",
    },
]


def check_entity_role(role: str, val: str, tf: TopologyFacts) -> bool:
    """去字面化实体语义角色抽象判断。"""
    val = str(val)
    if role == "DROPPED_OR_WRITTEN":
        is_script = any(val.endswith(ext) for ext in [".sh", ".py", ".pl", ".bin", ".elf", ".so"]) or "/." in val
        is_user_dir = any(val.startswith(p) for p in ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/srv/"])
        return tf.is_tainted(val) and (is_script or is_user_dir) and not any(
            val.startswith(p) for p in ["/lib", "/usr/lib", "/usr/share", "/proc", "/sys", "/var/lib/dpkg", "/var/cache/apt"]
        )
    if role == "DROPPED_SCRIPT":
        is_script = any(val.endswith(ext) for ext in [".sh", ".py", ".pl"])
        if not is_script:
            return False
        if any(val.startswith(p) for p in ["/lib", "/usr/lib", "/usr/share", "/etc/profile.d", "/root/.nvm", "/etc/bash"]):
            return False
        return tf.is_tainted(val)
    if role == "TEMP_OR_WRITTEN":
        return any(val.startswith(p) for p in ["/tmp/", "/var/tmp/", "/dev/shm/"]) or (
            tf.is_tainted(val) and not val.startswith("/usr/") and not val.startswith("/lib")
        )
    if role == "SENSITIVE_AUTH":
        return val in ["/etc/shadow", "/etc/passwd", "/etc/sudoers"] or val.endswith("/.ssh/authorized_keys") or val.endswith("/authorized_keys")
    if role == "PERSISTENCE":
        return any(
            val.startswith(p)
            for p in [
                "/etc/systemd/system",
                "/lib/systemd/system",
                "/etc/init.d",
                "/etc/cron",
                "/var/spool/cron",
                "/etc/rc.local",
            ]
        )
    name = val.split("/")[-1]
    if role == "INTERPRETER":
        return name in [
            "sh", "bash", "dash", "zsh", "python", "python3", "perl", "php"
        ]
    if role == "INTERPRETER_OR_TOOL":
        return name in [
            "sh", "bash", "dash", "zsh", "python", "python3", "perl", "php",
            "tar", "curl", "wget", "socat"
        ]
    if role == "NET_TOOL":
        return name in ["curl", "wget", "ssh", "socat", "nc", "netcat", "rsync", "nmap"]
    if role == "PRIV_TOOL":
        return name in ["sudo", "chmod", "chown", "su", "useradd", "install"]
    if role == "RECON_TOOL":
        return name in ["id", "whoami", "uname", "hostname", "ip", "ss", "ifconfig"]
    if role == "OUTBOUND_NET":
        return "->" in val and not ("127.0.0.1" in val or "0.0.0.0" in val or "localhost" in val)
    return True


def match_motif(motif: Dict[str, Any], e: Dict[str, Any], tf: TopologyFacts) -> bool:
    """判定单条边是否命中指定的因果拓扑基模。"""
    sc = e.get("syscall", "")
    src = str(e.get("src", ""))
    dst = str(e.get("dst", ""))
    pid = str(e.get("process_id", ""))

    if motif.get("syscalls") and sc not in motif["syscalls"]:
        return False
    proc_role = motif.get("proc_role")
    if proc_role == "TAINTED_PROC":
        if sc in ("read", "open"):
            if not tf.is_tainted_proc(pid) and not tf.is_tainted_proc(dst):
                return False
        else:
            if not tf.is_tainted_proc(pid) and not tf.is_tainted_proc(src):
                return False
    if proc_role == "INBOUND_PROC" and (src not in tf.inbound_processes and pid not in tf.inbound_processes):
        return False
    if motif.get("require_delivery") and not tf.has_delivery(pid):
        return False
    if motif.get("src_role") and not check_entity_role(motif["src_role"], src, tf):
        return False
    if motif.get("dst_role") and not check_entity_role(motif["dst_role"], dst, tf):
        return False
    if motif.get("min_batch") and tf.process_modifies_batch.get(pid, 0) < motif["min_batch"]:
        return False
    return True
