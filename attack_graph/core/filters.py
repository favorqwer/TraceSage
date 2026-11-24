"""路由管线的后置剪枝阶段。

- `DebrisPrune`：把包管理内部碎片、死端认证读取、本地 DNS 伪连接等从确认集移入未排除；
  包管理器名单与临时路径从 `config/navigator.toml` 的 `[prune]` 读取。

所有被移出的边一律进未排除，不删除。本模块不导入 `rules`、`llm`、`closure`。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import settings as cfg
from domain.network import is_loopback_dns_resolver
from domain.pool import TopologyFacts
from domain.taxonomy import PSEUDO_PREFIXES as FACT_PSEUDO_PREFIXES, SENSITIVE_AUTH_PATHS
from domain.edge import edge_key
from domain.keys import process_identity_variants

PSEUDO_PREFIXES = FACT_PSEUDO_PREFIXES + ("/dev/",)

AUTH_OR_CONFIG = SENSITIVE_AUTH_PATHS | frozenset({
    "/etc/nshadow", "/etc/shadow+", "/etc/passwd+",
})

PERSISTENCE_PREFIXES = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/etc/init.d",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/rc.local",
)


_SYSTEM_BIN_DIRS = frozenset({"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"})

_PKG_CATALOG_SINKS = ("/var/lib/apt/lists/", "/var/lib/swcatalog/", "/var/lib/app-info/", "/var/cache/apparmor/")
_CGROUP_KERNEL_PREFIXES = ("/sys/fs/cgroup/", "/sys/devices/", "/sys/kernel/", "/proc/sys/")
_BROADCAST_BUS_HUBS = frozenset({
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
    "/run/systemd/journal/socket",
    "/var/run/systemd/journal/socket",
    "/run/systemd/journal/stdout",
    "/var/run/systemd/journal/stdout",
    "/run/systemd/journal/dev-log",
    "/var/run/systemd/journal/dev-log",
})
INFRA_DAEMON_BINS = frozenset({
    "/lib/systemd/systemd", "/usr/lib/systemd/systemd", "/sbin/init",
    "/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-logind", "/usr/lib/systemd/systemd-logind",
    "/lib/systemd/systemd-resolved", "/usr/lib/systemd/systemd-resolved",
    "/lib/systemd/systemd-udevd", "/usr/lib/systemd/systemd-udevd",
    "/lib/systemd/systemd-timesyncd", "/usr/lib/systemd/systemd-timesyncd",
    "/lib/systemd/systemd-networkd", "/usr/lib/systemd/systemd-networkd",
    "/usr/bin/dbus-daemon",
})


def is_infra_daemon(path: str) -> bool:
    """判定是否为通用系统监督或基础运行守护进程（systemd 家族与 dbus）。"""
    return (
        path in INFRA_DAEMON_BINS
        or "/systemd/systemd-" in path
        or path.endswith("/systemd")
        or path.endswith("/sbin/init")
    )


class DebrisPrune:
    """后置剪枝：包管理碎片、死端读取、本地 DNS 伪连接、自派生空转边。"""

    def __init__(self, poi_anchors: Optional[List[Tuple[Any, Any, Any]]] = None):
        self.poi_dirs: Set[str] = set()
        self.anchor_keys: Set[Tuple[Any, Any, Any]] = set()
        if poi_anchors:
            for item in poi_anchors:
                s, sc, d = item[0], item[1], item[2]
                self.anchor_keys.add((s, sc, d))
                for node in (str(s), str(d)):
                    if "/" in node and not node.startswith("unix:") and "->" not in node:
                        parent_dir = "/".join(node.split("/")[:-1])
                        if parent_dir and parent_dir not in _SYSTEM_BIN_DIRS:
                            self.poi_dirs.add(parent_dir)

    def is_operational_debris(self, edge: Dict[str, Any]) -> bool:
        s = str(edge.get("src", ""))
        d = str(edge.get("dst", ""))
        sc = str(edge.get("syscall", ""))
        prog_s = s.split("/")[-1]
        prog_d = d.split("/")[-1]

        if sc in ("execve", "clone", "fork") or any(tok in s or tok in d for tok in cfg.prune_postinst_tokens()):
            return False
        if any(p.startswith(p_dir + "/") for p_dir in self.poi_dirs if len(p_dir) > 4 for p in (s, d)):
            return False
        if any(sink in s or sink in d for sink in _PKG_CATALOG_SINKS):
            return True
        if (is_infra_daemon(s) or is_infra_daemon(d)) and (
            any(p.startswith(px) for px in _CGROUP_KERNEL_PREFIXES for p in (s, d))
            or s in _BROADCAST_BUS_HUBS
            or d in _BROADCAST_BUS_HUBS
        ):
            return True
        managers = cfg.prune_managers()
        sinks = cfg.prune_internal_sinks()
        if prog_s in managers or prog_d in managers:
            other = d if prog_s in managers else s
            if any(sink in other for sink in sinks) or other.startswith("pipe:"):
                return True
            if sc in ("ioctl", "stat", "lstat", "fstat", "access", "faccessat", "readlink", "getdents", "getdents64", "mmap"):
                return True
        if (prog_s == "apt-get" or prog_d == "apt-get") and sc in ("read", "write", "open", "ioctl"):
            other = d if prog_s == "apt-get" else s
            if any(other.startswith(p) for p in ("/var/lib/apt/", "/var/cache/apt/", "pipe:")) or sc == "ioctl":
                return True
        return False

    def apply(self, confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
              candidate_pool: Optional[List[Dict[str, Any]]] = None,
              ) -> Tuple[Dict[Tuple[Any, Any, Any], Dict[str, Any]], List[Dict[str, Any]]]:
        filtered: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        moved: List[Dict[str, Any]] = []

        if not candidate_pool:
            for key, edge in confirmed_map.items():
                if edge.get("class") == "anchor" or key in self.anchor_keys:
                    filtered[key] = edge
                    continue
                if self.is_operational_debris(edge):
                    rec = dict(edge)
                    rec["origin"] = "kept"
                    rec["reason"] = "因果路由器：包管理内部死端伴生碎片，归入未排除"
                    moved.append(rec)
                else:
                    filtered[key] = edge
            return filtered, moved

        proc_has_net_inbound: Set[str] = set()
        proc_has_net_outbound: Set[str] = set()
        proc_has_high_impact_mutation: Set[str] = set()
        parent_of: Dict[str, Set[str]] = defaultdict(set)
        children_of: Dict[str, Set[str]] = defaultdict(set)
        pipe_io: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: {"writers": set(), "readers": set()}
        )

        for e in candidate_pool:
            sc = str(e.get("syscall") or "")
            pid = str(e.get("process_id") or "")
            s, d = str(e.get("src") or ""), str(e.get("dst") or "")

            if sc == "write" and d.startswith("pipe:"):
                if pid:
                    pipe_io[d]["writers"].add(pid)
                if s:
                    pipe_io[d]["writers"].add(s)
            if sc in ("read", "open") and s.startswith("pipe:"):
                if pid:
                    pipe_io[s]["readers"].add(pid)
                if d:
                    pipe_io[s]["readers"].add(d)

            if sc in ("connect", "sendto", "write") and "->" in d:
                if not is_loopback_dns_resolver(d):
                    if pid:
                        proc_has_net_outbound.add(pid)
                    if s:
                        proc_has_net_outbound.add(s)
            if sc in ("accept", "recvfrom", "read") and "->" in s:
                if not is_loopback_dns_resolver(s):
                    if pid:
                        proc_has_net_inbound.add(pid)
                    if d:
                        proc_has_net_inbound.add(d)

            if sc in ("write", "create", "rename", "chmod", "chown", "symlink"):
                is_pseudo = any(d.startswith(p) for p in PSEUDO_PREFIXES) or d.startswith("/dev/")
                is_persist = any(d.startswith(p) for p in PERSISTENCE_PREFIXES)
                is_auth = d in AUTH_OR_CONFIG or "authorized_keys" in d
                if not is_pseudo or is_persist or is_auth:
                    if pid:
                        proc_has_high_impact_mutation.add(pid)
                    if s:
                        proc_has_high_impact_mutation.add(s)

            if sc in ("execve", "clone", "fork"):
                for _, p in e.get("src_identities", []):
                    for pv in process_identity_variants(p):
                        for cid in process_identity_variants(pid) | {d}:
                            if cid:
                                parent_of[cid].add(pv)
                                children_of[pv].add(cid)
                if s and d and s != d:
                    parent_of[d].add(s)
                    children_of[s].add(d)

        interactive_session_procs: Set[str] = set()
        for e in confirmed_map.values():
            s = str(e.get("src") or "")
            d = str(e.get("dst") or "")
            pid = str(e.get("process_id") or "")
            if any(term in s for term in ("bash", "sh", "sshd")):
                interactive_session_procs.add(s)
                if pid:
                    interactive_session_procs.update(process_identity_variants(pid))
            if any(term in d for term in ("bash", "sh")):
                interactive_session_procs.add(d)
                if pid:
                    interactive_session_procs.update(process_identity_variants(pid))

        proc_has_any_delivery = set(proc_has_net_outbound | proc_has_high_impact_mutation)
        for _ in range(3):
            for p, ch_set in list(children_of.items()):
                if any(c in proc_has_any_delivery for c in ch_set):
                    proc_has_any_delivery.add(p)

        for key, edge in confirmed_map.items():
            if edge.get("class") == "anchor" or key in self.anchor_keys:
                filtered[key] = edge
                continue

            s = str(edge.get("src") or "")
            sc = str(edge.get("syscall") or "")
            d = str(edge.get("dst") or "")
            pid = str(edge.get("process_id") or "")
            motif = edge.get("motif", "")

            if is_loopback_dns_resolver(s) or is_loopback_dns_resolver(d):
                rec = dict(edge)
                rec["origin"] = "kept"
                rec["reason"] = "因果路由器：排除系统内部本地DNS存根解析伪桥接"
                moved.append(rec)
                continue

            if s.startswith("pipe:") or d.startswith("pipe:"):
                p_id = s if s.startswith("pipe:") else d
                pipe_info = pipe_io.get(p_id, {"writers": set(), "readers": set()})
                has_net_writer = any(
                    w in proc_has_net_outbound or w in proc_has_net_inbound
                    or "curl" in w or "wget" in w
                    for w in pipe_info["writers"]
                )
                has_exec_reader = any(
                    "bash" in r or "sh" in r or "python" in r for r in pipe_info["readers"]
                )
                if has_net_writer and (has_exec_reader or sc == "write"):
                    filtered[key] = edge
                    continue
                if motif in ("STRICT_INDUCED_CLOSURE", "REFINED_ACTIVE_BRIDGE"):
                    rec = dict(edge)
                    rec["origin"] = "kept"
                    rec["reason"] = "因果路由器：辅助工具内部无害管道降噪"
                    moved.append(rec)
                    continue

            if sc in ("read", "open", "sendfile") and s in AUTH_OR_CONFIG:
                reader_has_delivery = (pid in proc_has_any_delivery or d in proc_has_any_delivery)
                is_sshd_auth = ("authorized_keys" in s and "sshd" in d)
                parents = parent_of.get(pid, set()) | parent_of.get(d, set())
                is_interactive_recon = (
                    any(p in interactive_session_procs for p in parents)
                    or (pid in interactive_session_procs or d in interactive_session_procs)
                )
                if not reader_has_delivery and not is_sshd_auth and not is_interactive_recon:
                    rec = dict(edge)
                    rec["origin"] = "kept"
                    rec["reason"] = "因果路由器：死端认证读取 (无信息流交付且非会话侦察)"
                    moved.append(rec)
                    continue

            if sc == "execve" and s == d and motif == "PROCESS_LINEAGE_SPAWN":
                rec = dict(edge)
                rec["origin"] = "kept"
                rec["reason"] = "因果路由器：冗余自派生空转边"
                moved.append(rec)
                continue

            if self.is_operational_debris(edge):
                rec = dict(edge)
                rec["origin"] = "kept"
                rec["reason"] = "因果路由器：包管理内部死端伴生碎片，归入未排除"
                moved.append(rec)
                continue

            filtered[key] = edge

        return filtered, moved

