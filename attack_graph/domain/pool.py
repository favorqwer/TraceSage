"""候选池事实：写入客体、入站进程、外发交付与污染固定点。"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from domain.keys import path_part, process_identity_variants
from domain.network import find_local_ips, socket_ips
from domain.taxonomy import (
    INTERPRETER_NAMES, LOGIN_MACHINERY_PREFIXES, PERSISTENCE_PREFIXES,
    PSEUDO_DEV_EXACT, PSEUDO_PREFIXES, READ_SC, SENSITIVE_AUTH_PATHS, WRITE_SC,
)

# ==== 5. 污染传播与交付事实 ====

class TopologyFacts:
    """图拓扑的客观交付事实：写入、外部接收、外发、污染传播固定点。

    进程标识变体与路径拆分统一调用 `domain.keys`，本文件不再各自实现。
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


# ==== 候选池统一索引 ====

_SENSITIVE_SYSCALLS = ("read", "open", "sendfile")
_UPWARD_BLOCK_PREFIXES = (
    "/lib", "/usr/lib", "/usr/sbin/sshd", "/usr/sbin/nginx", "/usr/lib/systemd/systemd",
)


class PreparedEdge:
    __slots__ = ("idx", "e", "key", "s", "d", "sc", "pid", "login_skip", "taint_ok",
                 "pid_vars", "parent_vars", "child_vars", "all_id_vars", "sens_vars",
                 "upward_blocked", "is_auth", "is_persist", "is_dropped")

    def get(self, key: str, default: Any = None) -> Any:
        return self.e.get(key, default)


class CandidatePool:
    """一个候选池的预计算索引：邻接、系统调用分桶、进程标识变体、敏感读取索引。"""

    def __init__(self, edges: List[Dict[str, Any]], facts: Optional[TopologyFacts] = None):
        self.raw = list(edges)
        self.facts = facts if facts is not None else TopologyFacts(self.raw)
        self.out: Dict[str, List[PreparedEdge]] = defaultdict(list)
        self.inn: Dict[str, List[PreparedEdge]] = defaultdict(list)
        self.edges: List[PreparedEdge] = []
        self.by_syscall: Dict[str, List[PreparedEdge]] = defaultdict(list)
        self.by_key: Dict[Tuple, List[PreparedEdge]] = defaultdict(list)
        self.parent_index: Dict[str, Set[int]] = defaultdict(set)
        self.child_index: Dict[str, Set[int]] = defaultdict(set)
        self.sens_index: Dict[str, Set[int]] = defaultdict(set)

        prepared: List[PreparedEdge] = []
        for idx, e in enumerate(self.raw):
            pe = PreparedEdge()
            pe.idx = idx
            pe.e = e
            pe.s = str(e.get("src") or "")
            pe.d = str(e.get("dst") or "")
            pe.sc = str(e.get("syscall") or "")
            pe.pid = str(e.get("process_id") or "")
            pe.key = (pe.s, pe.sc, pe.d)
            pe.login_skip = any(path_part(pe.s).startswith(p) or path_part(pe.d).startswith(p)
                                for p in LOGIN_MACHINERY_PREFIXES)
            pe.taint_ok = bool(self.facts.is_tainted_proc(pe.pid)
                               or self.facts.is_tainted_proc(pe.s)
                               or pe.pid in self.facts.inbound_processes
                               or pe.s in self.facts.inbound_processes)
            pe.upward_blocked = any(pe.s.startswith(p) for p in _UPWARD_BLOCK_PREFIXES)

            pe.pid_vars = process_identity_variants(pe.pid)
            src_ids = {str(v) for _, v in (e.get("src_identities") or [])}
            dst_ids = {str(v) for _, v in (e.get("dst_identities") or [])}
            src_vars: Set[str] = set()
            for v in src_ids:
                src_vars |= process_identity_variants(v)
            dst_vars: Set[str] = set()
            for v in dst_ids:
                dst_vars |= process_identity_variants(v)
            pe.parent_vars = src_vars | process_identity_variants(e.get("via_key"))
            pe.child_vars = pe.pid_vars | dst_vars
            pe.all_id_vars = pe.pid_vars | src_vars | dst_vars
            pe.sens_vars = pe.pid_vars | dst_vars

            pe.is_auth = pe.is_persist = pe.is_dropped = False
            if pe.sc in _SENSITIVE_SYSCALLS:
                s_path = path_part(pe.s)
                pe.is_auth = bool(
                    s_path in SENSITIVE_AUTH_PATHS
                    or s_path.endswith("/authorized_keys")
                    or ".ssh/id_" in s_path
                    or s_path.endswith((".env", "wp-config.php", "credentials.ini", "settings.py"))
                )
                pe.is_persist = any(s_path.startswith(p) for p in PERSISTENCE_PREFIXES)
                pe.is_dropped = bool(self.facts.is_tainted(pe.s) and not any(
                    s_path.startswith(p) for p in ("/lib", "/usr/lib", "/proc", "/sys", "/dev")))

            prepared.append(pe)
            self.out[pe.s].append(pe)
            self.inn[pe.d].append(pe)
            self.by_syscall[pe.sc].append(pe)
            self.by_key[pe.key].append(pe)
            for v in pe.parent_vars:
                self.parent_index[v].add(idx)
            for v in pe.child_vars:
                self.child_index[v].add(idx)
            if pe.sc in _SENSITIVE_SYSCALLS:
                for v in pe.sens_vars:
                    self.sens_index[v].add(idx)
        self.edges = prepared

        self.pipe_writers: Dict[str, Set[str]] = defaultdict(set)
        self.pipe_readers: Dict[str, Set[str]] = defaultdict(set)
        for e in self.raw:
            s = str(e.get("src") or "")
            d = str(e.get("dst") or "")
            prog_s = s.split("/")[-1].split(":")[0]
            prog_d = d.split("/")[-1].split(":")[0]
            if d.startswith("pipe:"):
                self.pipe_writers[d].add(prog_s)
            if s.startswith("pipe:"):
                self.pipe_readers[s].add(prog_d)
        self.local_ips = find_local_ips(self.raw)
        self._story_index: Optional[Dict[str, Any]] = None

    @staticmethod
    def _is_pseudo_object(obj: Any) -> bool:
        o = str(obj)
        if o.startswith(PSEUDO_PREFIXES):
            return True
        if o.startswith("/dev/"):
            return (o in PSEUDO_DEV_EXACT) or o.startswith("/dev/pts/") or o.startswith("/dev/fd/")
        return False

    def story_index(self) -> Dict[str, Any]:
        if self._story_index is not None:
            return self._story_index
        idx = {"writers_pid": defaultdict(set), "writers_prog": defaultdict(set),
               "fresh": set(), "local_ip_counts": defaultdict(int)}
        for e in self.raw:
            sc = e.get("syscall")
            if sc in WRITE_SC:
                dst = str(e.get("dst"))
                if not self._is_pseudo_object(dst):
                    idx["fresh"].add(dst)
                if dst.startswith("pipe:"):
                    idx["writers_pid"][dst].add(str(e.get("process_id") or ""))
                    idx["writers_prog"][dst].add(str(e.get("src")).split("/")[-1])
                if sc in ("rename", "symlink"):
                    src = str(e.get("src"))
                    if not self._is_pseudo_object(src):
                        idx["fresh"].add(src)
            for node in (e.get("src"), e.get("dst")):
                for ip in socket_ips(node):
                    if not ip.startswith(("127.", "0.0.")):
                        idx["local_ip_counts"][ip] += 1
        idx["local_ip"] = (max(idx["local_ip_counts"].items(), key=lambda kv: kv[1])[0]
                           if idx["local_ip_counts"] else None)
        self._story_index = idx
        return idx
