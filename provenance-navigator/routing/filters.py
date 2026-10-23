"""路由管线的剪枝阶段：前置静态只读初筛 + 后置因果碎片剪枝。

- `PreFilter`：把无前序污染、无交付的静态系统读取移入未排除。
- `DebrisPrune`：把包管理内部碎片、死端认证读取、本地 DNS 伪连接等从确认集移入未排除；
  包管理器名单与临时路径从 `config/navigator.toml` 的 `[prune]` 读取。

所有被移出的边一律进未排除，不删除。本模块不导入 `rules`、`llm`、`closure`。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from common import config as cfg
from common.facts import (
    PSEUDO_PREFIXES as FACT_PSEUDO_PREFIXES,
    SENSITIVE_AUTH_PATHS,
    TopologyFacts,
    is_loopback_dns_resolver,
)
from common.graph import edge_key, process_identity_variants

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


class PreFilter:
    """前置初筛：静态只读、无污染、无交付的系统读取。"""

    def __init__(self, topology_facts: TopologyFacts):
        self.tf = topology_facts

    def apply(self, edges: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        kept: List[Dict[str, Any]] = []
        moved: List[Dict[str, Any]] = []
        prefixes = (
            "/proc/", "/sys/", "/lib/", "/usr/lib/", "/usr/share/",
            "/etc/ld.so.", "/etc/locale", "/usr/include/", "/dev/urandom", "/dev/null",
        )
        for e in edges:
            sc = e.get("syscall", "")
            src = str(e.get("src", ""))
            if sc == "read" and any(src.startswith(p) for p in prefixes):
                if not self.tf.is_tainted(src):
                    rec = dict(e)
                    rec["origin"] = "kept"
                    rec["reason"] = "因果初筛：系统只读静态资源且无前序写入污染，归入未排除"
                    moved.append(rec)
                    continue
            kept.append(e)
        return kept, moved


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
                    if "/" in node and not node.startswith("unix:"):
                        self.poi_dirs.add("/".join(node.split("/")[:-1]))

    def is_operational_debris(self, edge: Dict[str, Any]) -> bool:
        s = str(edge.get("src", ""))
        d = str(edge.get("dst", ""))
        sc = str(edge.get("syscall", ""))
        prog_s = s.split("/")[-1]

        if sc == "execve" or any(tok in s or tok in d for tok in cfg.prune_postinst_tokens()):
            return False
        if any(d.startswith(p_dir) for p_dir in self.poi_dirs if len(p_dir) > 4):
            return False
        if prog_s in cfg.prune_managers():
            if any(sink in d for sink in cfg.prune_internal_sinks()) or d.startswith("pipe:"):
                return True
            if any(sink in d for sink in cfg.prune_internal_sinks()):
                return True
        if prog_s == "apt-get" and sc in ("read", "write"):
            if any(d.startswith(p) for p in ("/var/lib/apt/", "/var/cache/apt/", "pipe:")):
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


# 兼容旧类名
CausalFilter = PreFilter
CausalPivotRouter = DebrisPrune
