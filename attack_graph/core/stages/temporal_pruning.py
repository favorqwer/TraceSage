"""按原始事件的方向和时序剪除无法回溯到告警的待复核边。"""
from __future__ import annotations

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import pickle
import sys
from time import perf_counter
from typing import Any, Iterable

import settings as cfg
from closure.intake import Deps
from closure.neo4j import ReadOnlyGraph
from closure.snapshot import db_fingerprint, snapshot_dir
from core.filters import AUTH_OR_CONFIG, PERSISTENCE_PREFIXES, is_infra_daemon
from core.stages.process_protection import protect
from domain.edge import ALL_RELS, REL_NORM, cypher_rel_match, edge_key
from domain.network import is_loopback_dns_resolver


_PAGE_SIZE = 4_000
_SMALL_QUERY_LIMIT = 20_000
_CACHE_FORMAT = 1
_REAL_READONLY_GRAPH = ReadOnlyGraph

_RETURN_FIELDS = (
    "type(e) AS rel, e.event_id AS eid, elementId(e) AS id, "
    "elementId(src) AS src, elementId(dst) AS dst, "
    "src.host_id AS src_host, dst.host_id AS dst_host, "
    "e.start_ns AS start, e.end_ns AS finish, "
    "e.action AS action, e.result AS result, src.file_type AS src_kind"
)
_EVENT_QUERY = f"""
MATCH (src)-[e]->(dst)
WHERE e.event_id IN $ids AND type(e) IN $relationships
RETURN {_RETURN_FIELDS}
"""
_SMALL_TYPED_QUERY = "\nUNION ALL\n".join(
    f"MATCH (src)-[e:{cypher_rel_match(rel)}]->(dst)\nWHERE e.event_id IN $ids\nRETURN {_RETURN_FIELDS}"
    for rel in ALL_RELS
)


def _intern_opt(value: Any) -> Any:
    return sys.intern(value) if isinstance(value, str) else value


def _row_to_event(row: list[Any]) -> dict[str, Any]:
    return {
        "rel": row[0],
        "eid": row[1],
        "id": row[2],
        "src": row[3],
        "dst": row[4],
        "src_host": row[5],
        "dst_host": row[6],
        "start": row[7],
        "finish": row[8],
        "action": row[9],
        "result": row[10],
        "src_kind": row[11],
    }


def _cache_paths(database: str) -> tuple[Path, Path, Path, Path]:
    base = snapshot_dir(database)
    return (
        base / "temporal_meta.json",
        base / "temporal_events.pkl",
        base / "temporal_meta.json.tmp",
        base / "temporal_events.pkl.tmp",
    )


def _read_cache_meta(meta_path: Path, database: str, fp: dict[str, Any]) -> bool:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - 缺失或损坏视同缓存未命中
        return False
    return (
        int(meta.get("format", 0)) == _CACHE_FORMAT
        and str(meta.get("database") or "") == database
        and (meta.get("edges"), meta.get("max_event_id")) == (fp["edges"], fp["max_event_id"])
    )


def _load_events_from_cache(cache_path: Path, id_set: set[int]) -> list[dict[str, Any]]:
    with cache_path.open("rb") as fh:
        payload = pickle.load(fh)
    nodes: list[str] = payload["nodes"]
    rels: list[str] = payload["rels"]
    packed_events: list[tuple[Any, ...]] = payload["events"]
    events: list[dict[str, Any]] = []
    for rec in packed_events:
        eid = rec[1]
        if eid not in id_set:
            continue
        events.append({
            "rel": rels[rec[0]],
            "eid": eid,
            "id": rec[2],
            "src": nodes[rec[3]],
            "dst": nodes[rec[4]],
            "src_host": rec[5],
            "dst_host": rec[6],
            "start": rec[7],
            "finish": rec[8],
            "action": rec[9],
            "result": rec[10],
            "src_kind": rec[11],
        })
    return events


def _stream_all_typed_events(graph: ReadOnlyGraph) -> list[list[Any]]:
    def fetch_rel(rel: str) -> list[list[Any]]:
        query = f"MATCH (src)-[e:{cypher_rel_match(rel)}]->(dst)\nRETURN {_RETURN_FIELDS}"
        return graph.stream_values(query, log_params=False)

    all_rows: list[list[Any]] = []
    with ThreadPoolExecutor(max_workers=len(ALL_RELS)) as pool:
        for rows in pool.map(fetch_rel, ALL_RELS):
            all_rows.extend(rows)
    return all_rows


def _write_events_cache(database: str, fp: dict[str, Any], rows: list[list[Any]]) -> None:
    meta_path, cache_path, tmp_meta, tmp_cache = _cache_paths(database)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.unlink(missing_ok=True)

    node_ids: dict[str, int] = {}
    nodes: list[str] = []
    rel_ids: dict[str, int] = {}
    rels: list[str] = []
    packed: list[tuple[Any, ...]] = []

    def intern_node(val: Any) -> int:
        key = str(val)
        idx = node_ids.get(key)
        if idx is None:
            idx = len(nodes)
            node_ids[key] = idx
            nodes.append(key)
        return idx

    def intern_rel(val: Any) -> int:
        key = str(val)
        idx = rel_ids.get(key)
        if idx is None:
            idx = len(rels)
            rel_ids[key] = idx
            rels.append(key)
        return idx

    try:
        for row in rows:
            packed.append((
                intern_rel(row[0]),
                row[1],
                str(row[2]),
                intern_node(row[3]),
                intern_node(row[4]),
                _intern_opt(row[5]),
                _intern_opt(row[6]),
                row[7],
                row[8],
                _intern_opt(row[9]),
                row[10],
                _intern_opt(row[11]),
            ))
        with tmp_cache.open("wb") as fh:
            pickle.dump({"nodes": nodes, "rels": rels, "events": packed}, fh, protocol=pickle.HIGHEST_PROTOCOL)
        meta = {
            "format": _CACHE_FORMAT,
            "database": database,
            "edges": fp["edges"],
            "max_event_id": fp["max_event_id"],
            "count": len(packed),
        }
        tmp_meta.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp_cache, cache_path)
        os.replace(tmp_meta, meta_path)
    except BaseException:
        tmp_cache.unlink(missing_ok=True)
        tmp_meta.unlink(missing_ok=True)
        raise


def _fetch_events(graph: Any, database: str, ordered_ids: list[int]) -> list[dict[str, Any]]:
    if not ordered_ids:
        return []
    if type(graph) is not _REAL_READONLY_GRAPH:
        events: list[dict[str, Any]] = []
        for offset in range(0, len(ordered_ids), _PAGE_SIZE):
            events.extend(graph.run(_EVENT_QUERY, {
                "ids": ordered_ids[offset:offset + _PAGE_SIZE], "relationships": list(REL_NORM),
            }))
            if offset == 0 or offset + _PAGE_SIZE >= len(ordered_ids) or offset % (10 * _PAGE_SIZE) == 0:
                print(f"[时序剪枝] 已回查 {min(offset + _PAGE_SIZE, len(ordered_ids))}/{len(ordered_ids)} 个事件编号",
                      flush=True)
        return events

    id_set = set(ordered_ids)
    meta_path, cache_path, _, _ = _cache_paths(database)
    fp = db_fingerprint(graph)
    if cache_path.is_file() and _read_cache_meta(meta_path, database, fp):
        events = _load_events_from_cache(cache_path, id_set)
        print(f"[时序剪枝] 命中本地事件快照缓存，已加载 {len(events)} 条原始事件（目标 {len(ordered_ids)} 个编号）",
              flush=True)
        return events

    if len(ordered_ids) <= _SMALL_QUERY_LIMIT:
        rows = graph.stream_values(_SMALL_TYPED_QUERY, {"ids": ordered_ids}, log_params=False)
        events = [_row_to_event(row) for row in rows]
        print(f"[时序剪枝] 已回查 {len(ordered_ids)}/{len(ordered_ids)} 个事件编号（单遍类型查询）", flush=True)
        return events

    rows = _stream_all_typed_events(graph)
    _write_events_cache(database, fp, rows)
    events = [_row_to_event(row) for row in rows if row[1] in id_set]
    print(f"[时序剪枝] 已单遍流式扫描全库 {len(rows)} 条关系并建立快照缓存，筛选 {len(events)} 条目标事件",
          flush=True)
    return events


_STATELESS_HUBS = frozenset({
    "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full",
    "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
    "/run/systemd/journal/socket", "/var/run/systemd/journal/socket",
    "/run/systemd/journal/stdout", "/var/run/systemd/journal/stdout",
    "/run/systemd/journal/dev-log", "/var/run/systemd/journal/dev-log",
})
_PKG_MANAGER_TOKENS = (
    "/usr/lib/apt/", "/usr/bin/apt", "/usr/bin/dpkg", "/snap/",
    "unattended-upgrade", "update-alternatives", "apt-config", "update-motd",
)
_BG_PKG_DAEMON_TOKENS = ("unattended-upgrade", "update-alternatives", "apt-config", "update-motd")
_SHELL_BINS = frozenset({"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/bin/dash"})
_ACCOUNT_MUT_SYSCALLS = frozenset({"write", "open", "openat", "rename", "creat", "chmod", "chown", "mkdir", "symlink"})
_MUTATING_FILE_SYSCALLS = frozenset({"write", "creat", "create", "truncate", "rename", "unlink", "chmod", "chown", "symlink", "mkdir"})
_SYSTEM_RUNTIME_READ_PREFIXES = (
    "/etc/", "/usr/lib/", "/lib/", "/usr/share/", "/proc/", "/sys/", "/var/log/", "/var/cache/", "/run/",
)


def reachable(events: list[dict], alerts: set[str], *, blocked_nodes: set[str] | None = None) -> set[str]:
    by_id = {event["id"]: event for event in events}
    if not alerts or not alerts <= by_id.keys():
        raise RuntimeError("时序剪枝无法回查全部告警原始关系")
    if any(not event["src_host"] or event["src_host"] != event["dst_host"] for event in events):
        raise RuntimeError("时序剪枝需要主机标识完整且两端同属一台主机")

    incoming = defaultdict(list)
    for event in events:
        incoming[event["dst"]].append(event)
    for candidates in incoming.values():
        candidates.sort(key=lambda event: float("-inf") if event["start"] is None else event["start"])

    visited = set(alerts)
    pending = deque(by_id[key] for key in sorted(alerts))
    cursors: dict[str, int] = {}
    blocked = blocked_nodes or set()
    while pending:
        current = pending.popleft()
        node = current["src"]
        if node in blocked:
            continue
        end = current["finish"] if current["finish"] is not None else float("inf")
        candidates = incoming.get(node, ())
        cursor = cursors.get(node, 0)
        # 入边按开始时间排序，同一实体只检查上次尚未覆盖的区间。
        while cursor < len(candidates):
            previous = candidates[cursor]
            if previous["start"] is not None and previous["start"] > end:
                break
            if previous["id"] not in visited:
                visited.add(previous["id"])
                pending.append(previous)
            cursor += 1
        cursors[node] = cursor
    return visited


def _load_events_and_anchors(
    deps: Deps, confirmed: Iterable[dict], pending: list[dict]
) -> tuple[list[dict], set[str]]:
    poi_rows = deps.record.poi_rows
    if not poi_rows or any(not row.get("relationship_id") for row in poi_rows):
        raise RuntimeError("时序剪枝缺少告警关系标识")
    anchors = {row["relationship_id"] for row in poi_rows}
    ids = {row["event_id"] for row in poi_rows}
    ids.update(eid for edges in (confirmed, pending) for edge in edges for eid in edge.get("event_ids", ()))
    ordered_ids = sorted(ids)
    graph = ReadOnlyGraph(deps.record.database, scenario=deps.record.scenario,
                          run_id=f"{deps.record.run_id}-temporal")
    try:
        events = _fetch_events(graph, deps.record.database, ordered_ids)
    finally:
        graph.close()
    return events, anchors


def prune(pending: list[dict], members: dict[tuple[int, str], list[dict]], visited: set[str]
          ) -> tuple[list[dict], list[dict], int]:
    kept, removed = [], []
    incomplete = 0
    for edge in pending:
        ids = set(edge.get("event_ids", ()))
        relations = {REL_NORM.get(rel) for rel in edge.get("rels", ())}
        matched = [event for eid in ids for rel in relations for event in members.get((eid, rel), ())]
        complete = bool(ids) and None not in relations and {event["eid"] for event in matched} == ids
        if not complete or any(event["id"] in visited or event["start"] is None or event["finish"] is None
                               for event in matched):
            kept.append(edge)
            incomplete += not complete
        else:
            removed.append({**edge, "origin": "excluded",
                            "previous_reason": edge.get("reason") or edge.get("verdict_reason"),
                            "reason": "时序剪枝：全部已核查的原始事件均无法沿候选方向和时序到达告警"})
    return kept, removed, incomplete


def _collect_edge_signals(edges: Iterable[dict]) -> dict[str, set]:
    """从边摘要中抽取基础设施节点、无状态枢纽、包管理器、持久化与变更信号对应的事件 ID。"""
    edge_list = list(edges)
    signals: dict[str, set] = {
        "conf_ids": set(),
        "sup_src_eids": set(),
        "sup_dst_eids": set(),
        "hub_eids": set(),
        "postinst_eids": set(),
        "pkg_eids": set(),
        "bg_pkg_eids": set(),
        "unconf_pkg_file_bridge_eids": set(),
        "persist_eids": set(),
        "ext_net_conf_eids": set(),
        "mut_conf_eids": set(),
        "shell_spawn_conf_eids": set(),
    }
    postinst_tokens = cfg.prune_postinst_tokens()
    written_persist_paths: set[str] = {
        str(edge.get("dst") or "")
        for edge in edge_list
        if str(edge.get("syscall") or "") in _ACCOUNT_MUT_SYSCALLS
        and any(str(edge.get("dst") or "").startswith(px) for px in PERSISTENCE_PREFIXES)
    }
    for edge in edge_list:
        s, d = str(edge.get("src") or ""), str(edge.get("dst") or "")
        sysc = str(edge.get("syscall") or "")
        rels_set = set(edge.get("rels") or ())
        is_conf = edge.get("origin") == "confirmed"
        is_postinst = any(tok in s or tok in d for tok in postinst_tokens)
        is_per_write = sysc in _ACCOUNT_MUT_SYSCALLS and any(d.startswith(px) for px in PERSISTENCE_PREFIXES)
        is_per_read = s in written_persist_paths or d in written_persist_paths
        is_acct_write = is_conf and sysc in _ACCOUNT_MUT_SYSCALLS and (d in AUTH_OR_CONFIG or d.startswith("/home/"))
        is_per = is_per_write or is_per_read or is_acct_write
        is_ext_net = (
            is_conf
            and bool(rels_set & {"p2n", "n2p"})
            and not is_loopback_dns_resolver(s)
            and not is_loopback_dns_resolver(d)
            and not any(lp in (s + d) for lp in ("127.0.0.1", "::1", "localhost"))
        )
        is_mut = is_conf and (
            sysc in ("accept", "accept4", "clone", "fork", "unlink", "rename", "chmod", "mkdir")
            or (sysc == "execve" and s != d and "p2p" in rels_set)
        )
        is_shell_spawn = is_conf and s in _SHELL_BINS and sysc == "execve" and "p2p" in rels_set
        is_pkg = any(tok in s for tok in _PKG_MANAGER_TOKENS) and not is_postinst
        is_bg_pkg = any(tok in s for tok in _BG_PKG_DAEMON_TOKENS) and not is_postinst
        is_unconf_pkg_bridge = (not is_conf) and is_pkg and bool(rels_set & {"p2f"}) and not is_per
        for eid in edge.get("event_ids", ()):
            if is_conf:
                signals["conf_ids"].add(eid)
            if is_infra_daemon(s):
                signals["sup_src_eids"].add(eid)
            if is_infra_daemon(d):
                signals["sup_dst_eids"].add(eid)
            if s in _STATELESS_HUBS:
                signals["hub_eids"].add(("src", eid))
            if d in _STATELESS_HUBS:
                signals["hub_eids"].add(("dst", eid))
            if is_postinst:
                signals["postinst_eids"].add(eid)
            if is_pkg:
                signals["pkg_eids"].add(eid)
            if is_bg_pkg:
                signals["bg_pkg_eids"].add(eid)
            if is_unconf_pkg_bridge:
                signals["unconf_pkg_file_bridge_eids"].add(eid)
            if is_per:
                signals["persist_eids"].add(eid)
            if is_ext_net:
                signals["ext_net_conf_eids"].add(eid)
            if is_mut:
                signals["mut_conf_eids"].add(eid)
            if is_shell_spawn:
                signals["shell_spawn_conf_eids"].add(eid)
    return signals


def _compute_causal_component(
    events: list[dict], anchors: set[str], signals: dict[str, set]
) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    """计算阻塞枢纽后的反向可达集与双向因果失陷进程分量。"""
    sup_nodes: set[str] = set()
    hub_nodes: set[str] = set()
    postinst_nodes: set[str] = set()
    pkg_nodes: set[str] = set()
    bg_nodes: set[str] = set()
    for ev in events:
        eid, rel = ev["eid"], ev["rel"]
        if eid in signals["sup_src_eids"] and rel in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess"):
            sup_nodes.add(ev["src"])
        if eid in signals["sup_dst_eids"] and rel in ("FileToProcess", "NetworkToProcess", "ProcessToProcess"):
            sup_nodes.add(ev["dst"])
        if ("src", eid) in signals["hub_eids"]:
            hub_nodes.add(ev["src"])
        if ("dst", eid) in signals["hub_eids"]:
            hub_nodes.add(ev["dst"])
        if eid in signals["postinst_eids"]:
            if rel in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess"):
                postinst_nodes.add(ev["src"])
            if rel in ("FileToProcess", "NetworkToProcess", "ProcessToProcess"):
                postinst_nodes.add(ev["dst"])
        if eid in signals["pkg_eids"] and rel in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess"):
            pkg_nodes.add(ev["src"])
        if eid in signals["bg_pkg_eids"] and rel in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess"):
            bg_nodes.add(ev["src"])
    pkg_nodes -= postinst_nodes
    bg_nodes -= postinst_nodes

    outgoing_spawn: dict[str, list[dict]] = defaultdict(list)
    exit_children: dict[str, list[dict]] = defaultdict(list)
    file_writers: dict[str, list[dict]] = defaultdict(list)
    file_readers: dict[str, list[dict]] = defaultdict(list)
    conf_ids = signals["conf_ids"]
    for ev in events:
        rel, act = ev["rel"], ev["action"]
        if rel == "ProcessToProcess" and act in ("exec", "clone", "fork", "vfork"):
            outgoing_spawn[ev["src"]].append(ev)
        elif rel == "ProcessToProcess" and act == "exit" and ev["src"] != ev["dst"]:
            exit_children[ev["dst"]].append(ev)
        elif ev["eid"] in conf_ids and rel == "ProcessToFile" and act in ("write", "creat", "create", "rename", "symlink"):
            file_writers[ev["src"]].append(ev)
        elif ev["eid"] in conf_ids and rel == "FileToProcess" and act in ("read", "open", "exec"):
            file_readers[ev["src"]].append(ev)

    pkg_queue = deque(pkg_nodes)
    while pkg_queue:
        pn = pkg_queue.popleft()
        for ev in outgoing_spawn.get(pn, ()):
            dst = ev["dst"]
            if dst not in pkg_nodes and dst not in postinst_nodes and ev["eid"] not in signals["persist_eids"]:
                pkg_nodes.add(dst)
                pkg_queue.append(dst)
        for ev in exit_children.get(pn, ()):
            src = ev["src"]
            if src not in pkg_nodes and src not in postinst_nodes and ev["eid"] not in signals["persist_eids"]:
                pkg_nodes.add(src)
                pkg_queue.append(src)

    bfs_events = [ev for ev in events if ev["eid"] not in signals["unconf_pkg_file_bridge_eids"]]
    visited = reachable(bfs_events, anchors, blocked_nodes=sup_nodes | hub_nodes | bg_nodes)
    by_id = {ev["id"]: ev for ev in events}

    mut_procs: set[str] = set()
    for ev in events:
        if ev["eid"] in signals["mut_conf_eids"]:
            pnode = ev["src"] if ev["rel"] in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess") else ev["dst"]
            mut_procs.add(pnode)
            if ev["rel"] == "ProcessToProcess":
                mut_procs.add(ev["dst"])

    comp_procs: set[str] = set()
    for vid in visited:
        ev = by_id[vid]
        if ev["rel"] in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess") and ev["src"] not in sup_nodes:
            comp_procs.add(ev["src"])
        if ev["rel"] in ("FileToProcess", "NetworkToProcess", "ProcessToProcess") and ev["dst"] not in sup_nodes:
            comp_procs.add(ev["dst"])
    for ev in events:
        if ev["eid"] in signals["persist_eids"]:
            if ev["rel"] in ("ProcessToFile", "ProcessToProcess") and ev["src"] not in sup_nodes:
                comp_procs.add(ev["src"])
            if ev["rel"] == "ProcessToProcess" and ev["dst"] not in sup_nodes:
                comp_procs.add(ev["dst"])
    for ev in events:
        if ev["eid"] in signals["ext_net_conf_eids"]:
            pnode = ev["src"] if ev["rel"] == "ProcessToNetwork" else ev["dst"]
            if pnode not in sup_nodes and pnode not in pkg_nodes and pnode in mut_procs:
                comp_procs.add(pnode)
    for ev in events:
        if ev["eid"] in signals["shell_spawn_conf_eids"] and ev["rel"] == "ProcessToProcess":
            if ev["src"] not in sup_nodes and ev["src"] not in pkg_nodes:
                comp_procs.add(ev["src"])

    fq = deque(comp_procs)
    tainted_files: set[str] = set()
    while fq:
        proc = fq.popleft()
        for ev in outgoing_spawn.get(proc, ()):
            if ev["dst"] not in comp_procs and ev["dst"] not in sup_nodes:
                comp_procs.add(ev["dst"])
                fq.append(ev["dst"])
        for ev in exit_children.get(proc, ()):
            if ev["src"] not in comp_procs and ev["src"] not in sup_nodes:
                comp_procs.add(ev["src"])
                fq.append(ev["src"])
        for ev in file_writers.get(proc, ()):
            target = ev["dst"]
            if target not in tainted_files and target not in hub_nodes:
                tainted_files.add(target)
                for rev in file_readers.get(target, ()):
                    if ev["start"] is None or rev["finish"] is None or ev["start"] <= rev["finish"]:
                        if rev["dst"] not in comp_procs and rev["dst"] not in sup_nodes:
                            comp_procs.add(rev["dst"])
                            fq.append(rev["dst"])

    keep_ev = set(visited)
    comp_pipes: set[str] = set()
    for ev in events:
        if ev["eid"] in conf_ids and (
            (ev["rel"] in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess") and ev["src"] in comp_procs)
            or (ev["rel"] in ("FileToProcess", "NetworkToProcess", "ProcessToProcess") and ev["dst"] in comp_procs)
        ):
            keep_ev.add(ev["id"])
            if ev["rel"] == "ProcessToFile" and ev["src"] in comp_procs:
                comp_pipes.add(ev["dst"])
    return visited, comp_procs, pkg_nodes, keep_ev, comp_pipes


def _is_unexcluded_causal(
    edge: dict,
    ev: dict,
    visited: set[str],
    comp_procs: set[str],
    pkg_nodes: set[str],
    comp_pipes: set[str],
) -> bool:
    if ev["start"] is None or ev["finish"] is None:
        return True
    pnode = ev["src"] if ev["rel"] in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess") else ev["dst"]
    other = ev["dst"] if ev["rel"] in ("ProcessToFile", "ProcessToNetwork", "ProcessToProcess") else ev["src"]
    if ev["id"] in visited:
        return (pnode in comp_procs) or (ev["dst"] in comp_procs) or (other in comp_pipes)
    if pnode in comp_procs and pnode not in pkg_nodes:
        sysc = str(edge.get("syscall") or "")
        if ev["rel"] == "ProcessToProcess" and sysc in ("execve", "clone", "fork"):
            return True
        if ev["rel"] in ("ProcessToNetwork", "NetworkToProcess"):
            return True
        if ev["rel"] in ("ProcessToFile", "FileToProcess"):
            src_s, dst_s = str(edge.get("src", "")), str(edge.get("dst", ""))
            if ev["rel"] == "ProcessToFile" and sysc in _MUTATING_FILE_SYSCALLS:
                return True
            if src_s in AUTH_OR_CONFIG or dst_s in AUTH_OR_CONFIG:
                return True
            return not any(px in (src_s + dst_s) for px in _SYSTEM_RUNTIME_READ_PREFIXES)
    return False


def run_bidirectional(
    deps: Deps,
    confirmed_map: dict[tuple[Any, Any, Any], dict[str, Any]],
    pending: list[dict],
) -> tuple[dict[tuple[Any, Any, Any], dict[str, Any]], list[dict], list[dict], dict[str, Any]]:
    """联合对已确认集与待复核集执行双向因果连通分量与时序保护剪枝。"""
    started = perf_counter()
    all_edges = list(confirmed_map.values()) + list(pending)
    events, anchors = _load_events_and_anchors(deps, confirmed_map.values(), pending)
    signals = _collect_edge_signals(all_edges)
    visited, comp_procs, pkg_nodes, keep_ev, comp_pipes = _compute_causal_component(events, anchors, signals)

    members = defaultdict(list)
    for event in events:
        members[event["eid"], REL_NORM[event["rel"]]].append(event)

    kept_conf_map: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    rem_conf: list[dict] = []
    kept_unex: list[dict] = []
    rem_unex: list[dict] = []
    incomplete = 0

    for key, edge in confirmed_map.items():
        if edge.get("class") == "anchor":
            kept_conf_map[key] = edge
            continue
        ids = set(edge.get("event_ids", ()))
        relations = {REL_NORM.get(rel) for rel in edge.get("rels", ())}
        matched = [event for eid in ids for rel in relations for event in members.get((eid, rel), ())]
        complete = bool(ids) and None not in relations and {event["eid"] for event in matched} == ids
        if not complete or any(
            ev["id"] in keep_ev or ev["eid"] in signals["persist_eids"] or ev["start"] is None or ev["finish"] is None
            for ev in matched
        ):
            kept_conf_map[key] = edge
            incomplete += not complete
        else:
            rem_conf.append({
                **edge,
                "origin": "excluded",
                "previous_reason": edge.get("reason") or edge.get("verdict_reason"),
                "reason": "因果连通剪枝：已确认边缘孤立组件，既不在告警可达链上也无持久化或受损派生关联",
            })

    for edge in pending:
        ids = set(edge.get("event_ids", ()))
        relations = {REL_NORM.get(rel) for rel in edge.get("rels", ())}
        matched = [event for eid in ids for rel in relations for event in members.get((eid, rel), ())]
        complete = bool(ids) and None not in relations and {event["eid"] for event in matched} == ids
        if not complete or any(
            _is_unexcluded_causal(edge, ev, visited, comp_procs, pkg_nodes, comp_pipes) for ev in matched
        ):
            kept_unex.append(edge)
            incomplete += not complete
        else:
            rem_unex.append({
                **edge,
                "origin": "excluded",
                "previous_reason": edge.get("reason") or edge.get("verdict_reason"),
                "reason": "时序剪枝：全部已核查原始事件均未落在双向因果可达分量内",
            })

    protected_conf: list[dict] = []
    protected_unex: list[dict] = []
    if rem_conf or rem_unex:
        finishes = [event["finish"] for event in events if event["id"] in anchors]
        if any(finish is None for finish in finishes):
            raise RuntimeError("进程保护缺少告警结束时间")
        max_finish = max(finishes)
        kept_conf_seed = list(kept_conf_map.values())
        if rem_conf:
            protected_conf, rem_conf = protect(kept_conf_seed, rem_conf, members, max_finish)
            for edge in protected_conf:
                kept_conf_map[edge_key(edge)] = {**edge, "origin": "confirmed"}
        if rem_unex:
            protected_unex, rem_unex = protect(list(kept_conf_map.values()), rem_unex, members, max_finish)
            kept_unex.extend(protected_unex)

    removed = rem_conf + rem_unex
    protected_total = len(protected_conf) + len(protected_unex)
    stats = {
        "seconds": round(perf_counter() - started, 3),
        "removed_edges": len(removed),
        "removed_confirmed_edges": len(rem_conf),
        "removed_pending_edges": len(rem_unex),
        "protected_edges": protected_total,
        "matched_events": len(events),
        "reachable_events": len(visited),
        "alert_events": len(anchors),
        "kept_incomplete_edges": incomplete,
    }
    print(
        f"[时序剪枝] 移除 {len(rem_conf)} 条孤立已确认边与 {len(rem_unex)} 条待复核边，"
        f"保护 {protected_total} 条，耗时 {stats['seconds']:.1f} 秒",
        flush=True,
    )
    return kept_conf_map, kept_unex, removed, stats


def run(deps: Deps, confirmed: Iterable[dict], pending: list[dict]
        ) -> tuple[list[dict], list[dict], dict[str, Any]]:
    started = perf_counter()
    confirmed = list(confirmed)
    events, anchors = _load_events_and_anchors(deps, confirmed, pending)

    visited = reachable(events, anchors)
    members = defaultdict(list)
    for event in events:
        members[event["eid"], REL_NORM[event["rel"]]].append(event)
    kept, removed, incomplete = prune(pending, members, visited)
    protected = []
    if removed:
        finishes = [event["finish"] for event in events if event["id"] in anchors]
        if any(finish is None for finish in finishes):
            raise RuntimeError("进程保护缺少告警结束时间")
        protected, removed = protect(confirmed, removed, members, max(finishes))
    kept.extend(protected)
    stats = {"seconds": round(perf_counter() - started, 3), "removed_edges": len(removed),
             "protected_edges": len(protected),
             "matched_events": len(events), "reachable_events": len(visited),
             "alert_events": len(anchors), "kept_incomplete_edges": incomplete}
    print(f"[时序剪枝] 移除 {len(removed)} 条待复核边，保护 {len(protected)} 条，"
          f"耗时 {stats['seconds']:.1f} 秒", flush=True)
    return kept, removed, stats
