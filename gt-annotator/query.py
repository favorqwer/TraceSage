"""Read-only queries: schema, edges, process tree/activity, summary."""

from __future__ import annotations

import argparse
import json
from typing import Any

from common import dumps, fail
from db import DB
from facts import (
    EDGE_REQUIRED,
    FILE_REQUIRED,
    LEGACY_PROPS,
    NETWORK_OPTIONAL,
    NETWORK_REQUIRED,
    PROCESS_OPTIONAL,
    PROCESS_REQUIRED,
    REL_TYPES,
    _local_tz,
    db_bounds_ns,
    edge_key_of,
    edge_row,
    fetch_edge,
    node_key,
    ns_info,
    parse_clock_ns,
    process_instance_key,
    process_summary,
    rel_summary,
    resolve_time_args,
)


def _schema_snapshot(db: DB) -> dict[str, Any]:
    """Two scans: one over nodes, one over relationships; samples stay separate."""
    counts: dict[str, int] = {label: 0 for label in ("Process", "File", "Network")}
    for rel in REL_TYPES:
        counts[rel] = 0
    file_type: dict[str, int] = {}
    proto: dict[str, int] = {}
    rows = db.run(
        "MATCH (n) WHERE n:Process OR n:File OR n:Network "
        "RETURN CASE WHEN n:Process THEN 'Process' "
        "WHEN n:File THEN 'File' ELSE 'Network' END AS label, "
        "CASE WHEN n:File THEN n.file_type "
        "WHEN n:Network THEN n.proto END AS k, "
        "count(*) AS n"
    )
    for row in rows:
        label = str(row["label"])
        count = int(row["n"])
        counts[label] = counts.get(label, 0) + count
        if label == "File":
            key = str(row["k"])
            file_type[key] = file_type.get(key, 0) + count
        elif label == "Network":
            key = str(row["k"])
            proto[key] = proto.get(key, 0) + count

    actions: dict[str, int] = {}
    time_range: dict[str, Any] = {}
    rows = db.run(
        "MATCH ()-[r]->() "
        "WITH type(r) AS rel, r.action AS action, r.start_ns AS t "
        "WITH rel, action, count(*) AS n, min(t) AS t0, max(t) AS t1 "
        "WITH collect({rel: rel, action: action, n: n}) AS rows, "
        "min(t0) AS min_t, max(t1) AS max_t "
        "RETURN rows, min_t, max_t"
    )
    if rows:
        for item in rows[0].get("rows") or []:
            rel = str(item["rel"])
            count = int(item["n"])
            counts[rel] = counts.get(rel, 0) + count
            action = str(item["action"])
            actions[action] = actions.get(action, 0) + count
        t0, t1 = rows[0].get("min_t"), rows[0].get("max_t")
        if t0 is not None:
            time_range = {"min_start_ns": t0, "max_start_ns": t1,
                          "min": ns_info(t0), "max": ns_info(t1)}
    return {"counts": counts, "actions": actions, "file_type": file_type,
            "proto": proto, "time_range": time_range}


def cmd_schema(db: DB, args: argparse.Namespace) -> None:
    out: dict[str, Any] = {"db": db.name, "ok": True, "errors": [], "warnings": [],
                           "counts": {}, "properties": {}}
    snapshot = _schema_snapshot(db)
    out["counts"] = snapshot["counts"]
    for label, required, optional in (
        ("Process", PROCESS_REQUIRED, PROCESS_OPTIONAL),
        ("File", FILE_REQUIRED, set()),
        ("Network", NETWORK_REQUIRED, NETWORK_OPTIONAL),
    ):
        count = int(out["counts"].get(label, 0))
        if count == 0:
            out["warnings"].append(f"{label} 节点为 0")
            continue
        sample = db.run(f"MATCH (n:{label}) RETURN keys(n) AS keys LIMIT 1")
        keys = set(sample[0]["keys"]) if sample else set()
        out["properties"][label] = sorted(keys)
        missing = sorted(required - keys)
        if missing:
            out["errors"].append(f"{label} 缺必需属性：{missing}")
        if label == "Process" and "exe_path" not in keys:
            out["warnings"].append("Process 没有 exe_path 属性（可能全是未知程序）")
        legacy = sorted(keys & LEGACY_PROPS)
        if legacy:
            out["warnings"].append(f"{label} 出现旧 schema 属性：{legacy}")
    for rel in REL_TYPES:
        count = int(out["counts"].get(rel, 0))
        if count == 0:
            out["warnings"].append(f"{rel} 边为 0")
            continue
        sample = db.run(f"MATCH ()-[r:{rel}]->() RETURN keys(r) AS keys LIMIT 1")
        keys = set(sample[0]["keys"]) if sample else set()
        out["properties"][rel] = sorted(keys)
        missing = sorted(EDGE_REQUIRED - keys)
        if missing:
            out["errors"].append(f"{rel} 缺必需属性：{missing}")
        legacy = sorted(keys & LEGACY_PROPS)
        if legacy:
            out["warnings"].append(f"{rel} 出现旧 schema 属性：{legacy}")
    out["stats"] = {
        "actions": dict(sorted(snapshot["actions"].items(),
                               key=lambda item: -item[1])),
        "file_type": dict(sorted(snapshot["file_type"].items(),
                                 key=lambda item: -item[1])),
        "proto": dict(sorted(snapshot["proto"].items(),
                             key=lambda item: -item[1])),
        "time_range": snapshot["time_range"],
    }
    out["ok"] = not out["errors"]
    print(dumps(out))
    if not out["ok"]:
        raise SystemExit(1)



def _enrich_rename_and_link(db: DB, row: dict[str, Any]) -> None:
    fact = row.get("fact") or {}
    ev = row.get("evidence") or {}
    ctx = row.setdefault("context", {})
    act = fact.get("action")
    if act == "rename":
        ev_id = ev.get("event_id")
        if ev_id is not None:
            rows = db.run(
                "MATCH (a)-[r]->(b) WHERE r.event_id = $ev AND r.action = 'rename' "
                "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst LIMIT 5",
                ev=ev_id,
            )
            for r_item in rows:
                p_rel = str(r_item["rel_type"])
                p_edge = r_item["edge"]
                if p_rel != row.get("edge_type") or str(p_edge.get("start_ns")) != str(ev.get("start_ns")):
                    direction = "读旧路径端 (FileToProcess)" if p_rel == "FileToProcess" else "写新路径端 (ProcessToFile)"
                    file_path = r_item["src"].get("path") if p_rel == "FileToProcess" else r_item["dst"].get("path")
                    ctx["paired_rename_edge"] = {
                        "edge_key": f"{p_rel}:{p_edge.get('event_id')}:{p_edge.get('action')}",
                        "rel_type": p_rel,
                        "direction": direction,
                        "file_path": file_path,
                        "note": "rename 系统调用在底层图拆分为读旧路径与写新路径两条边；此为配对的另一端边",
                    }
                    break
    if act in ("link", "symlink") or ctx.get("to_path"):
        if ctx.get("to_path"):
            ctx["to_path_annotation"] = "边属性 to_path（目标路径），Neo4j 图中不建立独立文件节点边"

def cmd_edges(db: DB, args: argparse.Namespace) -> None:
    if getattr(args, "edge_key", None):
        _, row = fetch_edge(db, args.edge_key)
        _enrich_rename_and_link(db, row)
        print(dumps(row))
        return
    resolve_time_args(db, args)
    where, params = edge_filter(args)
    count_rows = db.run(f"MATCH (a)-[r]->(b) WHERE {where} RETURN count(*) AS n",
                        **params)
    total = int(count_rows[0]["n"]) if count_rows else 0
    if args.count:
        print(dumps({"db": db.name, "total": total}))
        return
    order = ""
    if args.order == "time":
        direction = "DESC" if args.desc else "ASC"
        order = (f"ORDER BY r.start_ns {direction}, r.event_id {direction}, "
                 f"r.action {direction}")
    elif args.order == "event":
        direction = "DESC" if args.desc else "ASC"
        order = f"ORDER BY r.event_id {direction}, r.action {direction}"
    cypher = (
        "MATCH (a)-[r]->(b) "
        f"WHERE {where} "
        "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst "
        f"{order} SKIP $offset LIMIT $limit"
    )
    rows = db.run(cypher, offset=args.offset, limit=args.limit, **params)
    result = [edge_row(r) for r in rows]
    for r_item in result[:100]:
        _enrich_rename_and_link(db, r_item)
    if args.jsonl:
        for row in result:
            print(json.dumps(row, ensure_ascii=False, default=str))
        return
    has_more = args.offset + len(result) < total
    out: dict[str, Any] = {
        "db": db.name,
        "total": total,
        "returned": len(result),
        "offset": args.offset,
        "limit": args.limit,
        "has_more": has_more,
        "rows": result,
    }
    if has_more:
        remaining = total - (args.offset + len(result))
        out["truncation"] = {
            "is_truncated": True,
            "remaining_count": remaining,
            "next_offset": args.offset + len(result),
            "warning": f"结果被截断：当前返回 {len(result)} 条，仍有 {remaining} 条边未展示（总计 {total} 条）。",
            "suggestion": (
                "若该操作为关键确定性步骤（<=20条），可调大 --limit 或递增 --offset 获取后续；"
                "若该操作为批量并发/高频动作（>50条），请改用 summary 按 action 聚合观察，并归为 Possible 规则边，严禁全量展开导致上下文爆炸。"
            ),
        }
    print(dumps(out))


def _endpoint_groups(args: argparse.Namespace) -> list[tuple[str, str]]:
    """Return endpoint groups; filters of different types must hit different ends."""
    groups: list[tuple[str, str]] = []
    proc: list[str] = []
    if args.pid is not None:
        cond = "{alias}.pid = $pid"
        if args.start_ns is not None:
            cond += " AND {alias}.start_ns = $proc_start"
        proc.append(cond)
    if args.exe is not None:
        proc.append("{alias}.exe_path = $exe")
    if args.exe_null:
        proc.append("coalesce({alias}.exe_path, '') = ''")
    if getattr(args, "cmdline", None) is not None:
        proc.append("{alias}.cmdline = $cmdline")
    if getattr(args, "cmdline_contains", None) is not None:
        proc.append("{alias}.cmdline CONTAINS $cmdline_contains")
    if getattr(args, "uid", None) is not None:
        proc.append("toString({alias}.uid) = $uid")
    if getattr(args, "euid", None) is not None:
        proc.append("toString({alias}.euid) = $euid")
    if getattr(args, "ppid", None) is not None:
        proc.append("{alias}.ppid = $ppid")
    if proc:
        groups.append(("Process", " AND ".join(proc)))
    files: list[str] = []
    if args.path is not None:
        files.append("{alias}.path = $path")
    if args.path_prefix is not None:
        files.append("{alias}.path STARTS WITH $path_prefix")
    if getattr(args, "path_suffix", None) is not None:
        files.append("{alias}.path ENDS WITH $path_suffix")
    if getattr(args, "path_contains", None) is not None:
        files.append("{alias}.path CONTAINS $path_contains")
    if getattr(args, "file_type", None) is not None:
        files.append("{alias}.file_type = $file_type")
    if files:
        groups.append(("File", " AND ".join(files)))
    if args.endpoint is not None:
        groups.append(("Network", "{alias}.endpoints = $endpoint"))
    if getattr(args, "port", None) is not None:
        groups.append(("Network",
                       "({alias}.endpoints CONTAINS (':' + toString($port) + '->') "
                       "OR {alias}.endpoints ENDS WITH (':' + toString($port)))"))
    return groups

def basic_filter(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    where: list[str] = []
    params: dict[str, Any] = {}
    if args.from_ns is not None:
        where.append("r.start_ns >= $from_ns")
        params["from_ns"] = args.from_ns
    if args.to_ns is not None:
        where.append("r.start_ns <= $to_ns")
        params["to_ns"] = args.to_ns
    if args.rel:
        rels = [x.strip() for x in args.rel.split(",") if x.strip()]
        unknown = [r for r in rels if r not in REL_TYPES]
        if unknown:
            fail(f"未知关系类型：{unknown}；可选 {REL_TYPES}")
        where.append("type(r) IN $rels")
        params["rels"] = rels
    if args.action:
        actions = [x.strip() for x in args.action.split(",") if x.strip()]
        if actions:
            where.append("r.action IN $actions")
            params["actions"] = actions
    if args.syscall:
        calls = [x.strip() for x in args.syscall.split(",") if x.strip()]
        if calls:
            where.append("r.syscall IN $syscalls")
            params["syscalls"] = calls
    host_id = getattr(args, "host_id", None)
    container_id = getattr(args, "container_id", None)
    if host_id:
        where.append("(a.host_id = $host_id OR b.host_id = $host_id)")
        params["host_id"] = host_id
    if container_id:
        where.append("(a.container_id = $container_id OR b.container_id = $container_id)")
        params["container_id"] = container_id
    return (" AND ".join(where) if where else "true"), params

def edge_filter(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    where: list[str] = []
    params: dict[str, Any] = {}
    if args.from_ns is not None:
        where.append("r.start_ns >= $from_ns")
        params["from_ns"] = args.from_ns
    if args.to_ns is not None:
        where.append("r.start_ns <= $to_ns")
        params["to_ns"] = args.to_ns
    if args.rel:
        rels = [x.strip() for x in args.rel.split(",") if x.strip()]
        unknown = [r for r in rels if r not in REL_TYPES]
        if unknown:
            fail(f"未知关系类型：{unknown}；可选 {REL_TYPES}")
        where.append("type(r) IN $rels")
        params["rels"] = rels
    if args.action:
        actions = [x.strip() for x in args.action.split(",") if x.strip()]
        if actions:
            where.append("r.action IN $actions")
            params["actions"] = actions
    if args.syscall:
        calls = [x.strip() for x in args.syscall.split(",") if x.strip()]
        if calls:
            where.append("r.syscall IN $syscalls")
            params["syscalls"] = calls
    if args.pid is not None:
        params["pid"] = args.pid
        if args.start_ns is not None:
            params["proc_start"] = args.start_ns
    if args.exe is not None:
        params["exe"] = args.exe
    if args.path is not None:
        params["path"] = args.path
    if args.path_prefix is not None:
        params["path_prefix"] = args.path_prefix
    if args.endpoint is not None:
        params["endpoint"] = args.endpoint
    if getattr(args, "file_type", None) is not None:
        params["file_type"] = args.file_type
    for name in ("cmdline", "cmdline_contains", "uid", "euid", "ppid",
                 "path_suffix", "path_contains", "port"):
        value = getattr(args, name, None)
        if value is not None:
            params[name] = value
    if getattr(args, "to_path", None) is not None:
        where.append("r.to_path = $to_path")
        params["to_path"] = args.to_path
    if getattr(args, "to_path_prefix", None) is not None:
        where.append("r.to_path STARTS WITH $to_path_prefix")
        params["to_path_prefix"] = args.to_path_prefix
    if getattr(args, "host_id", None):
        where.append("(a.host_id = $host_id OR b.host_id = $host_id)")
        params["host_id"] = args.host_id
    if getattr(args, "container_id", None):
        where.append("(a.container_id = $container_id OR b.container_id = $container_id)")
        params["container_id"] = args.container_id
    # 显式源端/目标端进程条件过滤
    src_conds = []
    if getattr(args, "src_exe", None):
        src_conds.append("a:Process AND a.exe_path = $src_exe")
        params["src_exe"] = args.src_exe
    if getattr(args, "src_pid", None) is not None:
        src_conds.append("a:Process AND a.pid = $src_pid")
        params["src_pid"] = args.src_pid
    if getattr(args, "src_cmdline", None):
        src_conds.append("a:Process AND a.cmdline = $src_cmdline")
        params["src_cmdline"] = args.src_cmdline
    if getattr(args, "src_cmdline_contains", None):
        src_conds.append("a:Process AND a.cmdline CONTAINS $src_cmdline_contains")
        params["src_cmdline_contains"] = args.src_cmdline_contains

    dst_conds = []
    if getattr(args, "dst_exe", None):
        dst_conds.append("b:Process AND b.exe_path = $dst_exe")
        params["dst_exe"] = args.dst_exe
    if getattr(args, "dst_pid", None) is not None:
        dst_conds.append("b:Process AND b.pid = $dst_pid")
        params["dst_pid"] = args.dst_pid
    if getattr(args, "dst_cmdline", None):
        dst_conds.append("b:Process AND b.cmdline = $dst_cmdline")
        params["dst_cmdline"] = args.dst_cmdline
    if getattr(args, "dst_cmdline_contains", None):
        dst_conds.append("b:Process AND b.cmdline CONTAINS $dst_cmdline_contains")
        params["dst_cmdline_contains"] = args.dst_cmdline_contains

    if src_conds:
        where.append("(" + " AND ".join(src_conds) + ")")
    if dst_conds:
        where.append("(" + " AND ".join(dst_conds) + ")")

    groups = _endpoint_groups(args)
    if len(groups) > 2:
        fail("一条边只有两个端点，最多同时过滤两类端点（process/file/network）")
    if len(groups) == 1:
        label, cond = groups[0]
        where.append(
            f"((a:{label} AND {cond.format(alias='a')}) "
            f"OR (b:{label} AND {cond.format(alias='b')}))"
        )
    elif len(groups) == 2:
        (label1, cond1), (label2, cond2) = groups
        where.append(
            f"(((a:{label1} AND {cond1.format(alias='a')}) "
            f"AND (b:{label2} AND {cond2.format(alias='b')})) "
            f"OR ((a:{label2} AND {cond2.format(alias='a')}) "
            f"AND (b:{label1} AND {cond1.format(alias='b')})))"
        )
    if args.result_sign == "success":
        where.append("(r.result IS NULL OR r.result >= 0)")
    elif args.result_sign == "failure":
        where.append("r.result < 0")
    return (" AND ".join(where) if where else "true"), params

def cmd_time(db: DB, args: argparse.Namespace) -> None:
    t0, t1 = db_bounds_ns(db)
    out: dict[str, Any] = {
        "db": db.name,
        "time_range": {"min": ns_info(t0), "max": ns_info(t1)},
        "timezone": str(_local_tz()),
    }
    if args.clock:
        ns = parse_clock_ns(db, args.clock, args.date)
        out["clock"] = args.clock
        out["resolved"] = ns_info(ns)
    print(dumps(out))

def _collect_tree(db: DB, pid: int, start_ns: int, direction: str, depth: int,
                  host_id: str | None = None, container_id: str | None = None) -> dict[str, Any]:
    where = ["p.pid = $pid", "p.start_ns = $start_ns"]
    params: dict[str, Any] = {"pid": pid, "start_ns": start_ns}
    if host_id:
        where.append("p.host_id = $host_id")
        params["host_id"] = host_id
    if container_id:
        where.append("p.container_id = $container_id")
        params["container_id"] = container_id
    rows = db.run("MATCH (p:Process) WHERE " + " AND ".join(where) +
                  " RETURN p LIMIT 5", **params)
    if not rows:
        fail("找不到这个进程实例；请检查 pid/start_ns/host/container")
    if len(rows) > 1:
        candidates = [node_key(r["p"]) for r in rows]
        fail(f"进程实例不唯一，请加 --host-id/--container-id：{candidates}")
    root = rows[0]["p"]
    root_key = process_instance_key(root)
    nodes: dict[str, dict[str, Any]] = {root_key: process_summary(root)}
    edges: dict[str, dict[str, Any]] = {}
    seen = {root_key}
    frontier = [root]
    max_nodes = 500
    truncated = False
    for _ in range(max(1, depth)):
        nxt: list[Any] = []
        frontier_rows = [
            {"h": dict(node).get("host_id"),
             "c": dict(node).get("container_id"),
             "p": dict(node).get("pid"),
             "s": dict(node).get("start_ns")}
            for node in frontier
        ]
        if direction == "up":
            cypher = (
                "UNWIND $frontier AS x "
                "MATCH (parent:Process)-[r:ProcessToProcess]->(child:Process) "
                "WHERE child.host_id = x.h AND child.container_id = x.c "
                "AND child.pid = x.p AND child.start_ns = x.s "
                "AND r.action IN ['clone','exec'] "
                "RETURN parent, r, child LIMIT $limit"
            )
        else:
            cypher = (
                "UNWIND $frontier AS x "
                "MATCH (parent:Process)-[r:ProcessToProcess]->(child:Process) "
                "WHERE parent.host_id = x.h AND parent.container_id = x.c "
                "AND parent.pid = x.p AND parent.start_ns = x.s "
                "AND r.action IN ['clone','exec'] "
                "RETURN parent, r, child LIMIT $limit"
            )
        level = db.run(cypher, frontier=frontier_rows,
                       limit=max(1, max_nodes - len(nodes) + 1))
        for rec in level:
            parent = rec["parent"]
            child = rec["child"]
            rel = rec["r"]
            pkey = process_instance_key(parent)
            ckey = process_instance_key(child)
            akey = pkey if direction == "up" else ckey
            if akey not in seen:
                seen.add(akey)
                nodes[akey] = process_summary(parent if direction == "up" else child)
                nxt.append(parent if direction == "up" else child)
                if len(nodes) >= max_nodes:
                    truncated = True
            ek = edge_key_of("ProcessToProcess", rel)
            if ek not in edges:
                edges[ek] = rel_summary("ProcessToProcess", rel, parent, child)
            for extra in (parent, child):
                extra_key = process_instance_key(extra)
                if extra_key not in nodes:
                    nodes[extra_key] = process_summary(extra)
        if truncated or not nxt:
            break
        frontier = nxt
    return {
        "root": root_key,
        "root_program_key": node_key(root),
        "direction": direction,
        "depth": depth,
        "truncated": truncated,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
    }

def cmd_tree(db: DB, args: argparse.Namespace) -> None:
    tree = _collect_tree(db, args.pid, args.start_ns, args.direction, args.depth,
                         args.host_id, args.container_id)
    print(dumps({"db": db.name, **tree}))

def parse_process_instance_key(key: str) -> dict[str, Any]:
    if not key.startswith("p:"):
        fail(f"不是进程实例 key：{key!r}")
    scope, content = key[2:].split(":", 1)
    host, container = scope.split("/", 1)
    pid_text, start_text = content.split("@", 1)
    return {"h": host, "c": container,
            "p": int(pid_text), "s": int(start_text)}

def cmd_activity(db: DB, args: argparse.Namespace) -> None:
    resolve_time_args(db, args)
    tree = _collect_tree(db, args.pid, args.start_ns, args.direction, args.depth,
                         args.host_id, args.container_id)
    procs = []
    for node in tree["nodes"]:
        try:
            procs.append(parse_process_instance_key(str(node["key"])))
        except Exception:
            continue
    if not procs:
        fail("进程树为空，无法查活动")
    where: list[str] = []
    params: dict[str, Any] = {"procs": procs, "limit": args.limit + 1}
    if args.from_ns is not None:
        where.append("r.start_ns >= $from_ns")
        params["from_ns"] = args.from_ns
    if args.to_ns is not None:
        where.append("r.start_ns <= $to_ns")
        params["to_ns"] = args.to_ns
    tw = (" AND ".join(where) + " AND ") if where else ""
    out_cypher = (
        "UNWIND $procs AS x "
        "MATCH (a:Process {host_id: x.h, container_id: x.c, pid: x.p, start_ns: x.s})-[r]->(b) "
        f"WHERE {tw} true "
        "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst "
        "ORDER BY r.start_ns ASC LIMIT $limit"
    )
    in_cypher = (
        "UNWIND $procs AS x "
        "MATCH (a)-[r]->(b:Process {host_id: x.h, container_id: x.c, pid: x.p, start_ns: x.s}) "
        f"WHERE {tw} true "
        "RETURN type(r) AS rel_type, r AS edge, a AS src, b AS dst "
        "ORDER BY r.start_ns ASC LIMIT $limit"
    )
    records = db.run(out_cypher, **params) + db.run(in_cypher, **params)
    rows: dict[str, dict[str, Any]] = {}
    for rec in records:
        row = edge_row(rec)
        rows.setdefault(row["edge_key"], row)
    ordered = sorted(rows.values(),
                     key=lambda r: (r["evidence"].get("start_ns") or 0,
                                    r["edge_key"]))
    truncated = len(ordered) > args.limit or tree["truncated"]
    act_out: dict[str, Any] = {
        "db": db.name,
        "root": tree["root"],
        "root_program_key": tree["root_program_key"],
        "direction": tree["direction"],
        "depth": tree["depth"],
        "process_count": len(procs),
        "tree_truncated": tree["truncated"],
        "returned": min(len(ordered), args.limit),
        "truncated": truncated,
        "edges": ordered[:args.limit],
    }
    if truncated:
        act_out["truncation"] = {
            "is_truncated": True,
            "limit": args.limit,
            "warning": f"进程树活动边数量达到或超过限制（当前返回 {min(len(ordered), args.limit)} 条）。",
            "suggestion": "建议缩小时间窗（--from-clock / --to-clock）或使用 summary 按 action 分组聚合分析，避免大批量冗余边占用上下文。",
        }
    print(dumps(act_out))

SRC_KEY = (
    "CASE WHEN a:Process THEN 'p:'+a.host_id+'/'+a.container_id+':'+"
    "coalesce(a.exe_path,'<NA>') "
    "WHEN a:File THEN 'f:'+a.host_id+'/'+a.container_id+':'+a.path "
    "WHEN a:Network THEN 'n:'+a.host_id+':'+a.endpoints ELSE '?' END"
)
DST_KEY = (
    "CASE WHEN b:Process THEN 'p:'+b.host_id+'/'+b.container_id+':'+"
    "coalesce(b.exe_path,'<NA>') "
    "WHEN b:File THEN 'f:'+b.host_id+'/'+b.container_id+':'+b.path "
    "WHEN b:Network THEN 'n:'+b.host_id+':'+b.endpoints ELSE '?' END"
)


def cmd_summary(db: DB, args: argparse.Namespace) -> None:
    resolve_time_args(db, args)
    where, params = edge_filter(args)
    mapping = {
        "action,dst": ["r.action", DST_KEY],
        "action,src": ["r.action", SRC_KEY],
        "action": ["r.action"],
        "dst": [DST_KEY],
        "src": [SRC_KEY],
    }
    exprs = mapping[args.group_by]
    selects = ", ".join(f"{expr} AS k{i}" for i, expr in enumerate(exprs))
    group_list = "[" + ", ".join(f"k{i}" for i in range(len(exprs))) + "]"
    cypher = (
        "MATCH (a)-[r]->(b) "
        f"WHERE {where} "
        f"WITH {selects}, r "
        f"WITH {group_list} AS group_key, count(*) AS n, "
        "min(r.start_ns) AS t0, max(r.start_ns) AS t1, "
        "collect(type(r)+':'+toString(r.event_id)+':'+r.action)[0..5] AS sample "
        "WHERE n >= $min_count "
        "RETURN group_key, n, t0, t1, sample "
        "ORDER BY n DESC LIMIT $limit"
    )
    rows = db.run(cypher, min_count=args.min_count, limit=args.limit, **params)
    print(dumps({"db": db.name, "group_by": args.group_by,
                 "rows": [
                     {"group_key": r["group_key"], "n": int(r["n"]),
                      "t0": r["t0"], "t1": r["t1"],
                      "sample_edge_keys": r["sample"]}
                     for r in rows
                 ]}))
