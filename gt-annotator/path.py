"""Shortest-path helper for bridge discovery and causality checks."""

from __future__ import annotations

import argparse
from typing import Any

from common import dumps, fail
from db import DB
from facts import (
    endpoint_key,
    node_key,
    node_match,
    parse_edge_key,
    path_nodes,
    resolve_time_args,
    vertex_match,
)


def check_causal_monotonic(edges: list[dict[str, Any]]) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    for i in range(len(edges) - 1):
        t1 = edges[i].get("start_ns")
        t2 = edges[i + 1].get("start_ns")
        if t1 is not None and t2 is not None and int(t2) < int(t1):
            violations.append({
                "step": i + 1,
                "prev_edge": edges[i].get("edge_key"),
                "prev_start_ns": t1,
                "next_edge": edges[i + 1].get("edge_key"),
                "next_start_ns": t2,
                "diff_ns": int(t2) - int(t1),
                "note": "时间逆流：后一条边发生在前一条边之前",
            })
    duration = None
    if edges and edges[0].get("start_ns") is not None and edges[-1].get("start_ns") is not None:
        duration = int(edges[-1]["start_ns"]) - int(edges[0]["start_ns"])
    return {
        "causal_monotonic": len(violations) == 0,
        "violation_count": len(violations),
        "violations": violations,
        "duration_ns": duration,
    }


def cmd_path(db: DB, args: argparse.Namespace) -> None:
    resolve_time_args(db, args)
    key_mode = bool(args.from_key or args.to_key)
    edge_mode = bool(args.from_edge or args.to_edge)
    if key_mode and edge_mode:
        fail("--from-key/--to-key 与 --from-edge/--to-edge 不能混用")
    if key_mode:
        if not (args.from_key and args.to_key):
            fail("--from-key 与 --to-key 必须同时给")
        a_pat, a_where, a_params = vertex_match("a", args.from_key)
        b_pat, b_where, b_params = vertex_match("b", args.to_key)
        params = {**a_params, **b_params}
        where = " AND ".join(x for x in (a_where, b_where) if x)
        source = args.from_key
        target = args.to_key
        label = "key"
    else:
        if not (args.from_edge and args.to_edge):
            fail("必须给 --from-edge/--to-edge 或 --from-key/--to-key")
        rel1, ev1, act1 = parse_edge_key(args.from_edge)
        rel2, ev2, act2 = parse_edge_key(args.to_edge)
        rows1 = db.run(
            f"MATCH (a)-[r:{rel1} {{event_id: $ev, action: $act}}]->(b) "
            "RETURN a AS src, b AS dst, r AS edge LIMIT 2", ev=ev1, act=act1)
        rows2 = db.run(
            f"MATCH (a)-[r:{rel2} {{event_id: $ev, action: $act}}]->(b) "
            "RETURN a AS src, b AS dst, r AS edge LIMIT 2", ev=ev2, act=act2)
        if len(rows1) != 1 or len(rows2) != 1:
            fail("from-edge 或 to-edge 不存在/不唯一")
        start = rows1[0]["dst"]
        end = rows2[0]["src"]
        if endpoint_key(start) == endpoint_key(end):
            print(dumps({"db": db.name, "reachable": True, "same_node": True,
                         "from_edge": args.from_edge, "to_edge": args.to_edge,
                         "causal_monotonic": True,
                         "note": "候选边的目标就是 POI 边的源；两条边直接相接"}))
            return
        a_pat, a_params = node_match("a", start)
        b_pat, b_params = node_match("b", end)
        params = {**a_params, **b_params}
        where = ""
        source = args.from_edge
        target = args.to_edge
        label = "edge"

    max_depth = int(args.max_depth)
    time_conds: list[str] = []
    if getattr(args, "from_ns", None) is not None:
        time_conds.append("relationships(p)[0].start_ns >= $from_ns")
        params["from_ns"] = args.from_ns
    if getattr(args, "to_ns", None) is not None:
        time_conds.append("relationships(p)[-1].start_ns <= $to_ns")
        params["to_ns"] = args.to_ns

    # 如果指定了 --causal 标志，先尝试严格因果单调搜索
    if getattr(args, "causal", False):
        causal_where = list(time_conds)
        if where:
            causal_where.append(where)
        causal_where.append(
            "ALL(i in range(0, size(relationships(p))-2) WHERE relationships(p)[i].start_ns <= relationships(p)[i+1].start_ns)"
        )
        causal_cypher = (
            f"MATCH {a_pat}, {b_pat} "
            f"MATCH p=(a)-[*1..{min(max_depth, 6)}]-(b) "
            f"WHERE {' AND '.join(causal_where)} "
            "RETURN p LIMIT 1"
        )
        c_rows = db.run(causal_cypher, **params)
        if c_rows:
            nodes, edges = path_nodes(c_rows[0]["p"])
            mono_check = check_causal_monotonic(edges)
            print(dumps({
                "db": db.name, "reachable": True, "mode": label,
                "strategy": "strict_causal",
                "from": source, "to": target,
                **mono_check,
                "nodes": nodes, "path_edges": edges,
            }))
            return

    # 默认使用原生最短路
    cypher = f"MATCH {a_pat}, {b_pat} "
    if where:
        cypher += f"WHERE {where} "
    path_filter = ("WHERE " + " AND ".join(time_conds)) if time_conds else ""
    cypher += (f"MATCH p=shortestPath((a)-[*..{max_depth}]-(b)) "
               f"{path_filter} RETURN p LIMIT 1")
    rows = db.run(cypher, **params)
    if not rows:
        print(dumps({"db": db.name, "reachable": False, "mode": label,
                     "from": source, "to": target,
                     "searched": "候选/源 -> 目标"}))
        return
    nodes, edges = path_nodes(rows[0]["p"])
    mono_check = check_causal_monotonic(edges)
    print(dumps({
        "db": db.name, "reachable": True, "mode": label,
        "strategy": "shortest_path",
        "from": source, "to": target,
        **mono_check,
        "nodes": nodes, "path_edges": edges,
    }))
