"""GT validation: facts, connectivity, time, rules."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common import ROOT, dumps, fail
from db import DB
from facts import REL_TYPES, exact_node_key, ns_info, parse_edge_key, path_nodes, try_fetch_edge, vertex_match

if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
try:
    import rules_match as gt_rules
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"无法导入 tools/rules_match.py：{exc}") from exc


def _rule_content(row: dict[str, Any], side: str) -> str:
    ctx = (row.get("context") or {}).get(side) or {}
    label = str(ctx.get("label") or "")
    if label == "Process":
        return str(ctx.get("exe_path") or "<NA>")
    if label == "File":
        return str(ctx.get("path") or "")
    if label == "Network":
        return str(ctx.get("endpoints") or "")
    return ""

def _rule_label(row: dict[str, Any], side: str) -> str:
    ctx = (row.get("context") or {}).get(side) or {}
    return str(ctx.get("label") or "").lower()

def _endpoint_ok(spec: Any, row: dict[str, Any], side: str) -> bool:
    if not isinstance(spec, dict):
        return False
    label = _rule_label(row, side)
    kind = {label} if label else set()
    return bool(gt_rules.endpoint_matches(spec, kind, _rule_content(row, side)))

def _edge_attrs(row: dict[str, Any]) -> dict[str, Any]:
    ev = row.get("evidence") or {}
    start = ev.get("start_ns")
    end = ev.get("end_ns")
    duration = (int(end) - int(start)) if start is not None and end is not None else None
    return {"bytes": ev.get("result"), "duration_ns": duration}

@dataclass
class RuleSpec:
    where: str
    actions: set[str]
    predicate: Any
    cap: int
    effect: str
    time_bounds: tuple[int, int] | None = None
    hit: bool = False
    attached: bool = False
    matched: int = 0
    truncated: bool = False
    skipped_edge_attrs: bool = False
    done: bool = False
    failed: str | None = None
    overlapped_must: list[str] | None = None


def prepare_rule(rule: dict[str, Any], where: str,
                 errors: list[str],
                 time_bounds: tuple[int, int] | None = None) -> RuleSpec | None:
    actions = rule.get("action")
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, list) or not actions:
        errors.append(f"{where}: rule 缺 action 列表")
        return None
    source = rule.get("source")
    target = rule.get("target")
    if not isinstance(source, dict) or not isinstance(target, dict):
        errors.append(f"{where}: rule 缺 source/target")
        return None
    direction = str(rule.get("direction") or "either")
    if direction not in ("either", "src_to_dst"):
        errors.append(f"{where}: direction 只能是 either/src_to_dst")
        return None
    effect = str(rule.get("effect") or "any")
    if effect not in ("success", "failure", "any"):
        errors.append(f"{where}: effect 只能是 success/failure/any")
        return None
    edge_cond = rule.get("edge")
    spec = RuleSpec(where=where, actions=set(actions),
                    predicate=lambda row: False, cap=2000, effect=effect,
                    time_bounds=time_bounds, overlapped_must=[])

    def predicate(row: dict[str, Any]) -> bool:
        if effect != "any" and row["fact"]["effect"] != effect:
            return False
        if time_bounds is not None:
            ev = row.get("evidence") or {}
            st = ev.get("start_ns")
            if st is not None:
                st_int = int(st)
                if st_int < time_bounds[0] or st_int > time_bounds[1]:
                    return False
        if edge_cond:
            ok, skipped = gt_rules._edge_matches(edge_cond, _edge_attrs(row))
            spec.skipped_edge_attrs = spec.skipped_edge_attrs or skipped
            if not ok:
                return False
        a_src = _endpoint_ok(source, row, "src")
        a_dst = _endpoint_ok(target, row, "dst")
        if direction == "src_to_dst":
            return a_src and a_dst
        b_src = _endpoint_ok(source, row, "dst")
        b_dst = _endpoint_ok(target, row, "src")
        return (a_src and a_dst) or (b_src and b_dst)

    spec.predicate = predicate
    return spec


def finish_rule(spec: RuleSpec, errors: list[str], warnings: list[str],
                rule_results: list[dict[str, Any]]) -> None:
    if spec.failed:
        warnings.append(f"{spec.where}: rule 求值失败（{spec.failed}），未计数")
        return
    if spec.skipped_edge_attrs:
        warnings.append(
            f"{spec.where}: rule 的 edge 属性条件有缺失值，按现有匹配器口径忽略该条件")
    rule_results.append({
        "where": spec.where, "effect": spec.effect,
        "matched_count": spec.matched,
        "truncated": spec.truncated, "attached": spec.attached,
        "time_window_applied": bool(spec.time_bounds),
        "time_bounds": [spec.time_bounds[0], spec.time_bounds[1]] if spec.time_bounds else None,
        "disjoint_ok": not bool(spec.overlapped_must),
    })
    if spec.overlapped_must:
        errors.append(
            f"{spec.where}: 违背'两不相交定律'（覆盖了 must 边：{spec.overlapped_must[:3]}）；"
            "若该边为确定性 must 动作，必须在 rule 的 target/source 中通过 none_of 将其显式排除"
        )
    if not spec.hit:
        errors.append(f"{spec.where}: rule 在图上 0 条匹配")
    elif not spec.attached:
        suffix = (f"（计数达到 cap={spec.cap}，可能被截断）"
                  if spec.truncated else "")
        errors.append(f"{spec.where}: rule 有匹配，但没有一条挂在 GT 连通图上{suffix}")


def load_gt(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"读不了 GT 文件 {path}: {exc}")
    if not isinstance(data, dict):
        fail("GT 顶层必须是对象")
    return data

def _build_components(edges: list[tuple[str, str, str]],
                      extra_vertices: set[str]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    vertices: set[str] = set(extra_vertices)
    for src, dst, _where in edges:
        vertices.add(src)
        vertices.add(dst)
        if src != dst:
            adjacency[src].add(dst)
            adjacency[dst].add(src)
    seen: set[str] = set()
    comps: list[list[str]] = []
    for start in sorted(vertices):
        if start in seen:
            continue
        stack = [start]
        seen.add(start)
        members: list[str] = []
        while stack:
            vertex = stack.pop()
            members.append(vertex)
            for neighbour in adjacency[vertex]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    stack.append(neighbour)
        comps.append(members)
    comps.sort(key=len, reverse=True)
    comp_of: dict[str, int] = {}
    for index, members in enumerate(comps):
        for vertex in members:
            comp_of[vertex] = index
    out: list[dict[str, Any]] = []
    for index, members in enumerate(comps):
        member_set = set(members)
        samples: list[dict[str, str]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for src, dst, where in edges:
            if src not in member_set and dst not in member_set:
                continue
            key = (src, dst, where)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            samples.append({"src": src, "dst": dst, "where": where})
            if len(samples) >= 10:
                break
        out.append({
            "component": index + 1,
            "size": len(members),
            "sample_vertices": sorted(members)[:20],
            "edge_count": sum(1 for src, dst, _ in edges
                              if src in member_set or dst in member_set),
            "sample_edges": samples,
        })
    return out, comp_of

def _check_connectivity(gt: dict[str, Any],
                        must_edges: list[tuple[str, str, str]],
                        poi_fact: tuple[str, str, str, str] | None,
                        entry_fact: tuple[str, str, str, str] | None,
                        errors: list[str],
                        warnings: list[str],
                        conn_edges_override: list[tuple[str, str, str]] | None = None,
                        ) -> tuple[dict[str, Any], set[str]]:
    conn_edges = list(conn_edges_override) if conn_edges_override is not None else list(must_edges)
    if conn_edges_override is None:
        if poi_fact:
            conn_edges.append((poi_fact[0], poi_fact[2], "poi"))
        if entry_fact:
            conn_edges.append((entry_fact[0], entry_fact[2], "entry"))
    components, comp_of = _build_components(conn_edges, set())
    connected = len(components) == 1
    if not conn_edges:
        errors.append("GT 没有任何 must/poi/entry 边，无法形成连通图")
    elif not connected:
        sizes = [component["size"] for component in components]
        errors.append(
            f"GT 不是连通图：{len(components)} 个分量，大小 {sizes}；"
            "用 path/edges 找桥，或把断开的边改为 context/删除"
        )
    if conn_edges_override is None and poi_fact and poi_fact[0] not in comp_of:
        errors.append("poi 不在 GT 连通图里")
    return {
        "required": True,
        "connected": connected,
        "component_count": len(components),
        "components": components,
    }, set(comp_of)


def fetch_fact_time(db: DB, fact: tuple[str, str, str, str], edge_key: str | None = None) -> int | None:
    if edge_key:
        rec = try_fetch_edge(db, edge_key)
        if rec and rec.get("edge", {}).get("start_ns") is not None:
            return int(rec["edge"]["start_ns"])
    src_key, action, dst_key, effect = fact
    try:
        a_pat, a_where, a_params = vertex_match("a", src_key)
        b_pat, b_where, b_params = vertex_match("b", dst_key)
        where_parts = [p for p in (a_where, b_where) if p]
        where_parts.append("r.action = $act")
        if effect == "failure":
            where_parts.append("r.result < 0")
        else:
            where_parts.append("(r.result IS NULL OR r.result >= 0)")
        where_clause = " WHERE " + " AND ".join(where_parts)
        cypher = f"MATCH {a_pat}-[r]->{b_pat}{where_clause} RETURN min(r.start_ns) AS t0 LIMIT 1"
        params = {**a_params, **b_params, "act": action}
        rows = db.run(cypher, **params)
        if rows and rows[0].get("t0") is not None:
            return int(rows[0]["t0"])
    except Exception:
        pass
    return None


def find_candidate_bridges(db: DB, comp1_vertices: list[str], comp2_vertices: list[str],
                           time_bounds: tuple[int, int] | None = None, limit: int = 5) -> list[dict[str, Any]]:
    """在两个断开的连通分量之间自动搜索无向短路径因果桥。"""
    bridges: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    v1_samples = comp1_vertices[:6]
    v2_samples = comp2_vertices[:6]
    for v1 in v1_samples:
        for v2 in v2_samples:
            try:
                a_pat, a_where, a_params = vertex_match("a", v1)
                b_pat, b_where, b_params = vertex_match("b", v2)
                node_where = [w for w in (a_where, b_where) if w]
                params = {**a_params, **b_params}
                node_clause = ("WHERE " + " AND ".join(node_where)) if node_where else ""

                path_where = []
                if time_bounds:
                    path_where.append("ALL(r IN relationships(p) WHERE r.start_ns >= $t_min AND r.start_ns <= $t_max)")
                    params["t_min"] = time_bounds[0]
                    params["t_max"] = time_bounds[1]
                path_clause = ("WHERE " + " AND ".join(path_where)) if path_where else ""

                cypher = f"MATCH {a_pat}, {b_pat} {node_clause} MATCH p=shortestPath((a)-[*..5]-(b)) {path_clause} RETURN p LIMIT 1"
                rows = db.run(cypher, **params)
                if rows:
                    p = rows[0]["p"]
                    _, path_edges = path_nodes(p)
                    for ed in path_edges:
                        ekey = ed.get("edge_key")
                        if ekey and ekey not in seen_keys:
                            seen_keys.add(ekey)
                            bridges.append({
                                "edge_key": ekey,
                                "action": ed.get("action"),
                                "start_ns": ed.get("start_ns"),
                                "src": ed.get("src"),
                                "dst": ed.get("dst"),
                                "bridge_between": [v1, v2],
                                "note": f"连接分量顶点 [{v1}] 与 [{v2}] 的图上真实因果边",
                            })
                            if len(bridges) >= limit:
                                return bridges
            except Exception:
                continue
    return bridges

def cmd_validate(db: DB, args: argparse.Namespace) -> None:
    gt = load_gt(args.gt)
    errors: list[str] = []
    warnings: list[str] = []
    facts: list[tuple[str, str, str, str, str]] = []
    edge_keys: set[str] = set()
    key_to_fact: dict[str, tuple[str, str, str, str]] = {}
    seen: dict[tuple[str, str, str, str], str] = {}
    must_count = 0
    possible_count = 0
    must_edges: list[tuple[str, str, str]] = []
    must_facts: list[tuple[tuple[str, str, str, str], str]] = []
    must_edge_keys: list[tuple[str | None, tuple[str, str, str, str], str]] = []
    rules_pending: list[tuple[dict[str, Any], str]] = []
    rule_results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    poi_fact: tuple[str, str, str, str] | None = None
    entry_fact: tuple[str, str, str, str] | None = None

    def add_fact(obj: dict[str, Any], where: str, *,
                 unique: bool) -> tuple[str, str, str, str] | None:
        missing = [k for k in ("src", "action", "dst", "effect") if not obj.get(k)]
        if missing:
            errors.append(f"{where}: 缺字段 {missing}")
            return None
        fact = (str(obj["src"]), str(obj["action"]), str(obj["dst"]),
                str(obj["effect"]))
        if fact[3] not in ("success", "failure"):
            errors.append(f"{where}: effect 只能是 success/failure")
        if unique:
            if fact in seen:
                errors.append(f"{where}: 与 {seen[fact]} 重复的 4 元组 {fact}")
            else:
                seen[fact] = where
        facts.append((*fact, where))
        key = obj.get("edge_key")
        if key:
            key = str(key)
            parts = key.split(":", 2)
            if len(parts) != 3 or parts[0] not in REL_TYPES:
                errors.append(f"{where}: edge_key 格式不对：{key}")
            else:
                edge_keys.add(key)
                key_to_fact[key] = fact
        return fact

    if not gt.get("scenario"):
        errors.append("GT 缺 scenario")
    poi = gt.get("poi")
    if not isinstance(poi, dict):
        errors.append("GT 缺 poi")
    else:
        poi_fact = add_fact(poi, "poi", unique=False)
    entry = gt.get("entry")
    if entry is None:
        errors.append("GT 缺 entry")
    elif not isinstance(entry, dict):
        errors.append("entry 必须是对象")
    else:
        entry_fact = add_fact(entry, "entry", unique=False)
    poi_key = str(poi.get("edge_key")) if isinstance(poi, dict) and poi.get("edge_key") else None
    entry_key = str(entry.get("edge_key")) if isinstance(entry, dict) and entry.get("edge_key") else None
    phases = gt.get("attack_path")
    if not isinstance(phases, list) or not phases:
        errors.append("GT 缺 attack_path")
        phases = []
    phase_ids: set[str] = set()
    for phase in phases:
        if not isinstance(phase, dict):
            errors.append("attack_path 里有非对象")
            continue
        pid = str(phase.get("id") or "")
        if not pid:
            errors.append("phase 缺 id")
        elif pid in phase_ids:
            errors.append(f"phase id 重复：{pid}")
        phase_ids.add(pid)
        collection = str(phase.get("collection") or "")
        if collection not in ("must", "possible"):
            errors.append(f"{pid}: collection 必须是 must/possible")
        if collection == "must":
            must_count += 1
        elif collection == "possible":
            possible_count += 1
        raw_edges = phase.get("edges")
        raw_rules = phase.get("rules")
        if raw_edges is not None and not isinstance(raw_edges, list):
            errors.append(f"{pid}: edges 必须是数组")
        if raw_rules is not None and not isinstance(raw_rules, list):
            errors.append(f"{pid}: rules 必须是数组")
        phase_edges = raw_edges if isinstance(raw_edges, list) else []
        phase_rules = raw_rules if isinstance(raw_rules, list) else []
        if collection == "must":
            if not phase_edges:
                errors.append(f"{pid}: must 阶段至少要有 1 条 edges")
            if phase_rules:
                errors.append(f"{pid}: must 阶段不能有 rules")
        elif collection == "possible":
            if not phase_rules:
                errors.append(f"{pid}: possible 阶段至少要有 1 条 rules")
            if phase_edges:
                errors.append(f"{pid}: possible 阶段不能有 edges")
        for edge in phase_edges:
            if not isinstance(edge, dict):
                errors.append(f"{pid}: edge 不是对象")
                continue
            fact = add_fact(edge, f"{pid}.edge", unique=True)
            if fact is not None and collection == "must":
                must_edges.append((fact[0], fact[2], f"{pid}.edge"))
                must_facts.append((fact, f"{pid}.edge"))
                key = edge.get("edge_key")
                must_edge_keys.append((str(key) if key else None, fact, f"{pid}.edge"))
        for rule in phase_rules:
            if not isinstance(rule, dict):
                errors.append(f"{pid}: rule 不是对象")
                continue
            rid = str(rule.get("rule_id") or "")
            if not rid:
                errors.append(f"{pid}: rule 缺 rule_id")
            elif rid in rule_ids:
                errors.append(f"{pid}: rule_id 重复：{rid}")
            else:
                rule_ids.add(rid)
            rules_pending.append((rule, f"{pid}.rule"))

    if must_count == 0:
        errors.append("GT 至少要有一个 must 阶段")
    else:
        must_facts_set = {f for f, _ in must_facts}
        if entry_fact and entry_fact not in must_facts_set:
            errors.append("entry 边必须作为 attack_path 阶段边的一部分（如 A1.1）")
        if poi_fact and poi_fact not in must_facts_set:
            errors.append("poi 边必须作为 attack_path 阶段边的一部分（如终局破坏阶段边）")

    counts_spec = gt.get("counts")
    counts_result = None
    if counts_spec is not None:
        if not isinstance(counts_spec, dict):
            errors.append("counts 必须是对象")
        else:
            act_exp = len(phases)
            must_exp = len(must_facts)
            rule_exp = len(rules_pending)
            steps_exp = must_exp + rule_exp
            unique_must_exp = len({(f[0], f[1], f[2]) for f, _ in must_facts})

            if "actions" in counts_spec and counts_spec["actions"] != act_exp:
                errors.append(f"counts.actions ({counts_spec['actions']}) 与 attack_path 阶段数 ({act_exp}) 不一致")
            if "must_entries" in counts_spec and counts_spec["must_entries"] != must_exp:
                errors.append(f"counts.must_entries ({counts_spec['must_entries']}) 与实际 must 边条数 ({must_exp}) 不一致")
            if "rules" in counts_spec and counts_spec["rules"] != rule_exp:
                errors.append(f"counts.rules ({counts_spec['rules']}) 与实际 rules 条数 ({rule_exp}) 不一致")
            if "steps_total" in counts_spec and counts_spec["steps_total"] != steps_exp:
                errors.append(f"counts.steps_total ({counts_spec['steps_total']}) 与实际总步骤数 ({steps_exp}) 不一致")
            if "edges_total_with_dupes" in counts_spec and counts_spec["edges_total_with_dupes"] != must_exp:
                errors.append(f"counts.edges_total_with_dupes ({counts_spec['edges_total_with_dupes']}) 与实际 must 边条数 ({must_exp}) 不一致")
            if "edges_unique" in counts_spec and counts_spec["edges_unique"] != unique_must_exp:
                errors.append(f"counts.edges_unique ({counts_spec['edges_unique']}) 与唯一 must 边条数 ({unique_must_exp}) 不一致")
            counts_result = {
                "declared": counts_spec,
                "verified": {
                    "actions": act_exp,
                    "must_entries": must_exp,
                    "rules": rule_exp,
                    "steps_total": steps_exp,
                    "edges_total_with_dupes": must_exp,
                    "edges_unique": unique_must_exp,
                },
                "matched": (
                    counts_spec.get("actions") == act_exp
                    and counts_spec.get("must_entries") == must_exp
                    and counts_spec.get("rules") == rule_exp
                    and counts_spec.get("steps_total") == steps_exp
                ),
            }

    rule_time_bounds: tuple[int, int] | None = None
    if getattr(args, "check_time", True) and poi_fact and entry_fact:
        p_t = fetch_fact_time(db, poi_fact, poi_key)
        e_t = fetch_fact_time(db, entry_fact, entry_key)
        if p_t is not None and e_t is not None and e_t <= p_t:
            rule_time_bounds = (e_t, p_t)

    if args.strict_instances:
        strict_edges: list[tuple[str, str, str]] = []
        for key, fact, where in must_edge_keys:
            if not key and poi_fact and fact == poi_fact:
                key = poi_key
            if not key and entry_fact and fact == entry_fact:
                key = entry_key
            if not key:
                errors.append(f"{where}: strict-instances 要求每条 must 边都带 edge_key")
                continue
            rec = try_fetch_edge(db, key)
            if rec is None:
                errors.append(f"{where}: strict-instances 找不到 edge_key {key}")
                continue
            strict_edges.append((exact_node_key(rec["src"]),
                                 exact_node_key(rec["dst"]), where))
        if poi_fact:
            if not poi_key:
                errors.append("strict-instances 要求 poi 带 edge_key")
            else:
                rec = try_fetch_edge(db, poi_key)
                if rec is None:
                    errors.append(f"strict-instances 找不到 poi edge_key {poi_key}")
                else:
                    strict_edges.append((exact_node_key(rec["src"]),
                                         exact_node_key(rec["dst"]), "poi"))
        if entry_fact:
            if not entry_key:
                errors.append("strict-instances 要求 entry 带 edge_key")
            else:
                rec = try_fetch_edge(db, entry_key)
                if rec is None:
                    errors.append(f"strict-instances 找不到 entry edge_key {entry_key}")
                else:
                    strict_edges.append((exact_node_key(rec["src"]),
                                         exact_node_key(rec["dst"]), "entry"))
        connectivity, _exact_vertices = _check_connectivity(
            gt, must_edges, poi_fact, entry_fact, errors, warnings,
            conn_edges_override=strict_edges,
        )
        connectivity["mode"] = "strict_instances"
    else:
        connectivity, _exact_vertices = _check_connectivity(
            gt, must_edges, poi_fact, entry_fact, errors, warnings
        )
        connectivity["mode"] = "program_key"

    candidate_bridges: list[dict[str, Any]] = []
    if not connectivity["connected"] and len(connectivity.get("components", [])) >= 2:
        c1_verts = connectivity["components"][0].get("sample_vertices", [])
        c2_verts = connectivity["components"][1].get("sample_vertices", [])
        candidate_bridges = find_candidate_bridges(db, c1_verts, c2_verts, rule_time_bounds)
        if candidate_bridges:
            connectivity["candidate_bridges_found"] = len(candidate_bridges)
            warnings.append(
                f"自动检索到 {len(candidate_bridges)} 条跨分量候选桥梁边（见 candidate_bridges 看板），可挑选并加入 GT 以恢复连通性"
            )
        else:
            v1_sample = c1_verts[0] if c1_verts else ""
            v2_sample = c2_verts[0] if c2_verts else ""
            manual_cmd = (
                f"python gt-annotator/gt.py path --db {db.name} "
                f"--from-key \"{v1_sample}\" --to-key \"{v2_sample}\" --max-depth 15 --causal"
            )
            connectivity["manual_expansion_cmd"] = manual_cmd
            warnings.append(
                f"默认5跳内未自动找到候选桥梁边。请尝试手动加大深度探索分量间因果路径：`{manual_cmd}`"
            )

    # Rules attach by 4-tuple/program key; strict mode only tightens connectivity.
    rule_vertices: set[str] = set()
    for fact, _where in must_facts:
        rule_vertices.update((fact[0], fact[2]))
    if poi_fact:
        rule_vertices.update((poi_fact[0], poi_fact[2]))
    if entry_fact:
        rule_vertices.update((entry_fact[0], entry_fact[2]))

    specs: list[RuleSpec] = []
    for rule, where in rules_pending:
        spec = prepare_rule(rule, where, errors, time_bounds=rule_time_bounds)
        if spec is not None:
            spec.cap = args.rule_count_cap
            specs.append(spec)
    needed_facts = {(f[0], f[1], f[2], f[3]) for f in facts}
    found_facts, found_keys, key_facts, fact_times, key_times = db.scan_facts_and_rules(
        needed_facts, edge_keys, specs, rule_vertices)
    for spec in specs:
        finish_rule(spec, errors, warnings, rule_results)
    missing_facts = sorted(needed_facts - found_facts)
    missing_keys = sorted(edge_keys - found_keys)
    for fact in missing_facts:
        where = next((f[4] for f in facts if (f[0], f[1], f[2], f[3]) == fact), "?")
        errors.append(f"{where}: 图上找不到 4 元组 {fact}")
    for key in missing_keys:
        errors.append(f"图上找不到 edge_key {key}")
    for key, declared in key_to_fact.items():
        actual = key_facts.get(key)
        if actual is not None and actual != declared:
            errors.append(f"edge_key {key} 对应的 4 元组与 GT 写的不一致：图上={actual} GT={declared}")

    time_check: dict[str, Any] = {
        "enabled": bool(args.check_time),
        "entry_start_ns": None,
        "poi_start_ns": None,
        "entry_before_poi": None,
        "tolerance_ns": args.time_tolerance_ns,
        "violations": [],
    }
    if args.check_time and poi_fact:
        poi_start = key_times.get(poi_key) if poi_key else fact_times.get(poi_fact)
        time_check["poi_start_ns"] = poi_start
        if poi_start is None:
            warnings.append("poi 在图上没有 start_ns，无法做时间检查")
        else:
            entry_start = (key_times.get(entry_key) if entry_key else fact_times.get(entry_fact)) if entry_fact else None
            time_check["entry_start_ns"] = entry_start
            if entry_fact is None:
                pass
            elif entry_start is None:
                warnings.append("entry 在图上没有 start_ns，无法做下界检查")
            else:
                time_check["entry_before_poi"] = entry_start < poi_start
                if entry_start >= poi_start:
                    errors.append(
                        "entry 不早于 POI："
                        f"{ns_info(entry_start)} >= {ns_info(poi_start)}"
                    )
                    time_check["violations"].append({
                        "where": "entry", "kind": "entry_not_before_poi",
                        "entry_start": ns_info(entry_start),
                        "poi_start": ns_info(poi_start),
                    })
            for key, fact, where in must_edge_keys:
                if fact in (poi_fact, entry_fact):
                    continue
                start = key_times.get(key) if key else fact_times.get(fact)
                if start is None:
                    warnings.append(f"{where}: 图上没有 start_ns，跳过时间检查")
                    continue
                if start > poi_start + args.time_tolerance_ns:
                    msg = (f"{where}: 边时间晚于 POI（{ns_info(start)} > "
                           f"{ns_info(poi_start)}），不在 entry→POI 时间窗内")
                    time_check["violations"].append({
                        "where": where, "fact": list(fact), "kind": "after_poi",
                        "start": ns_info(start), "poi_start": ns_info(poi_start),
                    })
                    errors.append(msg)
                elif (entry_start is not None
                      and start < entry_start - args.time_tolerance_ns):
                    msg = (f"{where}: 边时间早于 entry（{ns_info(start)} < "
                           f"{ns_info(entry_start)}），不在 entry→POI 时间窗内")
                    time_check["violations"].append({
                        "where": where, "fact": list(fact), "kind": "before_entry",
                        "start": ns_info(start), "entry_start": ns_info(entry_start),
                    })
                    errors.append(msg)

    # 检查 rename 边成对完整性
    for edge_key_str, fact, where in must_edge_keys:
        if fact[1] == "rename" and edge_key_str:
            try:
                _rel, ev_id, _act = parse_edge_key(edge_key_str)
                rows = db.run(
                    "MATCH ()-[r]->() WHERE r.event_id = $ev AND r.action = 'rename' RETURN count(*) AS n",
                    ev=ev_id,
                )
                if rows and rows[0]["n"] > 1:
                    matching_in_gt = sum(
                        1 for k, f, _ in must_edge_keys
                        if f[1] == "rename" and k and k.split(":", 2)[1] == str(ev_id)
                    )
                    if matching_in_gt == 1:
                        warnings.append(
                            f"{where}: 包含 rename 边（event_id={ev_id}），数据库中该事件拆分出双向边（读旧路径/写新路径），当前 GT 仅包含 1 条。如需完整体现路径转移，建议将另一端也纳入 GT 或在备注中说明"
                        )
            except Exception:
                pass

    # 联动检查 steps 状态机销账
    if getattr(args, "check_steps", False):
        scenario = gt.get("scenario", "")
        steps_file = ROOT / "gt-annotator" / "tmp" / scenario / "steps.json"
        if not steps_file.exists():
            errors.append(f"开启了 --check-steps，但未找到步骤状态机文件：{steps_file}；请先运行 gt.py steps init --scenario {scenario}")
        else:
            try:
                sdata = json.loads(steps_file.read_text(encoding="utf-8"))
                absent_list = [s for s in sdata.get("steps", []) if s.get("status") == "absent"]
                if absent_list:
                    ids = [s.get("id") for s in absent_list[:5]]
                    more = f"...等共 {len(absent_list)} 项" if len(absent_list) > 5 else ""
                    errors.append(f"steps 销账未完成：存在 {len(absent_list)} 个 absent 步骤未解决（{ids}{more}）")
            except Exception as exc:
                errors.append(f"读取 steps.json 校验失败：{exc}")

    out = {
        "ok": not errors,
        "db": db.name,
        "gt": args.gt,
        "scenario": gt.get("scenario"),
        "facts_checked": len(needed_facts),
        "edge_keys_checked": len(edge_keys),
        "must_phases": must_count,
        "possible_phases": possible_count,
        "connectivity": connectivity,
        "time_check": time_check,
        "candidate_bridges": candidate_bridges,
        "counts": counts_result,
        "rules": rule_results,
        "missing_facts": [list(x) for x in missing_facts],
        "missing_edge_keys": missing_keys,
        "errors": errors,
        "warnings": warnings,
    }
    print(dumps(out))
    if not out["ok"]:
        raise SystemExit(1)
