"""因果闭包入口：装配依赖、定位 POI、展开并返回候选边。

实现分布在 `closure/snapshot.py`、`closure/traversal.py`、`closure/policy.py` 与
`closure/fold.py`；本文件只做装配与 POI 定位，并保留 `Deps` 容器供调用方使用。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

import settings as cfg
from domain.edge import normalize_rel, owner_is_source
from domain.state import Investigation
from closure.neo4j import ReadOnlyGraph
from closure.storage import poi_query
from closure import fold
from closure.trace import trace_event


@dataclass
class Deps:
    """一次运行的依赖（图 / 模型 / 记账 / 记录）。"""

    scenario: Any
    graph: ReadOnlyGraph
    model: Any
    budget: Any
    record: Investigation
    log: Callable[[str], None] = print
    trace: list[dict[str, Any]] = field(default_factory=list)


def build_deps(scenario: Any, run_id: str, *, model: Any = None,
               log: Callable[[str], None] = print) -> Deps:
    cfg.ensure_work_dirs()
    graph = ReadOnlyGraph(scenario.database, scenario=scenario.name, run_id=run_id)
    budget = None
    record = Investigation(run_id=run_id, scenario=scenario.name, database=scenario.database)
    return Deps(scenario=scenario, graph=graph, model=model, budget=budget, record=record, log=log)


def list_scenarios() -> List[str]:
    """全部场景名（真源：provenance/config/scenarios.json）。"""
    cfg.load_dotenv()
    return cfg.available_scenarios()


# ==== POI 定位 ====

def intake(deps: "Deps") -> dict[str, Any]:
    """POI 命中校验 + 时间范围现算（实例数/时间范围不写进配置）。"""
    poi = deps.scenario.poi.as_dict()
    rows = deps.graph.run(poi_query(poi["rel"], poi["kind"]),
                          {"key": poi["key"], "sc": poi["syscall"]})
    if not rows:
        raise RuntimeError(f"POI 在库中未命中：{poi}")

    process_ids = sorted({r["process_id"] for r in rows})
    owner = rows[0]["process_content"]
    t_first = min(int(r["starttime"]) for r in rows)
    t_last = max(int(r["endtime"]) for r in rows)

    inv = deps.record
    inv.poi_owner = owner
    inv.poi_instances = len(rows)
    inv.poi_t0 = t_first
    inv.poi_t1 = t_last
    # 终点事件的原文（闭包引擎的种子）
    normalized_rel = normalize_rel(poi["rel"])
    inv.poi_rows = [dict(row, rel=normalized_rel) for row in rows]
    inv.add_hypothesis("POI", f"POI: {owner} {poi['rel']} {poi['syscall']} {poi['key']}", status="confirmed")

    for pid in process_ids:
        inv.add_entity("Process", pid, status="tracing")
    deps.log(f"[intake] POI 命中 {len(rows)} 条实例；涉及进程 {process_ids}")
    trace_event(deps.trace, "intake", poi_rows=len(rows), processes=len(process_ids))
    return {"poi_rows": rows}


def _anchor_triples(deps: Any) -> List[Tuple[str, str, str]]:
    """终点事件的内容三元组（方向由关系类型决定，不在这里重写判断）。"""
    triples: List[Tuple[str, str, str]] = []
    for row in deps.record.poi_rows:
        rel = str(row.get("rel") or "")
        sc = str(row.get("syscall") or "")
        owner = str(row.get("process_content") or "")
        other = str(row.get("other") or "")
        triples.append((owner, sc, other) if owner_is_source(rel) else (other, sc, owner))
    return triples


def extract_raw_closure(scenario_name: str, return_deps: bool = False,
                        light: bool = False,
                        log: Callable[[str], None] = print) -> Any:
    """自主连接 Neo4j，从终点事件展开完整的反向因果闭包候选边集合。"""
    cfg.load_dotenv()
    sc = cfg.load_scenario(scenario_name)
    run_id = f"pnavigator-{int(time.time())}"

    t0 = time.time()
    deps = build_deps(sc, run_id, log=log)
    intake(deps)
    prep = fold.prepare(deps)

    raw_edges: List[Dict[str, Any]] = []
    for _key, edge_rec in deps.record.edges.items():
        if light:
            e = {
                "src": edge_rec.get("src"),
                "syscall": edge_rec.get("syscall"),
                "dst": edge_rec.get("dst"),
                "process_id": edge_rec.get("process_id"),
                "src_label": edge_rec.get("src_label"),
                "dst_label": edge_rec.get("dst_label"),
                "src_identities": edge_rec.get("src_identities") or [],
                "dst_identities": edge_rec.get("dst_identities") or [],
            }
        else:
            e = dict(edge_rec)
            e["origin"] = "closure_raw"
        raw_edges.append(e)

    elapsed_closure = time.time() - t0
    stats = {
        "scenario": scenario_name,
        "database": sc.database,
        "poi_count": len(deps.record.poi_rows),
        "raw_candidate_edges": len(raw_edges),
        "closure_rounds": prep.rounds,
        "closure_time_seconds": elapsed_closure,
        "anchor_triples": _anchor_triples(deps),
    }

    fold.finish(prep)
    deps.graph.close()

    if return_deps:
        return raw_edges, stats, deps
    return raw_edges, stats
