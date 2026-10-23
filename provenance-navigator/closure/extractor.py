"""因果闭包入口：组装依赖、跑 POI 定位与展开，返回候选边。

实现已迁到 `closure/walk.py`（POI、索引、反向闭包）与 `closure/fold.py`（折叠、进程摘要、展开）。
本文件只做装配，并保留 `Deps` 容器供旧调用方使用。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

from common import config as cfg
from common.graph import Investigation, ReadOnlyGraph
from common.model import LlmBudget
from closure import fold, walk


@dataclass
class Deps:
    """一次运行的依赖（图 / 模型 / 记账 / 记录）。"""

    scenario: Any
    graph: ReadOnlyGraph
    model: Any
    budget: LlmBudget
    record: Investigation
    log: Callable[[str], None] = print
    trace: list[dict[str, Any]] = field(default_factory=list)


def build_deps(scenario: Any, run_id: str, *, model: Any = None,
               log: Callable[[str], None] = print) -> Deps:
    cfg.ensure_work_dirs()
    graph = ReadOnlyGraph(scenario.database, scenario=scenario.name, run_id=run_id)
    budget = LlmBudget()
    record = Investigation(run_id=run_id, scenario=scenario.name, database=scenario.database)
    return Deps(scenario=scenario, graph=graph, model=model, budget=budget, record=record, log=log)


def list_scenarios() -> List[str]:
    """全部场景名（真源：provenance-navigator/config/scenarios.json）。"""
    cfg.load_dotenv()
    return cfg.available_scenarios()


def _anchor_triples(deps: Any) -> List[Tuple[str, str, str]]:
    triples: List[Tuple[str, str, str]] = []
    for row in deps.record.poi_rows:
        rel = str(row.get("rel") or "")
        sc = str(row.get("syscall") or "")
        owner = str(row.get("process_content") or "")
        other = str(row.get("other") or "")
        triples.append((owner, sc, other) if rel in ("p2f", "p2n") else (other, sc, owner))
    return triples


def extract_raw_closure(scenario_name: str, return_deps: bool = False,
                        light: bool = False) -> Any:
    """自主连接 Neo4j，从终点事件展开完整的反向因果闭包候选边集合。"""
    cfg.load_dotenv()
    sc = cfg.load_scenario(scenario_name)
    run_id = f"pnavigator-{int(time.time())}"

    t0 = time.time()
    deps = build_deps(sc, run_id)
    walk.intake(deps)
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
