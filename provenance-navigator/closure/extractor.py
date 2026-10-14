"""因果闭包与拓扑底座：结构可达因果闭包抽取器（直接直连 Neo4j 图数据库）

职责：
从 Neo4j 中根据场景配置匹配终点事件（POI），沿着进程、文件、套接字等图实体展开反向因果可达闭包，
抽取所有候选因果边，作为神经符号路由器的输入，彻底摆脱对外部大模型智能体预过滤产物的依赖。

场景与调查起点（POI）的唯一真源为 provenance-agent/config/scenarios.json，本系统不再维护副本。
"""

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# 引入 provenance-agent 核心库以复用确定性图展开逻辑
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "provenance-agent") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "provenance-agent"))

from pagent import app
from pagent.core import scenarios, settings
from pagent.orchestration import expand_closure, intake


def list_scenarios() -> List[str]:
    """全部场景名（真源：provenance-agent 的场景配置）。"""
    settings.load_dotenv()
    return scenarios.available_scenarios()


def _anchor_triples(deps: Any) -> List[Tuple[str, str, str]]:
    """计算 POI 锚点事件的内容三元组（与 agent 判定层 _confirm_anchor_poi 同口径）。"""
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
    """自主连接 Neo4j，从终点事件展开完整的反向因果闭包候选边集合。

    light=True 时只保留拓扑事实与基模匹配所需的四个字段（src/syscall/dst/process_id），
    专供离线蒸馏的训练候选池使用（不携带事件清单等大体量字段，控制内存占用）。

    返回:
        (raw_edges, stats) 或 (raw_edges, stats, deps)
        stats 中 anchor_triples 为 POI 锚点事件的内容三元组清单。
    """
    settings.load_dotenv()
    sc = scenarios.load_scenario(scenario_name)
    run_id = f"pnavigator-{int(time.time())}"

    t0 = time.time()
    deps = app.build_deps(sc, run_id)
    intake.intake(deps)
    prep = expand_closure.prepare(deps)

    raw_edges: List[Dict[str, Any]] = []
    for _key, edge_rec in deps.record.edges.items():
        if light:
            e = {
                "src": edge_rec.get("src"),
                "syscall": edge_rec.get("syscall"),
                "dst": edge_rec.get("dst"),
                "process_id": edge_rec.get("process_id"),
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

    expand_closure.finish(prep)
    deps.graph.close()

    if return_deps:
        return raw_edges, stats, deps
    return raw_edges, stats
