"""第 1 层：结构可达因果闭包抽取器（直接直连 Neo4j 图数据库）

职责：
从 Neo4j 中根据场景配置匹配终点事件（POI），沿着进程、文件、套接字等图实体展开反向因果可达闭包，
抽取所有候选因果边，作为神经符号路由器的输入，彻底摆脱对外部大模型智能体预过滤产物的依赖。
"""

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# 引入 provenance-agent 核心库以复用确定性图展开逻辑
_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT / "provenance-agent") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "provenance-agent"))

from pagent import app
from pagent.core import scenarios, settings
from pagent.orchestration import expand_closure, intake


def extract_raw_closure(scenario_name: str, return_deps: bool = False) -> Any:
    """自主连接 Neo4j，从终点事件展开完整的反向因果闭包候选边集合。

    返回:
        (raw_edges, stats) 或 (raw_edges, stats, deps)
    """
    settings.load_dotenv()
    sc = scenarios.load_scenario(scenario_name)
    run_id = f"prouter-{int(time.time())}"

    t0 = time.time()
    deps = app.build_deps(sc, run_id)
    intake.intake(deps)
    prep = expand_closure.prepare(deps)

    raw_edges: List[Dict[str, Any]] = []
    for (src, syscall, dst), edge_rec in deps.record.edges.items():
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
    }

    expand_closure.finish(prep)
    deps.graph.close()

    if return_deps:
        return raw_edges, stats, deps
    return raw_edges, stats
