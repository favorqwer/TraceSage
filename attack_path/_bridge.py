"""与研究点一（attack_graph/）内部模块及产物的复用桥接层。"""
from __future__ import annotations

import importlib
from pathlib import Path
import sys
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK_GRAPH_DIR = REPO_ROOT / "attack_graph"
ATTACK_PATH_DIR = Path(__file__).resolve().parent
BASELINE_DIR = REPO_ROOT / "output" / "attack-graph-baseline"
PATH_BASELINE_DIR = REPO_ROOT / "output" / "attack-path-baseline"
PATH_RUNS_DIR = REPO_ROOT / "output" / "attack-path-runs"


def ensure_attack_graph_on_path() -> Path:
    """将 attack_graph/ 置于 sys.path 最前，确保复用研究点一主线模块。"""
    ag_str = str(ATTACK_GRAPH_DIR)
    if ag_str in sys.path:
        if sys.path[0] != ag_str:
            sys.path.remove(ag_str)
            sys.path.insert(0, ag_str)
    else:
        sys.path.insert(0, ag_str)
    return ATTACK_GRAPH_DIR


def attack_graph_settings() -> Any:
    """导入并返回 attack_graph.settings 模块（不与其它目录同名模块混淆）。"""
    ensure_attack_graph_on_path()
    mod = sys.modules.get("settings")
    if mod is not None:
        mod_file = Path(getattr(mod, "__file__", "")).resolve()
        if mod_file.parent != ATTACK_GRAPH_DIR.resolve():
            del sys.modules["settings"]
            mod = None
    if mod is None:
        mod = importlib.import_module("settings")
    return mod


def available_scenarios() -> list[str]:
    """返回 attack_graph 配置中定义的全部场景名。"""
    return attack_graph_settings().available_scenarios()


def load_scenario(name: str) -> Any:
    """加载指定场景的数据库名与 POI 端点配置。"""
    return attack_graph_settings().load_scenario(name)


def l1_cache_dir(database: str) -> Path:
    """返回指定场景库在 tmp/provenance/l1-index/ 下的缓存目录。"""
    ensure_attack_graph_on_path()
    snapshot = importlib.import_module("closure.snapshot")
    return snapshot.snapshot_dir(database)


def baseline_report_path(scenario: str) -> Path:
    """返回研究点一正式基线压缩报告路径。"""
    return BASELINE_DIR / "reports_v2" / f"{scenario}.json.gz"


def open_readonly_graph(
    database: str,
    *,
    scenario: str = "",
    run_id: str = "attack-path",
) -> Any:
    """复用 attack_graph 只读 Neo4j 句柄打开指定场景数据库。"""
    cfg = attack_graph_settings()
    cfg.load_dotenv()
    neo4j_mod = importlib.import_module("closure.neo4j")
    return neo4j_mod.ReadOnlyGraph(
        database,
        uri=cfg.neo4j_uri(),
        auth=cfg.neo4j_auth(),
        scenario=scenario,
        run_id=run_id,
    )
