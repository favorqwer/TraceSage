"""与研究点一（attack_graph/）及单文件索引（tsg/）的复用桥接层（零 Neo4j 依赖）。"""
from __future__ import annotations

import importlib
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK_GRAPH_DIR = REPO_ROOT / "attack_graph"
ATTACK_PATH_DIR = Path(__file__).resolve().parent
GRAPH_STORE_DIR = REPO_ROOT / "graphs"
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
    """加载指定场景的配置与 POI 端点定义。"""
    return attack_graph_settings().load_scenario(name)


def graph_path(scenario: str) -> Path:
    """返回指定场景的正式单文件 .tsg 溯源图路径（graphs/<scenario>.tsg）。"""
    return attack_graph_settings().graph_path(scenario)


def open_graph(scenario: str) -> Any:
    """以 mmap 零拷贝只读方式打开指定场景的 .tsg 单文件溯源图（零 Neo4j 依赖）。"""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from tsg.format import TSGReader

    return TSGReader(graph_path(scenario))


def baseline_report_path(scenario: str) -> Path:
    """返回研究点一正式基线压缩报告路径。"""
    return BASELINE_DIR / "reports_v2" / f"{scenario}.json.gz"


def baseline_events_path(scenario: str) -> Path:
    """返回研究点一正式基线伴生事件明细路径。"""
    return BASELINE_DIR / "events_v2" / f"{scenario}.events.json.gz"


def events_path_for_report(report_path: str | Path) -> Path:
    """由任意研究点一报告路径推导同目录伴生事件明细路径。"""
    ensure_attack_graph_on_path()
    reporting = importlib.import_module("core.reporting")
    return reporting.default_events_path(report_path)
