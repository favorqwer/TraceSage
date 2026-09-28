"""装配：一次运行的依赖容器与流程顺序（编排的入口）。

`build_deps` 造依赖（图句柄 / 模型 / 记账 / 记录），`run_once` 按层顺序跑一次调查并把报告装配好；
文件落盘（报告、轨迹、记录、打印）由入口 `main.py` 负责。新的入口（批处理、接口服务）复用这里。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .core import settings
from .core.db import ReadOnlyGraph
from .core.llm import LlmBudget
from .core.record import Investigation
from .core.trace import trace_event
from .layers.l3_express import build_report, resolve_event_ids
from .orchestration import expand_closure as expand_closure_mod
from .orchestration import intake as intake_mod
from .orchestration import judging as judging_mod


@dataclass
class Deps:
    """一次运行的依赖（图 / 模型 / 记账 / 记录）。"""

    scenario: Any
    graph: ReadOnlyGraph
    model: Any
    budget: LlmBudget
    record: Investigation
    min_confidence: float = 0.5
    log: Callable[[str], None] = print
    trace: list[dict[str, Any]] = field(default_factory=list)


def build_deps(scenario: Any, run_id: str, *, model: Any = None, min_confidence: float = 0.5,
               log: Callable[[str], None] = print) -> Deps:
    """造一次运行的依赖。"""
    settings.ensure_work_dirs()
    graph = ReadOnlyGraph(scenario.database, scenario=scenario.name, run_id=run_id)
    budget = LlmBudget()
    record = Investigation(run_id=run_id, scenario=scenario.name, database=scenario.database)
    return Deps(scenario=scenario, graph=graph, model=model, budget=budget, record=record,
                min_confidence=min_confidence, log=log)


def run_once(deps: Deps, *, dry_run: bool) -> dict[str, Any]:
    """按层顺序跑一次调查，返回报告与统计（不做文件落盘）。"""
    record = deps.record
    t0 = time.time()
    intake_mod.intake(deps)
    expand = expand_closure_mod.expand_closure(deps)
    deps.log(f"[expand] 展开结束：{expand['rounds']} 轮 / {len(record.process_context)} 个进程 / "
             f"{len(record.edges)} 条折叠边；停止原因 {expand['stop_reason']}（{time.time() - t0:.1f}s）")

    if dry_run:
        judge_stats: dict[str, Any] = {}
        stop_reason = "dry_run"
    else:
        judge_stats = judging_mod.judge_all(deps)
        stop_reason = expand["stop_reason"]
    record.close_unclosed()

    stats = {
        "expand": {"rounds": expand["rounds"], "fold": expand["fold"],
                   "dropped": expand.get("dropped") or {},
                   "gate_blocked": (expand.get("closure") or {}).get("gate_blocked", 0)},
        "judge": judge_stats,
        "llm": deps.budget.to_dict(),
        "queries": deps.graph.query_count,
        "query_rows": deps.graph.total_rows,
        "wall_seconds": round(time.time() - t0, 1),
    }
    report = build_report(record, poi=deps.scenario.poi.as_dict(), stats=stats,
                          stop_reason=stop_reason, expand_rounds=expand["rounds"])
    if dry_run:
        report["edges"] = []
    report["scenario"] = deps.scenario.name
    report["run_id"] = record.run_id

    # 证据回填：万一某条边没有 event_id，回库按内容三元组补上（只补证据，不改三元组）。
    if not dry_run:
        all_edges = report.get("edges") or []
        resolved, unresolved = resolve_event_ids(deps.graph, all_edges)
        report["event_id_resolved"] = resolved
        report["event_id_unresolved"] = unresolved

    trace_event(deps.trace, "report", edges=len(report.get("edges") or []), stop_reason=stop_reason)
    return {"report": report, "stats": stats, "expand": expand, "stop_reason": stop_reason,
            "judge": judge_stats}
