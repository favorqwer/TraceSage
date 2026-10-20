"""装配：一次调查的依赖容器（只造依赖，不跑流程、不装配报告）。

只负责造依赖：跑哪些阶段由导航器自己决定（闭包 → 符号通道 → 歧义边判定 → 三段报告）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .core import settings
from .core.db import ReadOnlyGraph
from .core.llm import LlmBudget
from .core.record import Investigation


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
    """造一次运行的依赖。"""
    settings.ensure_work_dirs()
    graph = ReadOnlyGraph(scenario.database, scenario=scenario.name, run_id=run_id)
    budget = LlmBudget()
    record = Investigation(run_id=run_id, scenario=scenario.name, database=scenario.database)
    return Deps(scenario=scenario, graph=graph, model=model, budget=budget, record=record,
                log=log)
