"""单次调查装配：闭包 → 规则库 → 路由 → 三段报告。

两个入口（`main.py`、`run_leave_one_out.py`）只负责 CLI 与折循环，不再各自复制装配逻辑。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from closure import extract_raw_closure, list_scenarios
from common import config as cfg
from llm.judge import LlmChannel
from routing.report import build_report_from_outcome, save_report
from routing.route import route
from rules import offline as frozen
from rules.offline import OfflineDistiller


def load_rule_matcher() -> Any:
    """加载评测口径的规则匹配器；只在 fresh 蒸馏时使用。"""
    tools = cfg.REPO_ROOT / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    import rules_match
    return rules_match


def make_pool_provider() -> Callable[[str], List[Dict[str, Any]]]:
    """训练候选池提供器：同一运行期内每个场景只现算一次轻量闭包。"""
    cache: Dict[str, List[Dict[str, Any]]] = {}

    def provider(scenario: str) -> List[Dict[str, Any]]:
        if scenario not in cache:
            edges, _stats = extract_raw_closure(scenario, light=True)
            cache[scenario] = edges
        return cache[scenario]

    return provider


def load_patterns(mode: str, rules_from: str, *,
                  scenarios: Optional[List[str]] = None,
                  pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                  rule_matcher: Any = None,
                  library: Optional[tuple] = None) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """按模式与来源取规则清单；llm-only 不读规则库。"""
    if mode == "llm-only":
        return [], {}
    if library is not None:
        patterns, audit = library
        return list(patterns), dict(audit)
    if rules_from == "frozen":
        patterns, audit = frozen.load_library()
        print(f"  规则库：{audit['path']}（生成于 {audit.get('generated_at')}，"
              f"训练场景 {len(audit['train_scenarios'])} 个）→ 入选规则 {len(patterns)} 条")
        return patterns, audit

    train_scenarios = list(scenarios or list_scenarios())
    provider = pool_provider or make_pool_provider()
    distiller = OfflineDistiller(rule_matcher=rule_matcher or load_rule_matcher())
    patterns = distiller.distill(train_scenarios, pool_provider=provider)
    print(f"  现蒸馏规则库：训练集 = {len(train_scenarios)} 个场景 → 入选 {len(patterns)} 条")
    return patterns, dict(distiller.last_report)


def investigate(scenario_name: str, *,
                mode: str = "rules",
                rules_from: str = "frozen",
                input_report: Optional[str] = None,
                output_report: Optional[str] = None,
                pool_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                rule_matcher: Any = None,
                train_scenarios: Optional[List[str]] = None,
                library: Optional[tuple] = None,
                return_audit: bool = False) -> Any:
    """跑一次完整调查，返回报告字典（同时落盘到 output_report）。"""
    start_time = time.time()
    closure_stats: Dict[str, Any] = {}
    if not output_report:
        output_report = f"output/navigator-runs/{scenario_name}.json"

    all_scenarios = list_scenarios()
    if scenario_name not in all_scenarios:
        raise KeyError(f"未知场景 {scenario_name}；可选场景: {all_scenarios}")

    need_deps = mode in ("hybrid", "llm-only")
    deps = None
    anchor_triples: List[tuple] = []

    if input_report:
        if not Path(input_report).exists():
            raise FileNotFoundError(f"未找到输入候选文件: {input_report}")
        with open(input_report, "r", encoding="utf-8") as f:
            data = json.load(f)
        confirmed_edges = data.get("edges", [])
        unexcluded_edges = data.get("unexcluded", [])
        excluded_edges = data.get("excluded", [])
        print(f"[{scenario_name}] 从已有报告加载: {input_report} "
              f"(确认边={len(confirmed_edges)}, 未排除={len(unexcluded_edges)})")
    else:
        print(f"[{scenario_name}] 正在直连 Neo4j 图数据库，从 POI 终点事件自主展开反向因果闭包...")
        if need_deps:
            raw_edges, closure_stats, deps = extract_raw_closure(
                scenario_name, return_deps=True
            )
        else:
            raw_edges, closure_stats = extract_raw_closure(scenario_name, return_deps=False)
        anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]
        confirmed_edges = []
        unexcluded_edges = raw_edges
        excluded_edges = []
        print(f"[{scenario_name}] 因果闭包完成: 原始候选边={len(raw_edges)} 条 "
              f"(闭包耗时: {closure_stats['closure_time_seconds']:.2f}s, "
              f"POI 锚点 {len(anchor_triples)} 条)")

    patterns, library_audit = load_patterns(
        mode, rules_from, scenarios=train_scenarios, pool_provider=pool_provider,
        rule_matcher=rule_matcher, library=library,
    )

    t_route_0 = time.time()
    llm_channel = LlmChannel(deps=deps) if (need_deps and deps is not None) else None
    outcome = route(
        confirmed_edges,
        unexcluded_edges,
        anchor_triples=anchor_triples,
        patterns=patterns,
        llm_channel=llm_channel,
        mode=mode,
    )
    route_time = time.time() - t_route_0

    elapsed = time.time() - start_time
    llm_calls = deps.budget.calls if (deps and deps.budget) else 0
    report = build_report_from_outcome(
        outcome, scenario_name,
        elapsed_seconds=elapsed,
        llm_calls=llm_calls,
        llm_enabled=need_deps,
    )
    Path(output_report).parent.mkdir(parents=True, exist_ok=True)
    save_report(report, output_report)

    audit = dict(outcome.audit)
    audit.update({
        "raw_closure_edges": len(raw_edges),
        "closure_seconds": float(closure_stats.get("closure_time_seconds") or 0.0),
        "anchor_count": len(anchor_triples),
        "route_seconds": route_time,
        "elapsed_seconds": elapsed,
        "library_audit": library_audit,
    })
    print(f"[{scenario_name}] 调查完成（模式: {mode}）:")
    print(f"  已确认边数: {len(report['edges'])} 条 "
          f"(锚点强制确认 {audit['anchor_confirmed_count']} 条)")
    print(f"  因果初筛剥离背景: {audit['pruned_count']} 条")
    print(f"  抽象基模与桥接确认: {audit['promoted_count']} 条 "
          f"({', '.join(f'{k}×{v}' for k, v in audit['promoted_by_motif'].items()) or '无'})")
    print(f"  大模型仲裁确认: {audit['llm_confirmed_count']} 条 (模型调用: {llm_calls} 次)")
    print(f"  未排除保留候选边: {len(report['unexcluded'])} 条")
    print(f"  总耗时: {elapsed:.2f} 秒 (图闭包: {elapsed - route_time:.2f}s, "
          f"符号路由: {route_time:.3f}s)")
    print(f"  输出报告: {output_report}")
    return (report, audit) if return_audit else report
