"""场景调查执行器 (InvestigationRunner)。

按高内聚低耦合原则装配各个流水线独立阶段，替代旧的过程式上帝函数。
"""
from __future__ import annotations

import time
from typing import Any, Dict

from core.context import PipelineConfig, PipelineContext
from core.stages import (
    s1_closure,
    s2_prefilter,
    s3_evidence,
    s4_decision,
    s5_causal_heal,
    s6_pruning,
    s7_reporting,
)
from core import render as rag_render
import llm.judge as judge_mod


class InvestigationRunner:
    """端到端溯源图调查执行器。"""

    def __init__(self, render_hook: Any = None):
        self.render_hook = render_hook

    def run(self, ctx: PipelineContext) -> Dict[str, Any]:
        t0 = time.time()
        ctx.t0 = t0
        print(f"\n[{time.strftime('%H:%M:%S')}] >>> 开始执行场景: {ctx.scenario}")

        # 阶段 1: 规则库加载、闭包抽取、锚点确认
        (
            raw_edges, closure_stats, deps,
            final_confirmed, anchor_triples, anchor_keys,
            pool, tf, rule_lib_tuple
        ) = s1_closure.run(ctx)

        # 阶段 2: 静态初筛
        clean_unexcluded, pruned_background = s2_prefilter.run(raw_edges, anchor_keys, tf)

        # 阶段 3: 证据匹配与拓扑血缘
        matcher, rule_evidence_map, parent_map, ambiguous_candidates = s3_evidence.run(
            ctx, clean_unexcluded, raw_edges, pool, tf, rule_lib_tuple, final_confirmed
        )

        # 注册上下文到渲染器
        rag_render.set_matcher(matcher)
        rag_render.set_parent_map(parent_map)

        # 阶段 4: LLM 智能判定 (带渲染钩子隔离)
        original_render = judge_mod.render
        if self.render_hook is not None:
            judge_mod.render = self.render_hook
        try:
            llm_confirmed, excluded_edges, remaining_ambiguous = s4_decision.run(
                ctx, ambiguous_candidates, tf, deps, rule_evidence_map
            )
        finally:
            judge_mod.render = original_render

        # 阶段 5: 因果公理闭环与纯化
        purified_confirmed, unpromoted_ambiguous = s5_causal_heal.run(
            llm_confirmed, final_confirmed, clean_unexcluded, excluded_edges, anchor_keys
        )

        # 阶段 6: 后置剪枝
        final_confirmed_map, debris_pruned, final_unexcluded, final_excluded = s6_pruning.run(
            ctx, purified_confirmed, pool, unpromoted_ambiguous, pruned_background,
            remaining_ambiguous, excluded_edges
        )

        # 阶段 7: 报告与评分
        patterns, admitted, audit, role_cuts = rule_lib_tuple
        return s7_reporting.run(
            ctx,
            final_confirmed_map=final_confirmed_map,
            final_unexcluded=final_unexcluded,
            final_excluded=final_excluded,
            pruned_background=pruned_background,
            ambiguous_candidates=ambiguous_candidates,
            llm_confirmed=llm_confirmed,
            debris_pruned=debris_pruned,
            audit_dict=audit,
        )
