"""神经符号混合编排中枢：统一调度器（RouterOrchestrator / HybridRouter）

核心机制：
支持三种执行模式：
1. "rules"（纯规则模式）：离线脱网与确定性模式，0 次大模型调用，依靠抽象基模与因果桥接；
2. "hybrid"（智能路由模式）：神经符号协同，符号通道快速初筛与规则确认，歧义边按需分流大模型；
3. "llm-only"（纯大模型模式）：罕见未知威胁模式，旁路规则匹配，全量候选边交由大模型深度审视。
"""
from typing import Any, Dict, List, Optional, Tuple
from closure.facts import TopologyFacts
from orchestrator.boundary_story import BoundaryStoryOperator
from orchestrator.bridge import CausalBridge
from orchestrator.filter import CausalFilter
from orchestrator.pivot_router import CausalPivotRouter
from rules.matcher import PatternMatcher


def _key(e: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return (e.get("src"), e.get("syscall"), e.get("dst"))


class RouterOrchestrator:
    """
    神经符号智能混合分流编排调度器。
    """
    def __init__(self, patterns: Optional[List[Dict[str, Any]]] = None,
                 llm_judge: Optional[Any] = None,
                 mode: str = "hybrid"):
        self.patterns = patterns or []
        self.llm_judge = llm_judge
        self.mode = mode.lower() if mode else "hybrid"

    def route(self, confirmed_edges: List[Dict[str, Any]],
              unexcluded_edges: List[Dict[str, Any]],
              anchor_triples: Optional[List[Tuple[Any, Any, Any]]] = None) -> Dict[str, Any]:
        candidate_pool = confirmed_edges + unexcluded_edges

        # 1. 建立客观拓扑事实索引（基于全量候选池）
        tf = TopologyFacts(candidate_pool)

        final_confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        for e in confirmed_edges:
            final_confirmed_map[_key(e)] = e

        pool_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
        for e in candidate_pool:
            pool_map.setdefault(_key(e), e)

        # 2. 通道零：终点事件锚点强制确认（不参与初筛与规则匹配）
        anchor_keys = {tuple(t) for t in (anchor_triples or [])}
        anchor_confirmed = []
        for key in anchor_keys:
            if key in final_confirmed_map:
                continue
            e = pool_map.get(key)
            if e is None:
                continue
            rec = dict(e)
            rec["origin"] = "confirmed"
            rec["class"] = "anchor"
            rec["reason"] = "告警事实锚点（POI）事实确认"
            final_confirmed_map[key] = rec
            anchor_confirmed.append(rec)

        # 3. 通道一（初筛分流）：双向因果初筛剥离纯静态系统只读背景
        channel_input = [e for e in unexcluded_edges if _key(e) not in anchor_keys]
        causal_filter = CausalFilter(tf)
        clean_unexcluded, pruned_background = causal_filter.filter(channel_input)

        rule_promoted = []
        promoted_by_motif: Dict[str, int] = {}
        # 闸门审计：本次实际生效的放行门槛取值与“被门槛否决的匹配次数”
        matcher_min_conf: Optional[float] = None
        conf_filtered_count = 0

        # 4. 通道二（规则分流与因果桥接）：仅在 rules 和 hybrid 模式下执行；llm-only 模式旁路跳过
        if self.mode in ("rules", "hybrid"):
            matcher = PatternMatcher(tf, self.patterns)
            matcher_min_conf = matcher.min_conf
            matched = matcher.match(clean_unexcluded, confirmed_seeds=final_confirmed_map)
            conf_filtered_count = matcher.filtered_by_conf

            for e in clean_unexcluded:
                key = _key(e)
                pat = matched.get(key)
                if pat is not None:
                    e_promoted = dict(e)
                    e_promoted["origin"] = "confirmed"
                    e_promoted["class"] = "story"
                    e_promoted["motif"] = pat.get("id")
                    e_promoted["motif_name"] = pat.get("name", "")
                    e_promoted["reason"] = f"快速通道：抽象图基模 {pat.get('id')} 确定性确认"
                    final_confirmed_map[key] = e_promoted
                    rule_promoted.append(e_promoted)
                    promoted_by_motif[pat.get("id")] = promoted_by_motif.get(pat.get("id"), 0) + 1

            # 4.5 神经符号拓扑会话桥接与强因果实体诱导闭环（纯图拓扑，0 次大模型调用）
            bridge = CausalBridge()
            bridged_map = bridge.bridge(clean_unexcluded, final_confirmed_map, high_conf_pids=matcher.high_conf_pids)
            for key, e_bridged in bridged_map.items():
                final_confirmed_map[key] = e_bridged
                rule_promoted.append(e_bridged)
                motif_id = e_bridged.get("motif", "CAUSAL_BRIDGE")
                promoted_by_motif[motif_id] = promoted_by_motif.get(motif_id, 0) + 1

            # 4.6 边界穿越故事通道（并列的第二条符号促进通路，只增不减）
            #     与上文 matcher/bridge 完全并列：输入同一候选池与同一已确认集合，输出合并进已确认，
            #     不替换也不删除任何既有确认边。判据见 orchestrator/boundary_story.py。
            story_map = BoundaryStoryOperator().promote(candidate_pool, final_confirmed_map)
            for key, e_story in story_map.items():
                final_confirmed_map[key] = e_story
                rule_promoted.append(e_story)
                motif_id = e_story.get("motif", "BOUNDARY_STORY")
                promoted_by_motif[motif_id] = promoted_by_motif.get(motif_id, 0) + 1

        ambiguous_candidates = [e for e in clean_unexcluded if _key(e) not in final_confirmed_map]

        # 5. 通道三（模型分流）：仅在 hybrid 和 llm-only 模式下且启用了 llm_judge 时执行
        llm_confirmed = []
        excluded_edges = []
        remaining_ambiguous = []

        if self.mode in ("hybrid", "llm-only") and self.llm_judge is not None and ambiguous_candidates:
            # 同步确定性事实给判定上下文
            if hasattr(self.llm_judge, "deps") and self.llm_judge.deps is not None:
                inv = self.llm_judge.deps.record
                for k in final_confirmed_map:
                    if k in inv.edges:
                        inv.mark([k], "confirmed")
                for e in pruned_background:
                    k = _key(e)
                    if k in inv.edges:
                        inv.mark([k], "kept")

            llm_results = self.llm_judge.judge(ambiguous_candidates, tf)
            for e in llm_results.get("confirmed", []):
                key = _key(e)
                final_confirmed_map[key] = e
                llm_confirmed.append(e)
            for e in llm_results.get("excluded", []):
                excluded_edges.append(e)
            remaining_ambiguous = llm_results.get("kept", [])
        else:
            remaining_ambiguous = ambiguous_candidates

        # 6. 通道四（因果拓扑前向影响与死端伴生碎片剪枝）：消除包管理内部伴生碎片，阻断假阳性扩散
        pivot_router = CausalPivotRouter(poi_anchors=anchor_triples)
        final_confirmed_map, debris_pruned = pivot_router.route_confirmed(final_confirmed_map, candidate_pool=candidate_pool)

        # 组装最终未排除段（被剪枝的碎片安全留存至未排除段，绝不静默丢失）
        final_unexcluded = remaining_ambiguous + pruned_background + debris_pruned

        return {
            "mode": self.mode,
            "confirmed": list(final_confirmed_map.values()),
            "unexcluded": final_unexcluded,
            "excluded": excluded_edges,
            "pruned_count": len(pruned_background),
            "promoted_count": len(rule_promoted),
            "ambiguous_count": len(ambiguous_candidates),
            "llm_confirmed_count": len(llm_confirmed),
            "anchor_confirmed_count": len(anchor_confirmed),
            "debris_pruned_count": len(debris_pruned),
            "promoted_by_motif": promoted_by_motif,
            "matcher_min_conf": matcher_min_conf,
            "conf_filtered_count": conf_filtered_count,
            "routing_summary": {
                "mode": self.mode,
                "anchor_forced": len(anchor_confirmed),
                "fast_path_rules": len(rule_promoted),
                "fast_path_pruned": len(pruned_background),
                "slow_path_ambiguous": len(ambiguous_candidates),
                "slow_path_llm_confirmed": len(llm_confirmed),
                "debris_pruned": len(debris_pruned),
            }
        }


# 提供别名以保证向后完全兼容
HybridRouter = RouterOrchestrator
NavigatorOrchestrator = RouterOrchestrator
