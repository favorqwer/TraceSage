from prouter.layers.l1_reach.topology_indexer import TopologyFacts
from prouter.layers.l2_router.causal_filter import CausalFilter
from prouter.layers.l2_router.pattern_matcher import PatternMatcher


class HybridRouter:
    """
    神经符号智能混合分流路由器（Neuro-Symbolic Hybrid Router）：
    
    核心机制：
    1. 快速符号通道（Fast Symbolic Path）：
       - 第一步：双向因果拓扑初筛（剥离无污染的静态系统只读背景至未排除段，毫秒级降噪）；
       - 第二步：抽象因果图模式匹配（对落地执行、会话派生等强模式直接确定性确认，0 次大模型调用）。
       
    2. 慢速语义通道（Slow Semantic Path）：
       - 第三步：歧义度驱动分流。对于初筛未剔除、规则未命中的边界模糊候选事件，标记为歧义候选边。
       - 若启用大语言模型仲裁器（llm_judge），则分流至大语言模型进行上下文深层语义裁决；
       - 若处于离线纯符号模式，则安全归入未排除段（保持高查准率且零额外开销）。
    """
    def __init__(self, patterns=None, llm_judge=None):
        self.patterns = patterns or []
        self.llm_judge = llm_judge

    def route(self, confirmed_edges, unexcluded_edges):
        candidate_pool = confirmed_edges + unexcluded_edges

        # 1. 建立客观拓扑事实索引
        tf = TopologyFacts(candidate_pool)

        # 2. 通道一（初筛分流）：双向因果初筛剥离纯静态系统只读背景
        causal_filter = CausalFilter(tf)
        clean_unexcluded, pruned_background = causal_filter.filter(unexcluded_edges)

        # 3. 通道二（规则分流）：去字面化抽象图模式匹配
        matcher = PatternMatcher(tf, self.patterns)
        matched_triples = matcher.match(clean_unexcluded)

        final_confirmed_map = {}
        for e in confirmed_edges:
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            final_confirmed_map[key] = e

        rule_promoted = []
        ambiguous_candidates = []

        for e in clean_unexcluded:
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            if key in matched_triples:
                e_promoted = dict(e)
                e_promoted["origin"] = "confirmed"
                e_promoted["class"] = "story"
                e_promoted["reason"] = "快速通道：离线抽象图因果模式确定性确认"
                final_confirmed_map[key] = e_promoted
                rule_promoted.append(e_promoted)
            else:
                ambiguous_candidates.append(e)

        # 4. 通道三（模型分流）：针对歧义候选的按需深度仲裁
        llm_confirmed = []
        excluded_edges = []
        remaining_ambiguous = []

        if self.llm_judge is not None and ambiguous_candidates:
            # 同步确定性事实给判定上下文
            if hasattr(self.llm_judge, "deps") and self.llm_judge.deps is not None:
                inv = self.llm_judge.deps.record
                for k in final_confirmed_map:
                    if k in inv.edges:
                        inv.mark([k], "confirmed")
                for e in pruned_background:
                    k = (e.get("src"), e.get("syscall"), e.get("dst"))
                    if k in inv.edges:
                        inv.mark([k], "kept")

            llm_results = self.llm_judge.judge(ambiguous_candidates, tf)
            for e in llm_results.get("confirmed", []):
                key = (e.get("src"), e.get("syscall"), e.get("dst"))
                final_confirmed_map[key] = e
                llm_confirmed.append(e)
            for e in llm_results.get("excluded", []):
                excluded_edges.append(e)
            remaining_ambiguous = llm_results.get("kept", [])
        else:
            remaining_ambiguous = ambiguous_candidates

        # 组装最终未排除段
        final_unexcluded = remaining_ambiguous + pruned_background

        return {
            "confirmed": list(final_confirmed_map.values()),
            "unexcluded": final_unexcluded,
            "excluded": excluded_edges,
            "pruned_count": len(pruned_background),
            "promoted_count": len(rule_promoted),
            "ambiguous_count": len(ambiguous_candidates),
            "llm_confirmed_count": len(llm_confirmed),
            "routing_summary": {
                "fast_path_rules": len(rule_promoted),
                "fast_path_pruned": len(pruned_background),
                "slow_path_ambiguous": len(ambiguous_candidates),
                "slow_path_llm_confirmed": len(llm_confirmed),
            }
        }
