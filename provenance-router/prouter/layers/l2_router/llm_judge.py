"""
慢速语义通道：基于大语言模型的歧义候选边判定仲裁器（LlmJudge）。
与 provenance-agent 判定层完全同口径、同提示词、同数据结构，实现无缝复用与路由适配。
"""
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT / "provenance-agent") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "provenance-agent"))

from pagent.layers import l2_judge as l2
from pagent.orchestration.judging import _judge_pass, _confirm_anchor_poi
from pagent.core.llm import make_model


class LlmJudge:
    def __init__(self, deps=None, max_calls=20):
        self.deps = deps
        self.max_calls = max_calls
        if self.deps is not None and self.deps.model is None:
            self.deps.model = make_model()

    def judge(self, ambiguous_candidates: List[Dict[str, Any]], topology_facts=None) -> Dict[str, Any]:
        if self.deps is None or not ambiguous_candidates:
            return {"confirmed": [], "excluded": [], "kept": ambiguous_candidates, "calls": 0, "seconds": 0.0}

        inv = self.deps.record
        t0 = time.time()

        # 1. 提取歧义候选边的三元组集合
        triples_to_judge = set()
        for e in ambiguous_candidates:
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            if key in inv.edges:
                triples_to_judge.add(key)

        if not triples_to_judge:
            return {"confirmed": [], "excluded": [], "kept": ambiguous_candidates, "calls": 0, "seconds": 0.0}

        # 2. 装配与 Agent 完全一致的判定上下文与状态
        program_of = l2.program_table(inv.process_context)
        keyer = l2.LevelKey(program_of)
        state = l2.BundleState(anchor=l2.anchor_facts(inv.poi_rows), program_of=program_of)

        stats: Dict[str, Any] = {
            "candidates": len(triples_to_judge), "calls": 0, "seconds": 0.0, "levels": [],
            "guards": {"vacuous": 0, "fanout": {"bundles": 0, "edges": 0}, "hot": 0, "warrant": 0},
            "cap_kept_edges": 0, "missing_bundles": 0,
        }
        detail: List[Dict[str, Any]] = []

        # 3. 运行束级推进判定（仅针对歧义候选边）
        pass_res = _judge_pass(
            self.deps, triples_to_judge, keyer=keyer, state=state, inv=inv,
            stats=stats, detail=detail, pass_no=1, cap_calls=self.max_calls
        )

        elapsed = time.time() - t0

        # 4. 结算判定结论
        confirmed_edges = []
        excluded_edges = []
        kept_edges = []

        for key in triples_to_judge:
            origin = inv.origin.get(key, "kept")
            edge_rec = dict(inv.edges[key])
            if origin == "confirmed":
                edge_rec["origin"] = "confirmed"
                edge_rec["class"] = "story"
                edge_rec["reason"] = f"慢速通道：大语言模型判定整束相关 ({edge_rec.get('verdict_reason', '')})"
                confirmed_edges.append(edge_rec)
            elif origin == "excluded":
                edge_rec["origin"] = "excluded"
                edge_rec["reason"] = f"慢速通道：大语言模型判定整束无关 ({edge_rec.get('verdict_reason', '')})"
                excluded_edges.append(edge_rec)
            else:
                edge_rec["origin"] = "kept"
                kept_edges.append(edge_rec)

        return {
            "confirmed": confirmed_edges,
            "excluded": excluded_edges,
            "kept": kept_edges,
            "calls": pass_res.get("calls", 0),
            "seconds": elapsed,
        }
