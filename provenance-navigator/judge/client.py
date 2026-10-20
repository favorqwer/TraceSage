"""慢速语义通道：基于大语言模型的歧义候选边判定仲裁器（LlmJudge / LlmJudgeClient）。

与导航器内迁入的判定底座（`foundation/layers/l2_judge/`）同口径、同提示词、同数据结构，
只把「送哪些边去判」限制在符号通道未确认的歧义边上。
"""
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

_NAV_DIR = Path(__file__).resolve().parents[1]
if str(_NAV_DIR) not in sys.path:
    sys.path.insert(0, str(_NAV_DIR))

from foundation.core import settings
from foundation.core.llm import make_model
from foundation.layers import l2_judge as l2
from foundation.orchestration.judging_pass import _judge_pass


class LlmJudge:
    """大语言模型候选边语义仲裁客户端。"""
    def __init__(self, deps=None, max_calls=None):
        self.deps = deps
        settings.load_dotenv()
        self.max_calls = max_calls if max_calls is not None else settings.bundle_cap_calls()
        if self.deps is not None and self.deps.model is None:
            self.deps.model = make_model()

    def judge(self, ambiguous_candidates: List[Dict[str, Any]], topology_facts=None) -> Dict[str, Any]:
        if self.deps is None or not ambiguous_candidates:
            return {"confirmed": [], "excluded": [], "kept": ambiguous_candidates, "calls": 0, "seconds": 0.0}

        inv = self.deps.record
        t0 = time.time()

        # 1. 提取歧义候选边的三元组集合（不在候选清单里的边原样保留，绝不静默丢弃）
        triples_to_judge = set()
        missing_edges = []
        for e in ambiguous_candidates:
            key = (e.get("src"), e.get("syscall"), e.get("dst"))
            if key in inv.edges:
                triples_to_judge.add(key)
            else:
                missing_edges.append(e)

        if not triples_to_judge:
            return {"confirmed": [], "excluded": [], "kept": list(ambiguous_candidates), "calls": 0, "seconds": 0.0}

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
            "kept": kept_edges + missing_edges,
            "calls": pass_res.get("calls", 0),
            "seconds": elapsed,
        }


# 提供别名
LlmJudgeClient = LlmJudge
