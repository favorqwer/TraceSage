"""RAG 全量替换试点：层级路由 + 规则证据 + 技术证据。

保留 B1 的 LevelKey / _judge_pass / 调用预算；替换：
- 系统提示词：两类证据分开，判 all 时引用 R 编号+跳号或 E 编号；
- 束级证据：规则证据只查 Motif/Hop，技术证据只查 BehaviorObservable/Technique；
- all 守卫：无证据引用、无效引用都降级为 mixed。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import settings as cfg  # noqa: E402
import experiments.run_v4_frozen as m  # noqa: E402
import llm.judge as judge_mod  # noqa: E402
from experiments import rag_render  # noqa: E402
from experiments.rag_guard import enforce_citations  # noqa: E402

m.USE_MOTIF_EVIDENCE = False
m.REAL_2HOP = True
m.VARIANT = "v5_rag_hier"
m.CONTENT_BINDING = False
m.SPLIT_EVIDENCE = False
m.ANCHOR_PAIR_CONFIRM = False
m.SUBGRAPH_EVIDENCE = False
m.STRUCTURED_OUTPUT = False

judge_mod.BUNDLE_SYSTEM = cfg.load_prompt("judge_bundle_rag.md").replace(
    "{REASON_MAX_CHARS}", str(cfg.reason_max_chars()))

_orig_judge_bundles = judge_mod.judge_bundles


def guarded_judge_bundles(model, items, listing, *, budget):
    res = _orig_judge_bundles(model, items, listing, budget=budget)
    if not res.get("ok"):
        return res
    stats = enforce_citations(items, res.get("verdicts") or {})
    res["_rag_guard_stats"] = stats
    print("RAG_GUARD " + json.dumps(stats, ensure_ascii=False), flush=True)
    return res


judge_mod.judge_bundles = guarded_judge_bundles

scenario = sys.argv[1]
fold = str(ROOT / f"output/navigator-baseline/distill/fold-libraries/{scenario}.json")
out = str(ROOT / f"tmp/rag-pilot/{scenario}_rag.json")

rag_render.set_base_render(judge_mod.render)
rag_render.set_scenario(scenario)
m.RENDER_HOOK = rag_render.render

try:
    res = m.run_single_scenario(scenario, fold, out)
finally:
    rag_render.close()

print("RAG_RESULT " + json.dumps(res, ensure_ascii=False))
