"""单场景 CLI：完整调查流程与训练折规则检索。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import uuid4

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import settings as cfg  # noqa: E402
import llm.judge as judge_mod  # noqa: E402
from core import render as rag_render  # noqa: E402
from llm.guard import enforce_citations  # noqa: E402
from core.context import PipelineConfig, PipelineContext  # noqa: E402
from core.runner import InvestigationRunner  # noqa: E402


def _configure_rag() -> PipelineConfig:
    judge_mod.BUNDLE_SYSTEM = cfg.render_prompt(
        "system_judge.md", REASON_MAX_CHARS=str(cfg.reason_max_chars()))
    return PipelineConfig(
        variant="v5_rag_hier",
        use_motif_evidence=False,
        real_2hop=True,
        content_binding=False,
        split_evidence=False,
        anchor_pair_confirm=False,
        subgraph_evidence=False,
        structured_output=False,
    )


_ORIGINAL_JUDGE_BUNDLES = None


def _guarded_judge_bundles(model, items, listing, *, budget):
    res = _ORIGINAL_JUDGE_BUNDLES(model, items, listing, budget=budget)
    if not res.get("ok"):
        return res
    if res.get("_replayed"):
        return res
    stats = enforce_citations(items, res.get("verdicts") or {})
    res["_rag_guard_stats"] = stats
    print("RAG_GUARD " + json.dumps(stats, ensure_ascii=False), flush=True)
    return res


def run_scenario(scenario: str, *, output: str | None = None,
                 fold: str | None = None, replay_trace: str | None = None) -> dict:
    """执行一个场景的正式调查。"""
    global _ORIGINAL_JUDGE_BUNDLES
    cfg_obj = _configure_rag()
    fold_path = fold or str(
        REPO_ROOT / f"output/provenance-baseline/distill/fold-libraries/{scenario}.json")
    out_path = (Path(output).resolve() if output else
                REPO_ROOT / "output" / "attack-graph-runs" / uuid4().hex / "report.json")
    if any(out_path.is_relative_to((REPO_ROOT / "output" / directory).resolve())
           for directory in ("attack-graph-baseline", "provenance-baseline", "engine-baseline")):
        raise ValueError("当次运行产物必须写到正式基线目录之外")
    if out_path.exists() or out_path.with_suffix(".trace.jsonl").exists():
        raise FileExistsError(f"报告或分析记录已存在，请使用新的输出路径：{out_path}")

    _ORIGINAL_JUDGE_BUNDLES = judge_mod.judge_bundles
    judge_mod.judge_bundles = _guarded_judge_bundles
    rag_render.set_base_render(judge_mod.render)
    rag_render.set_scenario(scenario)

    ctx = PipelineContext(
        scenario=scenario,
        fold_lib_path=fold_path,
        out_path=str(out_path),
        replay_trace=replay_trace,
        config=cfg_obj,
    )
    runner = InvestigationRunner(render_hook=rag_render.render)
    try:
        return runner.run(ctx)
    finally:
        rag_render.close()
        judge_mod.judge_bundles = _ORIGINAL_JUDGE_BUNDLES


def main() -> int:
    parser = argparse.ArgumentParser(
        description="attack_graph 单场景调查：保留确认与待复核候选"
    )
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--output", default=None,
                        help="输出报告（默认 output/attack-graph-runs/<运行编号>/report.json）")
    parser.add_argument("--fold", default=None,
                        help="折库路径（默认 output/provenance-baseline/distill/fold-libraries/<场景>.json）")
    parser.add_argument("--replay-trace", default=None,
                        help="从已有 .trace.jsonl 重放大模型判定，跳过真实 LLM 调用")
    args = parser.parse_args()
    result = run_scenario(
        args.scenario, output=args.output, fold=args.fold, replay_trace=args.replay_trace
    )
    print("RAG_RESULT " + json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
