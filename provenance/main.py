"""单场景 CLI：规则证据与技术证据分离检索。

基于功能分层架构（Pipeline & Filters），执行高内聚低耦合的调查流水线：
- 规则证据：只查蒸馏规则库（Motif/Hop）；
- 技术证据：只查 ATT&CK 行为观测（BehaviorObservable/Technique）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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
    stats = enforce_citations(items, res.get("verdicts") or {})
    res["_rag_guard_stats"] = stats
    print("RAG_GUARD " + json.dumps(stats, ensure_ascii=False), flush=True)
    return res


def run_scenario(scenario: str, *, output: str | None = None,
                 fold: str | None = None) -> dict:
    """执行一个场景的正式调查。"""
    global _ORIGINAL_JUDGE_BUNDLES
    cfg_obj = _configure_rag()
    fold_path = fold or str(
        REPO_ROOT / f"output/provenance-baseline/distill/fold-libraries/{scenario}.json")
    out_path = output or str(REPO_ROOT / f"output/provenance-runs/{scenario}_rag.json")

    _ORIGINAL_JUDGE_BUNDLES = judge_mod.judge_bundles
    judge_mod.judge_bundles = _guarded_judge_bundles
    rag_render.set_base_render(judge_mod.render)
    rag_render.set_scenario(scenario)

    ctx = PipelineContext(
        scenario=scenario,
        fold_lib_path=fold_path,
        out_path=out_path,
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
        description="provenance 单场景调查：规则证据 + 技术证据"
    )
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--output", default=None,
                        help="输出报告（默认 output/provenance-runs/<场景>_rag.json）")
    parser.add_argument("--fold", default=None,
                        help="折库路径（默认 output/provenance-baseline/distill/fold-libraries/<场景>.json）")
    args = parser.parse_args()
    result = run_scenario(args.scenario, output=args.output, fold=args.fold)
    print("RAG_RESULT " + json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
