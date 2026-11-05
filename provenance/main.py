"""Provenance-Navigator 单场景 CLI：正式 RAG v2 流程。

流程固定为两段证据：
- 规则证据：只查蒸馏规则库（Motif/Hop）；
- 技术证据：只查 ATT&CK 行为观测（BehaviorObservable/Technique）。
不再提供 rules / hybrid / llm-only 模式。
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
import navigator.pipeline as m  # noqa: E402
import llm.judge as judge_mod  # noqa: E402
from navigator import render as rag_render  # noqa: E402
from navigator.guard import enforce_citations  # noqa: E402


def _configure_rag() -> None:
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
    """执行一个场景的正式 RAG v2 调查。"""
    global _ORIGINAL_JUDGE_BUNDLES
    _configure_rag()
    fold_path = fold or str(
        REPO_ROOT / f"output/navigator-baseline/distill/fold-libraries/{scenario}.json")
    out_path = output or str(REPO_ROOT / f"output/navigator-runs/{scenario}_rag.json")

    _ORIGINAL_JUDGE_BUNDLES = judge_mod.judge_bundles
    judge_mod.judge_bundles = _guarded_judge_bundles
    rag_render.set_base_render(judge_mod.render)
    rag_render.set_scenario(scenario)
    m.RENDER_HOOK = rag_render.render
    try:
        return m.run_single_scenario(scenario, fold_path, out_path)
    finally:
        rag_render.close()
        judge_mod.judge_bundles = _ORIGINAL_JUDGE_BUNDLES


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provenance-Navigator RAG v2：规则证据 + 技术证据"
    )
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--output", default=None,
                        help="输出报告（默认 output/navigator-runs/<场景>_rag.json）")
    parser.add_argument("--fold", default=None,
                        help="折库路径（默认 output/navigator-baseline/distill/fold-libraries/<场景>.json）")
    args = parser.parse_args()
    result = run_scenario(args.scenario, output=args.output, fold=args.fold)
    print("RAG_RESULT " + json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
