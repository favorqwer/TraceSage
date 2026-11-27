"""单场景 CLI：完整调查流程与训练折规则检索。"""
from __future__ import annotations

import argparse
import json
import sys
from math import ceil
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
from core.bundling import LevelKey, build_levels, program_table  # noqa: E402


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
                 fold: str | None = None, replay_trace: str | None = None,
                 request_limit: int | None = None) -> dict:
    """执行一个场景的正式调查。"""
    global _ORIGINAL_JUDGE_BUNDLES
    cfg.load_dotenv()
    if request_limit is not None and (request_limit <= 0 or cfg.llm_sdk_retries()):
        raise ValueError("请求预算模式需要正数上限，且接口 SDK 的内部重试必须关闭")
    cfg_obj = _configure_rag()
    fold_path = fold or str(cfg.fold_library_dir() / f"{scenario}.json")
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
    ctx.budget.request_limit = request_limit
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
                        help="折库路径（默认 output/rule-kg/v1/fold-libraries/<场景>.json）")
    parser.add_argument("--replay-trace", default=None,
                        help="从已有 .trace.jsonl 重放大模型判定，跳过真实 LLM 调用")
    parser.add_argument("--preflight", action="store_true",
                        help="执行候选抽取与证据准备，输出模型批次的结构上界")
    parser.add_argument("--request-limit", type=int, help="模型请求达到上限即停止运行")
    args = parser.parse_args()
    if args.preflight:
        if args.output or args.replay_trace or args.request_limit is not None:
            parser.error("--preflight 不接受运行输出、重放或模型额度参数")
        cfg.load_dotenv()
        rag_render.set_scenario(args.scenario)
        try:
            ctx = PipelineContext(
                scenario=args.scenario,
                fold_lib_path=args.fold or str(cfg.fold_library_dir() / f"{args.scenario}.json"),
                out_path="", config=_configure_rag(),
            )
            deps, _, anchors, _, _, _, _, _, _, candidates = InvestigationRunner().prepare(ctx)
            if not anchors:
                raise RuntimeError(f"未能定位告警锚点：{args.scenario}")
            triples = {(row["src"], row["syscall"], row["dst"]) for row in candidates}
            inv = deps.record
            eligible = triples.intersection(inv.edges)
            levels = build_levels(eligible, inv.edges, LevelKey(program_table(inv.process_context)))
            batches = [ceil(len(level) / cfg.bundle_batch()) for level in levels]
            print("TRIPLET_PREFLIGHT " + json.dumps({
                "scenario": args.scenario, "poi_instances": len(inv.poi_rows),
                "model": cfg.llm_model(), "credential_configured": bool(cfg.llm_api_key()),
                "judged_candidates": len(eligible), "level_batches": batches,
                "estimated_first_level_batches": batches[0], "max_distinct_batches": sum(batches),
                "concurrency": cfg.max_concurrency(), "requests_sent": 0,
            }, ensure_ascii=False))
        finally:
            rag_render.close()
        return 0
    result = run_scenario(
        args.scenario, output=args.output, fold=args.fold, replay_trace=args.replay_trace,
        request_limit=args.request_limit,
    )
    print("RAG_RESULT " + json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
