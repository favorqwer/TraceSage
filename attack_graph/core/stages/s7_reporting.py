"""阶段 7：输出完整保留图，并按交付内容评分。"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import settings as cfg
tools_dir = cfg.REPO_ROOT / "tools"
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))
import score_report_product as scorer
from core.reporting import RouteOutcome, build_report_from_outcome, save_report
from core.context import PipelineContext


def run(
    ctx: PipelineContext,
    final_confirmed_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
    final_unexcluded: List[Dict[str, Any]],
    final_excluded: List[Dict[str, Any]],
    pruned_background: List[Dict[str, Any]],
    ambiguous_candidates: List[Dict[str, Any]],
    llm_confirmed: List[Dict[str, Any]],
    debris_pruned: List[Dict[str, Any]],
    audit_dict: Dict[str, Any],
    temporal_stats: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    outcome = RouteOutcome(
        confirmed=final_confirmed_map,
        unexcluded=final_unexcluded,
        excluded=final_excluded,
        audit={
            "mode": "hybrid-rule-context-v4",
            "pruned_count": len(final_excluded),
            "ambiguous_count": len(ambiguous_candidates),
            "llm_confirmed_count": len(llm_confirmed),
            "anchor_confirmed_count": len(ctx.anchor_keys),
            "debris_pruned_count": len(debris_pruned),
        },
    )

    elapsed = time.time() - ctx.t0
    report = build_report_from_outcome(
        outcome,
        ctx.scenario,
        elapsed_seconds=elapsed,
        llm_calls=ctx.budget.calls,
        llm_enabled=True,
        library={
            "path": audit_dict.get("path"),
            "mode": "hybrid-rule-context-v4",
            "n_selected": len(audit_dict.get("selected") or []),
            "n_candidates": len(audit_dict.get("motifs") or []),
            "fold_library": True,
            "test_scenario": ctx.scenario,
            "variant": ctx.config.variant,
            "motif_evidence": ctx.config.use_motif_evidence,
            "real_2hop": ctx.config.real_2hop,
            "content_binding": ctx.config.content_binding,
            "split_evidence": ctx.config.split_evidence,
            "motif_candidates": len(ambiguous_candidates),
            "residual_candidates": 0,
            "anchor_pair_confirm": ctx.config.anchor_pair_confirm,
            "subgraph_evidence": ctx.config.subgraph_evidence,
            "structured_output": ctx.config.structured_output,
            **({"replay_trace": ctx.replay_trace} if ctx.replay_trace else {}),
        },
    )

    report["edges"].extend(report["unexcluded"])
    report["stats"]["retained_count"] = len(report["edges"])
    report["stats"]["prefilter_deferred_count"] = len(pruned_background)
    report["stats"]["postfilter_deferred_count"] = len(debris_pruned)
    if temporal_stats is not None:
        report["stats"]["temporal_pruning"] = temporal_stats
    save_report(report, ctx.out_path, overwrite=False)

    # 官方评分
    gt_path = str(cfg.REPO_ROOT / f"groundtruth/{ctx.scenario}.groundtruth.json")
    ev = scorer.evaluate(ctx.out_path, gt_path, scenario=ctx.scenario)

    recall_pct = ev["recall"] * 100
    precision_pct = ev["precision"] * 100
    print(
        f"[{time.strftime('%H:%M:%S')}] <<< 完成场景: {ctx.scenario} | "
        f"召回: {recall_pct:.1f}% ({ev['steps_hit']}/{ev['steps_total']}) | "
        f"查准: {precision_pct:.1f}% ({ev['correct_edges']}/{ev['reported_triples']}) | "
        f"保留边数: {report['stats']['retained_count']}，其中确认 {len(final_confirmed_map)} | 耗时: {elapsed:.1f}s | "
        f"LLM调用: {ctx.budget.calls}次"
    )

    return {
        "scenario": ctx.scenario,
        "recall": ev["recall"],
        "steps_hit": ev["steps_hit"],
        "steps_total": ev["steps_total"],
        "must_hit": ev["must_hits"],
        "must_total": ev["gt_edges"],
        "rules_hit": ev["rule_hits"],
        "rules_total": ev["rules_total"],
        "precision": ev["precision"],
        "correct_edges": ev["correct_edges"],
        "reported_triples": ev["reported_triples"],
        "confirmed_edges": len(final_confirmed_map),
        "retained_edges": report["stats"]["retained_count"],
        "temporal_pruning": temporal_stats,
        "llm_calls": ctx.budget.calls,
        "elapsed": elapsed,
        "report_file": ctx.out_path,
    }
