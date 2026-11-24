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
from core.reporting import (
    RouteOutcome,
    build_events_export,
    build_report_from_outcome,
    default_events_path,
    save_events_export,
    save_report,
)
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
    deps: Any = None,
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

    confirmed_edges_list = list(report["edges"])
    unexcluded_edges_list = list(report["unexcluded"])
    report["edges"].extend(report["unexcluded"])
    report["stats"]["retained_count"] = len(report["edges"])
    report["stats"]["prefilter_deferred_count"] = len(pruned_background)
    report["stats"]["postfilter_deferred_count"] = len(debris_pruned)
    if temporal_stats is not None:
        report["stats"]["temporal_pruning"] = temporal_stats
    save_report(report, ctx.out_path, overwrite=False)

    events_file: str | None = None
    events_count: int | None = None
    rec_obj = getattr(deps, "record", None)
    closure_events = getattr(rec_obj, "closure_events", None)
    raw_events = getattr(rec_obj, "raw_events", None)
    if closure_events or raw_events:
        if closure_events and not raw_events:
            from closure.fold import event_to_raw_dict
            retained_eids = {
                int(eid)
                for edge in report["edges"]
                for eid in (edge.get("event_ids") or ())
            }
            raw_events = [event_to_raw_dict(ev) for ev in closure_events if ev.event_id in retained_eids]
            vertex_attrs: Dict[str, Dict[str, Any]] = {}
            tsg_path = str(getattr(rec_obj, "tsg_path", "") or "")
            if tsg_path and Path(tsg_path).is_file():
                if str(cfg.REPO_ROOT) not in sys.path:
                    sys.path.insert(0, str(cfg.REPO_ROOT))
                from tsg.format import TSGReader
                with TSGReader(tsg_path) as tsg_r:
                    for ev in raw_events:
                        for kind, key in ((ev["src_kind"], ev["src_key"]), (ev["dst_kind"], ev["dst_key"])):
                            vkey = f"{kind}:{key}"
                            if vkey not in vertex_attrs:
                                vid = tsg_r.find_vertex_id(kind, key)
                                vertex_attrs[vkey] = (
                                    dict(tsg_r.vertex_props(vid)) if vid is not None else {"kind": kind, "key": key}
                                )
        else:
            vertex_attrs = getattr(rec_obj, "vertex_attrs", None) or {}
        events_payload = build_events_export(
            ctx.scenario,
            str(getattr(rec_obj, "database", "") or ""),
            confirmed_edges=confirmed_edges_list,
            unexcluded_edges=unexcluded_edges_list,
            raw_events=raw_events,
            vertex_attrs=vertex_attrs,
            poi_rows=getattr(rec_obj, "poi_rows", None) or [],
        )
        events_out = save_events_export(events_payload, default_events_path(ctx.out_path), overwrite=False)
        events_file = str(events_out)
        events_count = len(events_payload["events"])

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
        **({"events_file": events_file, "retained_events": events_count} if events_file is not None else {}),
    }
