"""阶段 4：大模型智能判定与引用守卫执行。"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from domain.edge import edge_key
from llm.client import set_trace_raw
from llm.judge import LlmChannel, set_trace_sink
from core.context import PipelineContext


def run(
    ctx: PipelineContext,
    ambiguous_candidates: List[Dict[str, Any]],
    tf: Any,
    deps: Any,
    rule_evidence_map: Dict[Tuple[Any, Any, Any], Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    trace_path = Path(ctx.out_path).with_suffix(".trace.jsonl")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_lock = threading.Lock()
    code_version = "b1-frozen-9c11503"

    def _trace_sink(payload: Dict[str, Any]) -> None:
        items = []
        for item in payload.get("items", []):
            rec = dict(item)
            rec["evidence_ids"] = sorted({
                str(rule_evidence_map[tuple(t)].get("motif_id"))
                for t in item.get("members", [])
                if tuple(t) in rule_evidence_map
            })
            rec["rag_rule_ids"] = list(item.get("rag_rule_ids")
                                       or item.get("_rag_rule_ids") or [])
            items.append(rec)
        record = {
            "scenario": ctx.scenario,
            "code_version": code_version,
            "ts": time.time(),
            "level_name": payload.get("level_name"),
            "items": items,
            "listing": payload.get("listing", ""),
            "result": payload.get("result", {}),
        }
        with trace_lock:
            with trace_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    set_trace_sink(_trace_sink)
    set_trace_raw(True)
    trace_details: List[Dict[str, Any]] = []

    deps.budget = ctx.budget
    llm_channel = LlmChannel(deps=deps)

    llm_results = llm_channel.judge(ambiguous_candidates, tf)
    llm_confirmed = llm_results.get("confirmed", [])
    excluded_edges = llm_results.get("excluded", [])
    remaining_ambiguous = llm_results.get("kept", [])
    trace_details.extend(llm_results.get("detail") or [])

    set_trace_sink(None)
    set_trace_raw(False)
    with trace_lock:
        with trace_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "scenario": ctx.scenario, "code_version": code_version,
                "kind": "detail", "detail": trace_details,
            }, ensure_ascii=False, default=str) + "\n")

    return llm_confirmed, excluded_edges, remaining_ambiguous
