"""把判定结果写成可被 tools/score_report_product.py 直接评分的报告。

评分按 edges 中的 src / syscall / dst 去重。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from .settings import Config
from .checkpoint import ENDPOINT_IDENTITY
from .chunking import triple_key


def build_report(
    *,
    scenario: str,
    database: str,
    poi_spec: dict[str, Any],
    anchor_triple: Optional[dict[str, Any]],
    kept: list[dict[str, str]],
    triples_by_id: dict[str, dict[str, Any]],
    stats: dict[str, Any],
    llm_stats: dict[str, Any],
    cfg: Config,
    timings: dict[str, float],
    entry_id: str,
    story: str,
) -> dict[str, Any]:
    edges: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    missing_call = 0

    def add(triple: dict[str, Any], phase: str) -> None:
        nonlocal missing_call
        if triple.get("call") in (None, "", "<NA>"):
            missing_call += 1
            return
        key = triple_key(triple)
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "id": triple["id"],
            "src": triple["src"],
            "src_kind": triple.get("src_kind"),
            "syscall": triple["call"],
            "dst": triple["dst"],
            "dst_kind": triple.get("dst_kind"),
            "instances": triple.get("n"),
            "first_ns": triple.get("first_ns"),
            "last_ns": triple.get("last_ns"),
            "phase": phase or "A1",
        })

    for item in kept:
        triple = triples_by_id.get(item["id"])
        if triple:
            add(triple, item.get("phase") or "A1")
    if anchor_triple:
        add(anchor_triple, "POI")

    edges.sort(key=lambda e: (e.get("first_ns") if e.get("first_ns") is not None else 0))

    phases: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        phases.setdefault(edge["phase"], []).append(edge)
    attack_path = [
        {"id": name, "phase": name, "edges": items}
        for name, items in sorted(phases.items(), key=lambda kv: (
            kv[1][0].get("first_ns") if kv[1][0].get("first_ns") is not None else 0, kv[0]))
    ]

    return {
        "scenario": scenario,
        "report_version": 2,
        "input_protocol": "triplet-v1",
        "endpoint_identity": ENDPOINT_IDENTITY,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "entry_edge": entry_id,
        "story": story,
        "edges": edges,
        "attack_path": attack_path,
        "input": {
            "database": database,
            "poi": poi_spec,
            "triples": stats.get("triples"),
            "instances": stats.get("instances"),
            "time_range_ns": [stats.get("first_ns"), stats.get("last_ns")],
        },
        "llm": {
            "model": cfg.model,
            "chunk_size": cfg.chunk_size,
            "assemble_chunk": cfg.assemble_chunk,
            "concurrency": cfg.concurrency,
            **llm_stats,
        },
        "selection": {
            "reported_edges": len(edges),
            "dropped_missing_syscall": missing_call,
        },
        "timings": {k: round(v, 1) for k, v in timings.items()},
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
