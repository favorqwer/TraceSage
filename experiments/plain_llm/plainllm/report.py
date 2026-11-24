"""把判定结果写成可被 tools/score_report_product.py 直接评分的报告。

评分只读 edges 里的 src / syscall / dst / effect；其余字段供人工核对与成本核算。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

from .settings import Config


def build_report(
    *,
    scenario: str,
    database: str,
    poi_spec: dict[str, Any],
    anchor_quad: Optional[dict[str, Any]],
    kept: list[dict[str, str]],
    quads_by_id: dict[str, dict[str, Any]],
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

    def add(quad: dict[str, Any], phase: str) -> None:
        nonlocal missing_call
        if quad.get("call") in (None, "", "<NA>"):
            missing_call += 1
            return
        key = (quad["src"], quad["call"], quad["dst"], quad.get("effect"))
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "id": quad["id"],
            "src": quad["src"],
            "src_kind": quad.get("src_kind"),
            "syscall": quad["call"],
            "dst": quad["dst"],
            "dst_kind": quad.get("dst_kind"),
            "effect": quad.get("effect"),
            "instances": quad.get("n"),
            "first_ns": quad.get("first_ns"),
            "last_ns": quad.get("last_ns"),
            "phase": phase or "A1",
        })

    for item in kept:
        quad = quads_by_id.get(item["id"])
        if quad:
            add(quad, item.get("phase") or "A1")
    if anchor_quad:
        add(anchor_quad, "POI")

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
        "report_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "entry_edge": entry_id,
        "story": story,
        "edges": edges,
        "attack_path": attack_path,
        "input": {
            "database": database,
            "poi": poi_spec,
            "quads": stats.get("quads"),
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
