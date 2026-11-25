"""单场景端到端：导出 → 阶段一 → 阶段二 → 报告 + manifest。"""
from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Any

from .assemble import run_assemble
from .chunking import load_triples
from .checkpoint import ENDPOINT_IDENTITY, PROTOCOL
from .client import LlmClient
from .export_graph import export_graph
from .poi import (find_anchor_triple, load_scenarios, poi_block, resolve_anchor,
                  scenarios_fingerprint, stats_block)
from .report import build_report, write_report
from .scan import run_scan
from .settings import MODULE_ROOT, Config


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_hashes() -> dict[str, str]:
    return {p.name: _sha256(p) for p in sorted((MODULE_ROOT / "plainllm").glob("*.py"))}


def _prompt_hashes(cfg: Config) -> dict[str, str]:
    return {p.name: _sha256(p) for p in sorted(cfg.prompt_dir.glob("*.txt"))}


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def run_scenario(
    cfg: Config,
    scenario: str,
    *,
    out_dir: Path | None = None,
    resume: bool = True,
    reexport: bool = False,
) -> dict[str, Any]:
    scenarios = load_scenarios(cfg.scenarios_file)
    if scenario not in scenarios:
        raise KeyError(f"场景不存在：{scenario}（配置来自 {cfg.scenarios_file}）")
    spec = scenarios[scenario]
    database = spec["database"]
    poi_spec = spec["poi"]

    out = Path(out_dir) if out_dir else cfg.output_root / scenario
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    timings: dict[str, float] = {}
    print(f"\n=== {scenario} ===", flush=True)
    print(f"  图库 {database}，输出 {out}", flush=True)

    edges_path = out / "edges.jsonl"
    stats_path = out / "stats.json"
    stats = {}
    if resume and not reexport and edges_path.is_file() and stats_path.is_file():
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
    if (stats.get("input_protocol") == PROTOCOL and stats.get("database") == database
            and stats.get("endpoint_identity") == ENDPOINT_IDENTITY
            and stats.get("payload_preview_chars") == cfg.payload_preview_chars
            and stats.get("edges_sha256") == _sha256(edges_path)):
        triples = load_triples(edges_path)
        print(f"  复用已导出的边表：{len(triples):,} 个内容三元组", flush=True)
        timings["export"] = 0.0
    else:
        tick = time.time()
        stats = export_graph(
            cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, database, edges_path,
            payload_preview_chars=cfg.payload_preview_chars,
        )
        _write_json(stats_path, stats)
        triples = load_triples(edges_path)
        timings["export"] = time.time() - tick

    anchor = resolve_anchor(cfg, database, poi_spec)
    anchor_triple = find_anchor_triple(anchor, triples)
    if anchor_triple is None:
        raise RuntimeError(f"场景 {scenario} 的告警未映射到导出的三元组")
    poi_text = poi_block(poi_spec, anchor)
    graph_text = stats_block(stats, stats.get("vertices"))

    client = LlmClient(cfg, out / "calls.jsonl")
    try:
        tick = time.time()
        scan_result = run_scan(cfg, triples, poi_text, graph_text, out, client, scenario=scenario, resume=resume)
        timings["scan"] = time.time() - tick
        if scan_result["failed_chunks"]:
            raise RuntimeError(
                f"阻断：阶段一 {scan_result['failed_chunks']}/{scan_result['chunks']} 批失败；"
                f"调用日志见 {out / 'calls.jsonl'}"
            )

        selected_ids = set(scan_result["selected_ids"])
        selected_triples = [q for q in triples if q["id"] in selected_ids]

        tick = time.time()
        assemble_result = run_assemble(cfg, selected_triples, poi_text, out, client, scenario=scenario, resume=resume)
        timings["assemble"] = time.time() - tick
        if assemble_result["failed_batches"]:
            raise RuntimeError(
                f"阻断：阶段二 {assemble_result['failed_batches']}/{assemble_result['batches']} 批失败；"
                f"调用日志见 {out / 'calls.jsonl'}"
            )
        llm_stats = client.snapshot()
    finally:
        client.close()

    timings["total"] = time.time() - started
    report = build_report(
        scenario=scenario,
        database=database,
        poi_spec=poi_spec,
        anchor_triple=anchor_triple,
        kept=assemble_result["kept"],
        triples_by_id={q["id"]: q for q in triples},
        stats=stats,
        llm_stats=llm_stats,
        cfg=cfg,
        timings=timings,
        entry_id=assemble_result["entry"],
        story=assemble_result["story"],
    )
    write_report(report, out / "report.json")

    manifest = {
        "input_protocol": PROTOCOL,
        "endpoint_identity": ENDPOINT_IDENTITY,
        "report_sha256": _sha256(out / "report.json"),
        "scenario": scenario,
        "database": database,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(started)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": platform.python_version(),
        "repo_commit_note": "未读取 git 状态；代码指纹见 code 字段",
        "code": _code_hashes(),
        "prompts": _prompt_hashes(),
        "config": cfg.describe(),
        "config_yaml": str(cfg.config_path) if cfg.config_path else None,
        "config_sha256": _sha256(cfg.config_path) if cfg.config_path and cfg.config_path.exists() else None,
        "inputs": {
            "scenarios_file": str(cfg.scenarios_file),
            "scenarios_sha256": scenarios_fingerprint(cfg.scenarios_file),
            "edges_jsonl": str(edges_path),
            "edges_sha256": stats.get("edges_sha256"),
            "triples": stats.get("triples"),
            "instances": stats.get("instances"),
        },
        "poi": poi_spec,
        "anchor": anchor,
        "anchor_triple": anchor_triple["id"] if anchor_triple else None,
        "llm": {
            "model": cfg.model,
            "base_url": cfg.base_url,
            "temperature": cfg.temperature,
            **llm_stats,
        },
        "counts": {
            "scan_selected": len(selected_ids),
            "assembled": len(assemble_result["kept"]),
            "reported_edges": len(report["edges"]),
            "scan_batches": scan_result["chunks"],
            "scan_failed_batches": scan_result["failed_chunks"],
            "assemble_batches": assemble_result["batches"],
            "assemble_failed_batches": assemble_result["failed_batches"],
        },
        "timings": {k: round(v, 1) for k, v in timings.items()},
    }
    _write_json(out / "manifest.json", manifest)
    print(f"  完成：报告 {len(report['edges']):,} 条边，调用 {llm_stats['calls']} 次，"
          f"总耗时 {timings['total']:.1f}s", flush=True)
    return manifest
