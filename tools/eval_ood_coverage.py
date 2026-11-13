#!/usr/bin/env python3
"""Out-of-sample coverage: apply the mined library to graphs that were never
used for mining (the TC_E3 windows), plus the in-sample scenarios as a control.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import eval_flexis_effect as efe  # noqa: E402

KG = ROOT / "output" / "rule-kg" / "flexis-exact-v1"

OOD = (
    ("TC_E3_THEIA_20180410", "TC_E3_THEIA_20180410-cdm"),
    ("TC_E3_THEIA_20180412", "TC_E3_THEIA_20180412-cdm"),
    ("TC_E3_THEIA_20180413", "TC_E3_THEIA_20180413-cdm"),
    ("TC_E3_TRACE_20180413", "TC_E3_TRACE_20180413-cdm"),
    ("TC_E3_TRACE_20180413_AM", "TC_E3_TRACE_20180413_AM-cdm"),
    ("TC_E3_TRACE_20180413_PM", "TC_E3_TRACE_20180413_PM-cdm"),
)


def library_patterns(parsed: dict, kmin: int, network_free: bool) -> list:
    pats = [p for p in parsed["aggregate"]["patterns"] if p["size"] >= kmin]
    if network_free:
        pats = [p for p in pats if not any(str(v).startswith("N") for v in p["vertices"])]
    return pats


def evaluate(scenario: str, dirname: str, graph_dir: Path, pats: list) -> dict:
    graph = efe.build_scenario(scenario, dirname, graph_dir)
    matched = efe.match_patterns(graph, pats)
    matched.pop("_unbound_patterns", None)
    covered = set()
    for arcs in matched.values():
        covered |= arcs
    covered_edges = sum(graph["orig"][a] for a in covered)
    gt_cov = sum(graph["gt_on_arc"][a] for a in covered)
    return {
        "scenario": scenario,
        "vertices": graph["n"],
        "arcs": graph["nz"],
        "parser_edges": graph["parser_edges"],
        "patterns": len(pats),
        "patterns_matched": sum(1 for v in matched.values() if v),
        "covered_arcs": len(covered),
        "coverage_arcs": len(covered) / graph["nz"] if graph["nz"] else 0.0,
        "covered_edges": covered_edges,
        "coverage_edges": covered_edges / graph["parser_edges"] if graph["parser_edges"] else 0.0,
        "gt_edges": graph["gt_edges"],
        "gt_covered": gt_cov,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parsed", default=str(KG / "parsed-k3-t20-a09.json"))
    ap.add_argument("--in-sample-graphs", default=str(KG / "graphs"))
    ap.add_argument("--ood-graphs", default=str(KG / "graphs-ood"))
    ap.add_argument("--kmin", type=int, default=3)
    ap.add_argument("--network-free", action="store_true", default=True)
    ap.add_argument("--out", default=str(KG / "ood-coverage.json"))
    args = ap.parse_args()

    parsed = json.loads(Path(args.parsed).read_text(encoding="utf-8"))
    pats = library_patterns(parsed, args.kmin, args.network_free)
    print(f"library: {len(pats)} patterns (kmin={args.kmin}, network_free={args.network_free})", flush=True)

    rows = []
    print("\n--- in-sample (used for mining) ---")
    for scenario, dirname in efe.SCENARIOS:
        r = evaluate(scenario, dirname, Path(args.in_sample_graphs), pats)
        rows.append({"set": "in_sample", **r})
        print(f"  {scenario[:34]:34s} edges={r['parser_edges']:9d} coverage={100*r['coverage_edges']:6.2f}% "
              f"matched_patterns={r['patterns_matched']:5d}", flush=True)

    print("\n--- out-of-sample (never mined) ---")
    for scenario, dirname in OOD:
        r = evaluate(scenario, dirname, Path(args.ood_graphs), pats)
        rows.append({"set": "ood", **r})
        print(f"  {scenario[:34]:34s} edges={r['parser_edges']:9d} coverage={100*r['coverage_edges']:6.2f}% "
              f"matched_patterns={r['patterns_matched']:5d}", flush=True)

    ins = [r for r in rows if r["set"] == "in_sample"]
    ood = [r for r in rows if r["set"] == "ood"]
    def agg(rs):
        edges = sum(r["parser_edges"] for r in rs)
        cov = sum(r["covered_edges"] for r in rs)
        return cov, edges, cov / edges if edges else 0.0
    ci, ei, ri = agg(ins)
    co, eo, ro = agg(ood)
    print(f"\nin-sample     covered={ci}/{ei} = {100*ri:.2f}%")
    print(f"out-of-sample covered={co}/{eo} = {100*ro:.2f}%")
    Path(args.out).write_text(json.dumps({"rows": rows,
                                          "summary": {"in_sample": ri, "ood": ro,
                                                      "library_size": len(pats)}},
                                         ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
