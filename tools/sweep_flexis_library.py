#!/usr/bin/env python3
"""Sweep the library admission knobs and report coverage vs GT coverage.

For every (min_scenario_support, min_pattern_size) cell this reports, over all
10 scenarios:
  coverage_edges   original parser edges carried by covered arcs / all edges
  gt_covered       GT attack edges sitting on covered arcs / all GT edges

The graphs are built once per scenario and reused for every cell.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import eval_flexis_effect as efe  # noqa: E402

KG = ROOT / "output" / "rule-kg" / "flexis-exact-v1"


def main() -> None:
    ap = argparse.ArgumentParser(description="Sweep library admission knobs")
    ap.add_argument("--parsed", default=str(KG / "parsed-k3-t20-a09.json"))
    ap.add_argument("--graphs", default=str(KG / "graphs"))
    ap.add_argument("--out", default=str(KG / "sweep-k3-t20-a09.json"))
    ap.add_argument("--supports", default="1,2,3,4")
    ap.add_argument("--sizes", default="2,3")
    ap.add_argument("--variants", default="none",
                    help="none | network-free (drop patterns containing a Network vertex)")
    args = ap.parse_args()

    parsed = json.loads(Path(args.parsed).read_text(encoding="utf-8"))
    graph_dir = Path(args.graphs)
    support_map = {p["render"]: p["scenario_support"] for p in parsed["aggregate"]["patterns"]}

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    cells: List[Tuple[int, int, str]] = [(s, k, v) for s in
                                         [int(x) for x in args.supports.split(",")]
                                         for k in [int(x) for x in args.sizes.split(",")]
                                         for v in variants]
    acc: Dict[Tuple[int, int, str], Dict[str, float]] = {
        c: {"patterns": 0, "covered_arcs": 0, "covered_edges": 0, "gt_covered": 0,
            "arcs": 0, "edges": 0, "gt": 0} for c in cells}
    per_scenario: Dict[Tuple[int, int, str], Dict[str, dict]] = {c: {} for c in cells}

    for scenario, dirname in efe.SCENARIOS:
        graph = efe.build_scenario(scenario, dirname, graph_dir)
        all_pats = parsed["scenarios"][scenario]["patterns"]
        for cell in cells:
            s_min, k_min, variant = cell
            pats = [p for p in all_pats if support_map.get(p["render"], 1) >= s_min and p["size"] >= k_min]
            if variant == "network-free":
                pats = [p for p in pats if not any(str(v).startswith("N") for v in p["vertices"])]
            matched = efe.match_patterns(graph, pats) if pats else {}
            matched.pop("_unbound_patterns", None)
            covered = set()
            for arcs in matched.values():
                covered |= arcs
            covered_edges = sum(graph["orig"][a] for a in covered)
            gt_cov = sum(graph["gt_on_arc"][a] for a in covered)
            a = acc[cell]
            a["patterns"] += len(pats)
            a["covered_arcs"] += len(covered)
            a["covered_edges"] += covered_edges
            a["gt_covered"] += gt_cov
            a["arcs"] += graph["nz"]
            a["edges"] += graph["parser_edges"]
            a["gt"] += graph["gt_edges"]
            per_scenario[cell][scenario] = {
                "patterns": len(pats), "covered_arcs": len(covered),
                "covered_edges": covered_edges, "gt_covered": gt_cov,
            }
        print(f"[{scenario[:26]:26s}] done", flush=True)

    rows = []
    print("\n  S  kmin  variant       patterns  cov_edges  coverage   gt_covered  gt_ratio")
    for cell in cells:
        a = acc[cell]
        cov = a["covered_edges"] / a["edges"] if a["edges"] else 0.0
        gtr = a["gt_covered"] / a["gt"] if a["gt"] else 0.0
        rows.append({
            "min_scenario_support": cell[0], "min_pattern_size": cell[1], "variant": cell[2],
            "patterns": int(a["patterns"]),
            "coverage_arcs": a["covered_arcs"] / a["arcs"] if a["arcs"] else 0.0,
            "coverage_edges": cov,
            "gt_covered": int(a["gt_covered"]),
            "gt_ratio": gtr,
            "per_scenario": per_scenario[cell],
        })
        print(f"  {cell[0]:2d}  {cell[1]:4d}  {cell[2]:12s}  {int(a['patterns']):8d}  "
              f"{int(a['covered_edges']):9d}  {100*cov:6.2f}%   {int(a['gt_covered']):10d}  {100*gtr:7.2f}%")

    feasible = [r for r in rows if r["gt_covered"] <= 9]
    print("\n--- cells with gt_covered <= 9 ---")
    if feasible:
        best = max(feasible, key=lambda r: (r["coverage_edges"], -r["min_scenario_support"],
                                            -r["min_pattern_size"]))
        for r in sorted(feasible, key=lambda r: -r["coverage_edges"]):
            print(f"  S>={r['min_scenario_support']} kmin={r['min_pattern_size']} {r.get('variant')} "
                  f"coverage={100*r['coverage_edges']:.2f}% gt={r['gt_covered']} patterns={r['patterns']}")
        print(f"\nselected: S>={best['min_scenario_support']} kmin={best['min_pattern_size']} "
              f"{best.get('variant')} coverage={100*best['coverage_edges']:.2f}% gt={best['gt_covered']}")
    else:
        print("  none")

    Path(args.out).write_text(json.dumps({"grid": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
