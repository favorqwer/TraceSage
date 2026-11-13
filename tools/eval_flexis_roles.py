#!/usr/bin/env python3
"""Coverage of the role-vocabulary benign library, in-sample and out-of-sample."""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eval_flexis_effect as efe  # noqa: E402

KG = ROOT / "output" / "rule-kg" / "flexis-roles-v1"


def read_graph(stats_path: Path) -> dict:
    sid = stats_path.name.replace(".graph_stats.json", "")
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    vmap = {int(v): k for k, v in stats["vertex_labels"].items()}
    emap = {int(v): k for k, v in stats["edge_labels"].items()}
    data = (stats_path.parent / f"{sid}.vf3.bin").read_bytes()
    n, nz, _nl = struct.unpack_from("<III", data, 0)
    off = 12
    vecs = []
    for _ in range(4):
        (length,) = struct.unpack_from("<Q", data, off)
        off += 8
        vecs.append(list(struct.unpack_from(f"<{length}I", data, off)))
        off += 4 * length
    csr_row, csr_dst, csr_lab, vid = vecs
    return {
        "scenario": sid, "nz": nz, "n": n,
        "csr_row": csr_row, "csr_dst": csr_dst,
        "elabels": [emap[i] for i in csr_lab],
        "vlabels": [vmap[i] for i in vid],
        "orig": stats["orig_counts"],
    }


def evaluate(graph: dict, pats: list) -> dict:
    matched = efe.match_patterns(graph, pats)
    matched.pop("_unbound_patterns", None)
    covered = set()
    for arcs in matched.values():
        covered |= arcs
    covered_edges = sum(graph["orig"][a] for a in covered)
    total_edges = sum(graph["orig"]) or 1
    return {
        "scenario": graph["scenario"],
        "arcs": graph["nz"], "vertices": graph["n"],
        "parser_edges": total_edges,
        "patterns": len(pats),
        "patterns_matched": sum(1 for v in matched.values() if v),
        "coverage_arcs": len(covered) / graph["nz"] if graph["nz"] else 0.0,
        "coverage_edges": covered_edges / total_edges,
        "covered_edges": covered_edges,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parsed", default=str(KG / "parsed-k3-t20-a09.json"))
    ap.add_argument("--in-sample", default=str(KG / "graphs"))
    ap.add_argument("--ood", default=str(KG / "graphs-ood"))
    ap.add_argument("--min-size", type=int, default=2)
    ap.add_argument("--min-scenario-support", type=int, default=1)
    ap.add_argument("--out", default=str(KG / "coverage.json"))
    args = ap.parse_args()

    parsed = json.loads(Path(args.parsed).read_text(encoding="utf-8"))
    pats = [p for p in parsed["aggregate"]["patterns"]
            if p["size"] >= args.min_size and p["scenario_support"] >= args.min_scenario_support]
    print(f"library: {len(pats)} patterns (size>={args.min_size}, support>={args.min_scenario_support})", flush=True)

    rows = []
    for tag, folder in (("in_sample", args.in_sample), ("ood", args.ood)):
        d = Path(folder)
        if not d.is_dir():
            continue
        print(f"\n--- {tag} ---", flush=True)
        for stats_path in sorted(d.glob("*.graph_stats.json")):
            graph = read_graph(stats_path)
            r = evaluate(graph, pats)
            r["set"] = tag
            rows.append(r)
            print(f"  {r['scenario'][:34]:34s} edges={r['parser_edges']:9d} "
                  f"coverage={100*r['coverage_edges']:6.2f}% matched={r['patterns_matched']:3d}", flush=True)

    for tag in ("in_sample", "ood"):
        sel = [r for r in rows if r["set"] == tag]
        if not sel:
            continue
        cov = sum(r["covered_edges"] for r in sel)
        tot = sum(r["parser_edges"] for r in sel)
        print(f"\n{tag}: {cov}/{tot} = {100*cov/tot:.2f}%")

    Path(args.out).write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
