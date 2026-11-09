#!/usr/bin/env python3
"""Attribute the groundtruth attack edges that the pattern library covers.

For every GT attack edge we locate the collapsed arc it sits on, then find every
library pattern that has an embedding using that arc. Output breaks the total
down by pattern size (k=2 / k=3 / both), by scenario, by GT action, and ranks the
patterns that cover the most GT edges.
"""
from __future__ import annotations

import argparse
import bisect
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import eval_flexis_effect as efe  # noqa: E402

KG = ROOT / "output" / "rule-kg" / "flexis-exact-v1"


def pattern_covers_arc(pat: dict, anchor: Tuple[int, int, int], src: int, dst: int,
                       graph: dict) -> bool:
    verts = pat["vertices"]
    edges = [(int(a), int(b), c) for a, b, c in pat["edges"]]
    a0, b0, _lab0 = anchor
    bind = {a0: src, b0: dst}
    used = {src, dst}
    csr_row, csr_dst, elabels, vlabels = graph["csr_row"], graph["csr_dst"], graph["elabels"], graph["vlabels"]
    for u, v, lab in edges:
        if (u, v) == (a0, b0) and bind.get(u) == src and bind.get(v) == dst:
            continue
        if u in bind and v in bind:
            lo, hi = csr_row[bind[u]], csr_row[bind[u] + 1]
            pos = bisect.bisect_left(csr_dst, bind[v], lo, hi)
            if pos >= hi or csr_dst[pos] != bind[v] or elabels[pos] != lab:
                return False
            continue
        if u in bind:
            base, want, rev = bind[u], v, False
        elif v in bind:
            base, want, rev = bind[v], u, True
        else:
            return False
        found = None
        for q in range(csr_row[base], csr_row[base + 1]):
            if elabels[q] != lab:
                continue
            cand = csr_dst[q]
            if vlabels[cand] != verts[want] or cand in used:
                continue
            found = cand
            break
        if found is None:
            return False
        bind[want] = found
        used.add(found)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Attribute GT coverage of the pattern library")
    ap.add_argument("--parsed", default=str(KG / "parsed-k3-t20-a09.json"))
    ap.add_argument("--graphs", default=str(KG / "graphs"))
    ap.add_argument("--out", default=str(KG / "gt-attribution-k3-t20-a09.json"))
    ap.add_argument("--min-scenario-support", type=int, default=1)
    args = ap.parse_args()

    parsed = json.loads(Path(args.parsed).read_text(encoding="utf-8"))
    graph_dir = Path(args.graphs)
    support = {p["render"]: p["scenario_support"] for p in parsed["aggregate"]["patterns"]}

    report = {"scenarios": {}, "pattern_hits": {}, "totals": {}}
    size_split = Counter()
    per_scenario_rows = []
    gt_action_counter = Counter()
    arc_label_counter = Counter()
    pattern_counter = Counter()
    covers_per_edge = []

    for scenario, dirname in efe.SCENARIOS:
        graph = efe.build_scenario(scenario, dirname, graph_dir)
        pats = [p for p in parsed["scenarios"][scenario]["patterns"]
                if support.get(p["render"], 1) >= args.min_scenario_support]

        index: Dict[Tuple[str, str, str], List[Tuple[Tuple[int, int, int], dict]]] = defaultdict(list)
        for pat in pats:
            verts = pat["vertices"]
            for a, b, lab in pat["edges"]:
                index[(verts[int(a)], lab, verts[int(b)])].append(((int(a), int(b), lab), pat))

        covered_rows = []
        for event_id, edge_class, action, result, arc in graph["gt_arcs"]:
            src = bisect.bisect_right(graph["csr_row"], arc) - 1
            dst = graph["csr_dst"][arc]
            triple = (graph["vlabels"][src], graph["elabels"][arc], graph["vlabels"][dst])
            hits = []
            for anchor, pat in index.get(triple, []):
                if len(pat["vertices"]) == 2:
                    hits.append(pat)
                elif pattern_covers_arc(pat, anchor, src, dst, graph):
                    hits.append(pat)
            renders = sorted({h["render"] for h in hits})
            sizes = {len(h["vertices"]) for h in hits}
            if sizes == {2}:
                kind = "k2_only"
            elif sizes == {3}:
                kind = "k3_only"
            elif sizes == {2, 3}:
                kind = "both"
            else:
                kind = "none"
            size_split[kind] += 1
            if hits:
                covers_per_edge.append(len(renders))
                for r in renders:
                    pattern_counter[(scenario, r)] += 1
                try:
                    bit = "ok" if int(result) >= 0 else "err"
                except (TypeError, ValueError):
                    bit = "na"
                gt_action_counter[f"{action}|{bit}"] += 1
                arc_label_counter[triple[1]] += 1
                covered_rows.append({
                    "event_id": event_id, "edge_class": edge_class, "action": action,
                    "arc_label": triple[1], "src_label": triple[0], "dst_label": triple[2],
                    "covered_by": len(renders), "sizes": kind,
                    "patterns": renders[:5],
                })

        per_scenario_rows.append({
            "scenario": scenario,
            "gt_edges": len(graph["gt_arcs"]),
            "gt_covered": len(covered_rows),
            "details": covered_rows,
        })
        report["scenarios"][scenario] = per_scenario_rows[-1]
        print(f"[{scenario[:26]:26s}] GT={len(graph['gt_arcs']):3d} covered={len(covered_rows):3d}", flush=True)

    print("\n=== split by pattern size ===")
    for kind in ("k2_only", "k3_only", "both", "none"):
        print(f"  {kind:8s} {size_split[kind]}")
    report["totals"]["size_split"] = dict(size_split)

    print("\n=== top patterns by number of distinct GT edges covered ===")
    for (scenario, render), count in pattern_counter.most_common(15):
        print(f"  {count:3d}  [{scenario[:20]:20s}] {render[:120]}")
    report["pattern_hits"] = {f"{sc}||{r}": c for (sc, r), c in pattern_counter.most_common()}

    print("\n=== GT action distribution of the covered edges ===")
    for action, count in gt_action_counter.most_common():
        print(f"  {action}: {count}")
    report["totals"]["gt_actions"] = dict(gt_action_counter)

    print("\n=== arc label distribution of the covered edges ===")
    for label, count in arc_label_counter.most_common(15):
        print(f"  {label}: {count}")
    report["totals"]["arc_labels"] = dict(arc_label_counter)

    if covers_per_edge:
        covers_per_edge.sort()
        n = len(covers_per_edge)
        print(f"\ncovering patterns per GT edge: min={covers_per_edge[0]} "
              f"median={covers_per_edge[n // 2]} max={covers_per_edge[-1]}")
        report["totals"]["covers_per_edge"] = {
            "min": covers_per_edge[0], "median": covers_per_edge[n // 2], "max": covers_per_edge[-1]}

    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
