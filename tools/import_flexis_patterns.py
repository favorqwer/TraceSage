#!/usr/bin/env python3
"""Parse upstream FLEXIS pattern dumps and aggregate them across scenarios.

Upstream ``--print-patterns`` writes, per mining step, a block headed by
``Frequent patterns: <n>`` followed by n records of the form::

    p <vertex_count> <edge_count>
    v <id> <vertex_label_id>
    e <src> <dst> <edge_label_id>

This tool maps label ids back to the strings recorded by
``tools/export_flexis_graph.py``, canonicalises every pattern (brute-force over
all vertex permutations, smallest encoding wins, so isomorphic patterns collapse)
and counts in how many scenarios each canonical pattern is frequent.
"""
from __future__ import annotations

import argparse
import itertools
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
GRAPHS = ROOT / "output" / "rule-kg" / "flexis-exact-v1" / "graphs"
OUT = ROOT / "output" / "rule-kg" / "flexis-exact-v1"

Pattern = Tuple[int, Tuple[str, ...], Tuple[Tuple[int, int, str], ...]]


def parse_patterns(path: Path) -> List[Tuple[int, List[int], List[Tuple[int, int, int]]]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: List[Tuple[int, List[int], List[Tuple[int, int, int]]]] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.startswith("Frequent patterns:"):
            i += 1
            continue
        count_text = line.split(":", 1)[1].strip()
        try:
            count = int(count_text)
        except ValueError:
            i += 1
            continue
        i += 1
        taken = 0
        while taken < count and i < n:
            if not lines[i].startswith("p "):
                i += 1
                continue
            parts = lines[i].split()
            nv, ne = int(parts[1]), int(parts[2])
            i += 1
            verts: List[int] = []
            while len(verts) < nv and i < n:
                p = lines[i].split()
                if p and p[0] == "v":
                    verts.append(int(p[2]))
                i += 1
            edges: List[Tuple[int, int, int]] = []
            while len(edges) < ne and i < n:
                p = lines[i].split()
                if p and p[0] == "e":
                    edges.append((int(p[1]), int(p[2]), int(p[3])))
                i += 1
            out.append((nv, verts, edges))
            taken += 1
    return out


def canonicalise(nv: int, vlabels: Sequence[str],
                 edges: Sequence[Tuple[int, int, str]]) -> Pattern:
    best: Tuple[Tuple[str, ...], Tuple[Tuple[int, int, str], ...]] | None = None
    for perm in itertools.permutations(range(nv)):
        pos = {orig: idx for idx, orig in enumerate(perm)}
        lab = tuple(vlabels[orig] for orig in perm)
        mapped = tuple(sorted((pos[s], pos[d], el) for s, d, el in edges))
        cand = (lab, mapped)
        if best is None or cand < best:
            best = cand
    assert best is not None
    return (nv, best[0], best[1])


def render(pattern: Pattern) -> str:
    nv, labels, edges = pattern
    verts = " , ".join(f"v{i}:{labels[i]}" for i in range(nv))
    arcs = " ; ".join(f"v{s} -[{el}]-> v{d}" for s, d, el in edges)
    return f"({verts}) {arcs}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse and aggregate FLEXIS patterns")
    ap.add_argument("--run", required=True, help="run directory with *.patterns.txt")
    ap.add_argument("--graphs", default=str(GRAPHS))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--support", type=int, default=20)
    ap.add_argument("--slider", type=float, default=0.9)
    ap.add_argument("--max-size", type=int, default=3)
    args = ap.parse_args()

    run_dir = Path(args.run)
    graph_dir = Path(args.graphs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    per_scenario: Dict[str, Dict[str, List[str]]] = {}
    scenario_patterns: Dict[str, set] = {}
    size_hist: Dict[int, int] = Counter()

    for path in sorted(run_dir.glob("*.patterns.txt")):
        scenario = path.name[: -len(".patterns.txt")]
        stats_path = graph_dir / f"{scenario}.graph_stats.json"
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        vmap = {int(v): k for k, v in stats["vertex_labels"].items()}
        emap = {int(v): k for k, v in stats["edge_labels"].items()}
        raw = parse_patterns(path)
        canon: Dict[Pattern, int] = {}
        for nv, verts, edges in raw:
            try:
                vlabels = [vmap[a] for a in verts]
                elabels = [(s, d, emap[el]) for s, d, el in edges]
            except KeyError as exc:
                raise SystemExit(f"{scenario}: label id {exc} not in graph_stats.json")
            key = canonicalise(nv, vlabels, elabels)
            canon[key] = canon.get(key, 0) + 1
        scenario_patterns[scenario] = set(canon)
        per_scenario[scenario] = {
            "patterns_raw": len(raw),
            "patterns_canonical": len(canon),
            "by_size": dict(Counter(p[0] for p in canon)),
            "patterns": [{"size": p[0], "render": render(p),
                          "vertices": list(p[1]),
                          "edges": [list(e) for e in p[2]]} for p in sorted(canon)],
        }
        for p in canon:
            size_hist[p[0]] += 1
        print(f"[{scenario}] raw={len(raw)} canonical={len(canon)} "
              f"sizes={dict(Counter(p[0] for p in canon))}", flush=True)

    scenario_count: Dict[Pattern, set] = defaultdict(set)
    for scenario, pats in scenario_patterns.items():
        for p in pats:
            scenario_count[p].add(scenario)
    dist = Counter(len(v) for v in scenario_count.values())
    print(f"\ncanonical patterns overall={len(scenario_count)}")
    print("scenario-occurrence distribution: " + ", ".join(
        f">={k}:{sum(c for s, c in dist.items() if s >= k)}" for k in range(1, 11)))

    ranked = sorted(scenario_count.items(), key=lambda kv: (-len(kv[1]), kv[0][0], kv[0][1]))
    top = []
    for p, scenarios in ranked:
        top.append({
            "size": p[0], "render": render(p), "vertices": list(p[1]),
            "edges": [list(e) for e in p[2]],
            "scenario_support": len(scenarios), "scenarios": sorted(scenarios),
        })

    payload = {
        "run_dir": str(run_dir),
        "params": {"support": args.support, "slider": args.slider, "max_size": args.max_size},
        "scenarios": per_scenario,
        "aggregate": {
            "canonical_patterns": len(scenario_count),
            "distribution": {f">={k}": sum(c for s, c in dist.items() if s >= k) for k in range(1, 11)},
            "patterns": top,
        },
    }
    target = out_dir / f"parsed-{run_dir.name}.json"
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {target}", flush=True)

    print("\npatterns frequent in >=7 scenarios:")
    for item in top:
        if item["scenario_support"] >= 7:
            print(f"  [{item['scenario_support']}/10] size={item['size']} {item['render']}")
    print("\npatterns frequent in >=2 scenarios (excluding the above):")
    for item in top:
        if 2 <= item["scenario_support"] < 7:
            print(f"  [{item['scenario_support']}/10] size={item['size']} {item['render']}")


if __name__ == "__main__":
    main()
