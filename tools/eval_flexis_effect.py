#!/usr/bin/env python3
"""Effect measurement for the FLEXIS-mined pattern library (no LLM involved).

Metrics, per scenario and for the cross-scenario library:
  coverage_arcs      covered arcs / all arcs in the collapsed labelled graph
  coverage_edges     original parser edges carried by covered arcs / all edges
  gt_attack_ratio    groundtruth attack edges sitting on covered arcs / all GT edges
  attack_share       GT attack edges / original edges carried by covered arcs
  concentration      for each pattern: max share of its matched arcs on one
                     (src,dst) pair, and the share of its top-10 pairs

The graph is taken from the exported .vf3.bin (so the pattern labels are exactly
the ones the miner saw); the parser CSVs are only streamed to attribute original
edge volume and groundtruth edges to each arc.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
KG = ROOT / "output" / "rule-kg" / "flexis-exact-v1"
GT_ROOT = ROOT / "groundtruth"

SCENARIOS: Tuple[Tuple[str, str], ...] = (
    ("1_Web_Exploit_Ransomware", "1_Web_Exploit_Ransomware-r3"),
    ("2_SSH_Spray_Lateral_Exfiltration", "2_SSH_Spray_Lateral_Exfiltration-r3"),
    ("3_Phishing_Beacon_Cryptomining", "3_Phishing_Beacon_Cryptomining-r3"),
    ("4_Repo_Poisoning_Backdoor", "4_Repo_Poisoning_Backdoor-r3"),
    ("5_Exposed_Service_Pivot", "5_Exposed_Service_Pivot-r3"),
    ("6_Web_SQLi_Data_Exfiltration", "6_Web_SQLi_Data_Exfiltration-r3"),
    ("7_DB_Bruteforce_Datawipe", "7_DB_BruteForce_DataWipe-r3"),
    ("8_FTP_WeakCreds_WebShell_Exfiltration", "8_FTP_WeakCreds_WebShell_Exfiltration-r3"),
    ("9_Exposed_Container_Escape", "9_Exposed_Container_Escape-r9"),
    ("10_Tomcat_Weakcreds_DNS_Exfiltration", "10_Tomcat_Weakcreds_DNS_Exfiltration-r3"),
)


def read_bin(path: Path) -> Tuple[int, int, List[int], List[int], List[int], List[int]]:
    data = path.read_bytes()
    n, nz, nl = struct.unpack_from("<III", data, 0)
    off = 12
    vecs = []
    for _ in range(8):
        (length,) = struct.unpack_from("<Q", data, off)
        off += 8
        vecs.append(list(struct.unpack_from(f"<{length}I", data, off)))
        off += 4 * length
    return n, nz, nl, vecs[0], vecs[1], vecs[2], vecs[3]


def node_key(row: Dict[str, str], side: str) -> Tuple[str, ...]:
    label = row[f"{side}_label"]
    if label == "Network":
        return (label, row[f"{side}_host"], "", "", "", "", row[f"{side}_path"])
    return (
        label,
        row[f"{side}_host"],
        row[f"{side}_container"] or "host",
        row[f"{side}_pid"],
        (row[f"{side}_start_ns"] or "0") if label == "Process" else row[f"{side}_start_ns"],
        row[f"{side}_path"],
        "",
    )


def load_gt_keys(scenario: str) -> set:
    path = GT_ROOT / f"{scenario}.groundtruth.json"
    if not path.is_file():
        return set()
    gt = json.loads(path.read_text(encoding="utf-8"))
    keys = set()
    for step in gt.get("attack_path") or []:
        for e in step.get("edges") or []:
            parts = str(e.get("edge_key", "")).split(":")
            if len(parts) >= 3:
                keys.add((parts[1], parts[0], str(e.get("action"))))
    return keys


def build_scenario(scenario: str, dirname: str, scheme_dir: Path):
    stats_path = scheme_dir / f"{scenario}.graph_stats.json"
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    vmap = {int(v): k for k, v in stats["vertex_labels"].items()}
    emap = {int(v): k for k, v in stats["edge_labels"].items()}
    n, nz, nl, csr_row, csr_dst, csr_lab, vid = read_bin(scheme_dir / f"{scenario}.vf3.bin")
    vlabels = [vmap[i] for i in vid]
    elabels = [emap[i] for i in csr_lab]

    # node ids in nodes.csv order, same normalisation as the exporter
    keys: Dict[Tuple[str, ...], int] = {}
    nodes_path = ROOT / "output" / "parser-v2" / dirname / "nodes.csv"
    with nodes_path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            label = row.get("label", "")
            key = (
                label,
                row.get("host_id", ""),
                (row.get("container_id", "") or "host") if label != "Network" else "",
                row.get("pid", ""),
                ((row.get("start_ns", "") or "0") if label == "Process" else row.get("start_ns", "")),
                row.get("path", "") if label != "Network" else "",
                row.get("endpoints", "") if label == "Network" else "",
            )
            if key not in keys:
                keys[key] = len(keys)

    gt = load_gt_keys(scenario)
    orig = [0] * nz
    gt_on_arc = [0] * nz
    gt_arcs = []
    edges_path = ROOT / "output" / "parser-v2" / dirname / "edges.csv"
    rows = 0
    with edges_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows += 1
            try:
                src = keys[node_key(row, "src")]
                dst = keys[node_key(row, "dst")]
            except KeyError:
                continue
            lo = csr_row[src]
            hi = csr_row[src + 1]
            pos = bisect.bisect_left(csr_dst, dst, lo, hi)
            if pos >= hi or csr_dst[pos] != dst:
                continue
            orig[pos] += 1
            k = (row["event_id"], row["edge_class"], row["action"])
            if k in gt:
                gt_on_arc[pos] += 1
                gt_arcs.append((row["event_id"], row["edge_class"], row["action"], row["result"], pos))
    return {
        "n": n, "nz": nz, "csr_row": csr_row, "csr_dst": csr_dst, "elabels": elabels,
        "vlabels": vlabels, "orig": orig, "gt_on_arc": gt_on_arc, "gt_arcs": gt_arcs,
        "parser_edges": rows, "gt_edges": len(gt),
    }


def match_patterns(graph: dict, patterns: Sequence[dict]) -> Dict[str, set]:
    """Return pattern-render -> set of matched arc indices (k<=3, injective mapping)."""
    nz = graph["nz"]
    csr_row = graph["csr_row"]
    csr_dst = graph["csr_dst"]
    elabels = graph["elabels"]
    vlabels = graph["vlabels"]

    triple_index: Dict[Tuple[str, str, str], List[int]] = defaultdict(list)
    for arc in range(nz):
        src = bisect.bisect_right(csr_row, arc) - 1
        triple_index[(vlabels[src], elabels[arc], vlabels[csr_dst[arc]])].append(arc)

    out: Dict[str, set] = {}
    unbound: set = set()
    for pat in patterns:
        verts = pat["vertices"]
        edges = [(int(a), int(b), c) for a, b, c in pat["edges"]]
        k = len(verts)
        if k == 2:
            a, b, lab = edges[0]
            matched = set(triple_index.get((verts[a], lab, verts[b]), []))
            out[pat["render"]] = matched
            continue

        best = None
        for idx, (a, b, lab) in enumerate(edges):
            cand = triple_index.get((verts[a], lab, verts[b]), [])
            if best is None or len(cand) < len(best[1]):
                best = (idx, cand)
        assert best is not None
        anchor_idx, anchor_cand = best
        a, b, lab = edges[anchor_idx]
        matched = set()
        for arc in anchor_cand:
            src = bisect.bisect_right(csr_row, arc) - 1
            dst = csr_dst[arc]
            bind = {a: src, b: dst}
            used_nodes = {src, dst}
            used_arcs = {arc}
            ok = True
            for other_idx, (u, v, lab2) in enumerate(edges):
                if other_idx == anchor_idx:
                    continue
                if u in bind and v in bind:
                    lo, hi = csr_row[bind[u]], csr_row[bind[u] + 1]
                    pos = bisect.bisect_left(csr_dst, bind[v], lo, hi)
                    if pos >= hi or csr_dst[pos] != bind[v] or elabels[pos] != lab2:
                        ok = False
                        break
                    used_arcs.add(pos)
                    continue
                if u not in bind and v not in bind:
                    unbound.add(pat["render"])
                    ok = False
                    break
                base = bind[u] if u in bind else bind[v]
                want_vertex = v if u in bind else u
                want_label = verts[want_vertex]
                found = None
                for q in range(csr_row[base], csr_row[base + 1]):
                    if elabels[q] != lab2:
                        continue
                    cand_node = csr_dst[q]
                    if vlabels[cand_node] != want_label or cand_node in used_nodes:
                        continue
                    found = (cand_node, q)
                    break
                if found is None:
                    ok = False
                    break
                bind[want_vertex] = found[0]
                used_nodes.add(found[0])
                used_arcs.add(found[1])
            if ok:
                matched |= used_arcs
        out[pat["render"]] = matched
    if unbound:
        out["_unbound_patterns"] = unbound
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure effect of the FLEXIS pattern library")
    ap.add_argument("--parsed", default=str(KG / "parsed-k3-t20-a09.json"))
    ap.add_argument("--graphs", default=str(KG / "graphs"))
    ap.add_argument("--out", default=str(KG / "effects-k3-t20-a09.json"))
    ap.add_argument("--min-scenario-support", type=int, default=1,
                    help="only patterns frequent in at least N scenarios count as the library")
    args = ap.parse_args()

    parsed = json.loads(Path(args.parsed).read_text(encoding="utf-8"))
    graph_dir = Path(args.graphs)
    per_scenario = parsed["scenarios"]
    scenario_support = {p["render"]: p["scenario_support"] for p in parsed["aggregate"]["patterns"]}

    report = {"library": {}, "scenarios": {}}
    lib_pairs = set()
    lib_covered = set()
    lib_orig = 0
    lib_gt = 0
    total_arcs = 0
    total_orig = 0
    total_gt = 0
    concentration_rows = []

    for scenario, dirname in SCENARIOS:
        graph = build_scenario(scenario, dirname, graph_dir)
        pats = [p for p in per_scenario[scenario]["patterns"]
                if scenario_support.get(p["render"], 1) >= args.min_scenario_support]
        matched = match_patterns(graph, pats)
        unbound = matched.pop("_unbound_patterns", set())
        covered = set()
        for arcset in matched.values():
            covered |= arcset
        covered_orig = sum(graph["orig"][a] for a in covered)
        covered_gt = sum(graph["gt_on_arc"][a] for a in covered)
        total_arcs += graph["nz"]
        total_orig += graph["parser_edges"]
        total_gt += graph["gt_edges"]
        lib_covered |= {(scenario, a) for a in covered}
        lib_orig += covered_orig
        lib_gt += covered_gt

        per_pat = []
        for pat in pats:
            arcs = matched.get(pat["render"], set())
            if not arcs:
                continue
            pairs = Counter()
            weight = 0
            for arc in arcs:
                src = bisect.bisect_right(graph["csr_row"], arc) - 1
                w = graph["orig"][arc]
                pairs[(src, graph["csr_dst"][arc])] += w
                weight += w
            top = pairs.most_common(10)
            per_pat.append({
                "render": pat["render"],
                "matched_arcs": len(arcs),
                "matched_edges": weight,
                "entity_pairs": len(pairs),
                "top1_share": top[0][1] / weight if weight else 0.0,
                "top10_share": sum(c for _, c in top) / weight if weight else 0.0,
            })
        per_pat.sort(key=lambda x: -x["matched_arcs"])
        concentration_rows.extend((scenario, p) for p in per_pat[:5])

        report["scenarios"][scenario] = {
            "arcs": graph["nz"],
            "parser_edges": graph["parser_edges"],
            "gt_edges": graph["gt_edges"],
            "patterns_evaluated": len(pats),
            "patterns_with_unbound_edges": len(unbound),
            "covered_arcs": len(covered),
            "coverage_arcs": len(covered) / graph["nz"] if graph["nz"] else None,
            "covered_original_edges": covered_orig,
            "coverage_edges": covered_orig / graph["parser_edges"] if graph["parser_edges"] else None,
            "gt_on_covered_arcs": covered_gt,
            "gt_attack_ratio": covered_gt / graph["gt_edges"] if graph["gt_edges"] else None,
            "attack_share_of_covered": covered_gt / covered_orig if covered_orig else None,
            "top_patterns": per_pat[:5],
        }
        print(f"[{scenario}] arcs={graph['nz']} covered_arcs={len(covered)} "
              f"({100*len(covered)/graph['nz']:.1f}%) edges_covered={covered_orig}"
              f" ({100*covered_orig/graph['parser_edges']:.1f}%) gt_on_covered={covered_gt}/{graph['gt_edges']}"
              f" unbound_patterns={len(unbound)}",
              flush=True)

    report["library"] = {
        "min_scenario_support": args.min_scenario_support,
        "total_arcs": total_arcs,
        "total_original_edges": total_orig,
        "total_gt_edges": total_gt,
        "covered_arcs": len(lib_covered),
        "coverage_arcs": len(lib_covered) / total_arcs if total_arcs else None,
        "covered_original_edges": lib_orig,
        "coverage_edges": lib_orig / total_orig if total_orig else None,
        "gt_on_covered_arcs": lib_gt,
        "gt_attack_ratio": lib_gt / total_gt if total_gt else None,
        "attack_share_of_covered": lib_gt / lib_orig if lib_orig else None,
    }
    lib = report["library"]
    print("\n=== library level (patterns frequent in >= %d scenarios) ===" % args.min_scenario_support)
    print(f"arcs        {lib['covered_arcs']}/{lib['total_arcs']} = {100*lib['coverage_arcs']:.2f}%")
    print(f"parser edges{lib['covered_original_edges']}/{lib['total_original_edges']} = {100*lib['coverage_edges']:.2f}%")
    print(f"GT attack edges on covered arcs {lib['gt_on_covered_arcs']}/{lib['total_gt_edges']} = {100*lib['gt_attack_ratio']:.2f}%")
    print(f"attack share of covered edges {100*lib['attack_share_of_covered']:.4f}%")

    print("\n=== concentration of the top matched patterns ===")
    for scenario, p in concentration_rows[:15]:
        print(f"  [{scenario[:22]:22s}] arcs={p['matched_arcs']:6d} pairs={p['entity_pairs']:6d} "
              f"top1={100*p['top1_share']:.1f}% top10={100*p['top10_share']:.1f}%  {p['render'][:90]}")

    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
