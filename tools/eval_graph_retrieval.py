"""规则图检索覆盖：与同一角色上下文下的符号规则匹配结果对照，不计算规则正确率。"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))
sys.path.insert(0, str(ROOT / "tools"))

import settings as cfg  # noqa: E402
from closure import extract_raw_closure  # noqa: E402
from domain.edge import edge_key  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from core.prepare import PreFilter  # noqa: E402
from rules.library import load_library_file, _role_cuts  # noqa: E402
from rules.online import MatchIndex  # noqa: E402
from rag.graph_retrieve import RuleGraphRetriever  # noqa: E402
from rag.neo4j_kg import DEFAULT_DATABASE  # noqa: E402
import score_graph_product as eg  # noqa: E402


def label_of(endpoint: Any) -> str:
    s = str(endpoint or "")
    if s.startswith("p:"):
        return "P"
    if s.startswith("f:"):
        return "F"
    if s.startswith("n:"):
        return "N"
    return "?"






def gt_edge_rows(gt: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for phase in gt.get("attack_path") or []:
        pid = str(phase.get("id") or "")
        for edge in phase.get("edges") or []:
            call = edge.get("syscall") or edge.get("action")
            src = eg.strip_endpoint_key(edge.get("src"))
            dst = eg.strip_endpoint_key(edge.get("dst"))
            if not (src and call and dst):
                continue
            out.append({
                "src": src, "dst": dst, "syscall": call,
                "src_label": label_of(edge.get("src")),
                "dst_label": label_of(edge.get("dst")),
                "phase_id": pid,
            })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="7_DB_Bruteforce_Datawipe")
    ap.add_argument("--fold-dir", default=str(ROOT / "output/provenance-baseline/distill/fold-libraries"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    cfg.load_dotenv()
    scenario = args.scenario
    fold_path = Path(args.fold_dir) / f"{scenario}.json"
    patterns, audit = load_library_file(fold_path)
    admitted = set(audit.get("selected") or [])
    role_cuts = _role_cuts(audit)

    t0 = time.time()
    raw_edges, stats, deps = extract_raw_closure(scenario, return_deps=True, log=lambda s: None)
    anchor_keys = {tuple(t) for t in (stats.get("anchor_triples") or [])}
    final_confirmed = {edge_key(e): dict(e) for e in raw_edges if edge_key(e) in anchor_keys}
    pool = CandidatePool(raw_edges)
    tf = pool.facts
    clean_unexcluded, _ = PreFilter(tf).apply([e for e in raw_edges if edge_key(e) not in anchor_keys])
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, tf, role_cuts=role_cuts)
    matched_all = matcher.match(patterns or [], admitted=admitted,
                                seed_edges=final_confirmed, return_all=True)
    extract_s = time.time() - t0

    gt = json.loads((Path(args.gt_dir) / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    edges = gt_edge_rows(gt)
    retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), args.database, scenario)

    rows: List[Dict[str, Any]] = []
    t1 = time.time()
    for edge in edges:
        key = (edge["src"], edge["syscall"], edge["dst"])
        expected = {str(m.get("id")) for m in matched_all.get(key, [])}
        src_role = matcher.role_of(edge["src"])
        dst_role = matcher.role_of(edge["dst"])
        res = retriever.retrieve_rules(src_role, edge["syscall"], dst_role, limit=args.limit)
        exact_ids = [g["motif"]["motif_id"] for g in res["exact"]]
        partial_ids = [g["motif"]["motif_id"] for g in res["partial"]]
        combined = res["motifs"]
        rows.append({
            "phase": edge["phase_id"],
            "edge": f"{edge['src']} --{edge['syscall']}--> {edge['dst']}",
            "src_role": src_role, "dst_role": dst_role,
            "expected_motifs": sorted(expected),
            "symbolic_reachable": bool(expected),
            "graph_exact_motifs": exact_ids,
            "graph_partial_motifs": partial_ids,
            "graph_exact_hit": bool(expected & set(exact_ids)),
            "graph_rule_hit": bool(expected & {g["motif"]["motif_id"] for g in combined}),
            "motif_details": [{"motif_id": g["motif"]["motif_id"],
                               "precision": g["motif"].get("precision"),
                               "entry_source": g["entry_source"], "hops": g["hops"]}
                              for g in combined],
        })
    retriever.close()
    query_s = time.time() - t1

    def summarize(items):
        n = len(items)
        return {
            "n_gt_edges": n,
            "symbolic_reachable": sum(bool(r["symbolic_reachable"]) for r in items),
            "exact_nonempty": sum(bool(r["graph_exact_motifs"]) for r in items),
            "partial_nonempty": sum(bool(r["graph_partial_motifs"]) for r in items),
            "graph_exact_hit_count": sum(bool(r["graph_exact_hit"]) for r in items),
            "graph_rule_hit_count": sum(bool(r["graph_rule_hit"]) for r in items),
            "graph_exact_hit": sum(bool(r["graph_exact_hit"]) for r in items) / n if n else 0.0,
            "graph_rule_hit": sum(bool(r["graph_rule_hit"]) for r in items) / n if n else 0.0,
        }
    summary = summarize(rows)
    summary["unreachable"] = summarize([r for r in rows if not r["symbolic_reachable"]])
    result = {
        "scenario": scenario,
        "protocol": "规则步骤精确与部分匹配；对照 MatchIndex 候选集合；不代表攻击正确率",
        "extract_seconds": round(extract_s, 2),
        "graph_query_seconds": round(query_s, 2),
        "summary": summary,
        "rows": rows,
    }
    dest = Path(args.out) if args.out else ROOT / f"tmp/rule-retrieval/graph_retrieval_{scenario}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
