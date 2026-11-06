#!/usr/bin/env python
"""图优先检索评测：查 Neo4j Rule KG，而不是文本向量。

对每条 GT 边：
1. 用 MatchIndex 的角色上下文计算 src_role/dst_role；
2. 查 Rule KG 的 Hop 节点，沿 HAS_HOP/IMPLEMENTS/DERIVED_FROM 取子图；
3. 技术入口：BehaviorObservable -> Technique -> IMPLEMENTS -> Motif；
4. 与 MatchIndex 的精确正确规则集对比，并单独看符号不可达边。

用法：
    .venv/Scripts/python.exe tools/eval_graph_retrieval.py --scenario 7_DB_Bruteforce_Datawipe
"""
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


def parent_of(tid: str) -> str:
    return str(tid).split(".", 1)[0]


def tech_match(ids: Set[str], correct: Set[str]) -> bool:
    if ids & correct:
        return True
    for r in ids:
        for c in correct:
            if parent_of(r) == c or parent_of(c) == r:
                return True
    return False


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
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--technique-map", default=str(ROOT / "groundtruth/attack-technique-map.json"))
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
    tech_map = json.loads(Path(args.technique_map).read_text(encoding="utf-8"))["scenarios"][scenario]
    retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), args.database, scenario)

    rows: List[Dict[str, Any]] = []
    t1 = time.time()
    for edge in edges:
        key = (edge["src"], edge["syscall"], edge["dst"])
        expected = {str(m.get("id")) for m in matched_all.get(key, [])}
        src_role = matcher.role_of(edge["src"])
        dst_role = matcher.role_of(edge["dst"])
        res = retriever.retrieve_for_edge(
            src_role, edge["syscall"], dst_role,
            edge["src_label"], edge["dst_label"], limit=args.limit)
        exact_ids = [g["motif"]["motif_id"] for g in res["exact"]]
        tech_motif_ids = [g["motif"]["motif_id"] for g in res["technique"]]
        candidate_list = [t["attack_id"] for t in res["technique_candidates"]]
        tech_candidates = set(candidate_list)
        tech_only = {t["attack_id"] for t in res["technique_only"]}
        expanded_tech = set()
        motif_details = []
        combined = res.get("motifs") or (res["exact"] + res["technique"])
        for g in combined:
            ids = {t.get("attack_id") for t in (g.get("techniques") or []) if t.get("attack_id")}
            expanded_tech |= ids
            motif_details.append({"motif_id": g["motif"]["motif_id"],
                                  "precision": g["motif"].get("precision"),
                                  "techniques": sorted(ids)})
        correct = {str(t) for t in (tech_map.get(edge["phase_id"], {}).get("techniques") or [])}

        def prec_at(k: int) -> float:
            top = candidate_list[:k]
            if not top:
                return 0.0
            return sum(1 for x in top if tech_match({x}, correct)) / len(top)

        def tech_union(k: int) -> Set[str]:
            out: Set[str] = set()
            for d in motif_details[:k]:
                out |= set(d["techniques"])
            return out

        def motif_hit_at(k: int) -> float:
            top = motif_details[:k]
            if not top:
                return 0.0
            return sum(1 for d in top if tech_match(set(d["techniques"]), correct)) / len(top)

        expanded_correct = sum(1 for x in expanded_tech if tech_match({x}, correct))
        motif_correct = sum(1 for d in motif_details if tech_match(set(d["techniques"]), correct))
        rows.append({
            "phase": edge["phase_id"],
            "edge": f"{edge['src']} --{edge['syscall']}--> {edge['dst']}",
            "src_role": src_role, "dst_role": dst_role,
            "expected_motifs": sorted(expected),
            "symbolic_reachable": bool(expected),
            "graph_exact_motifs": exact_ids,
            "graph_exact_hit": bool(expected & set(exact_ids)),
            "graph_technique_motifs": tech_motif_ids,
            "graph_technique_new_motifs": [m for m in tech_motif_ids if m not in expected],
            "technique_candidate_list": candidate_list,
            "technique_candidates": sorted(tech_candidates),
            "technique_only": sorted(tech_only),
            "expanded_techniques": sorted(expanded_tech),
            "correct_techniques": sorted(correct),
            "technique_candidate_hit": bool(correct) and tech_match(tech_candidates | tech_only, correct),
            "expanded_technique_hit": bool(correct) and tech_match(expanded_tech, correct),
            "expanded_technique_hit@1": bool(correct) and tech_match(tech_union(1), correct),
            "expanded_technique_hit@3": bool(correct) and tech_match(tech_union(3), correct),
            "candidate_precision@1": prec_at(1),
            "candidate_precision@3": prec_at(3),
            "candidate_precision@5": prec_at(5),
            "expanded_precision": (expanded_correct / len(expanded_tech)) if expanded_tech else 0.0,
            "motif_precision": (motif_correct / len(motif_details)) if motif_details else 0.0,
            "motif_precision@1": motif_hit_at(1),
            "motif_precision@3": motif_hit_at(3),
            "motif_details": motif_details,
        })
    retriever.close()
    query_s = time.time() - t1

    n = len(rows)
    unreachable = [r for r in rows if not r["symbolic_reachable"]]

    def rate(items, key):
        return sum(1 for r in items if r.get(key)) / len(items) if items else 0.0

    def avg(items, key):
        return sum(float(r.get(key) or 0.0) for r in items) / len(items) if items else 0.0

    summary = {
        "n_gt_edges": n,
        "symbolic_reachable": sum(1 for r in rows if r["symbolic_reachable"]),
        "symbolic_reachable_rate": rate(rows, "symbolic_reachable"),
        "graph_exact_hit": rate(rows, "graph_exact_hit"),
        "graph_technique_new_motif_edges": sum(1 for r in rows if r["graph_technique_new_motifs"]),
        "technique_candidate_hit": rate(rows, "technique_candidate_hit"),
        "expanded_technique_hit": rate(rows, "expanded_technique_hit"),
        "expanded_technique_hit@1": rate(rows, "expanded_technique_hit@1"),
        "expanded_technique_hit@3": rate(rows, "expanded_technique_hit@3"),
        "candidate_precision@1": avg(rows, "candidate_precision@1"),
        "candidate_precision@3": avg(rows, "candidate_precision@3"),
        "candidate_precision@5": avg(rows, "candidate_precision@5"),
        "expanded_precision": avg(rows, "expanded_precision"),
        "motif_precision": avg(rows, "motif_precision"),
        "motif_precision@1": avg(rows, "motif_precision@1"),
        "motif_precision@3": avg(rows, "motif_precision@3"),
        "unreachable": {
            "n": len(unreachable),
            "graph_technique_new_motif_edges": sum(1 for r in unreachable if r["graph_technique_new_motifs"]),
            "technique_candidate_hit": rate(unreachable, "technique_candidate_hit"),
            "expanded_technique_hit": rate(unreachable, "expanded_technique_hit"),
            "expanded_technique_hit@1": rate(unreachable, "expanded_technique_hit@1"),
            "expanded_technique_hit@3": rate(unreachable, "expanded_technique_hit@3"),
            "candidate_precision@1": avg(unreachable, "candidate_precision@1"),
            "candidate_precision@3": avg(unreachable, "candidate_precision@3"),
            "candidate_precision@5": avg(unreachable, "candidate_precision@5"),
            "expanded_precision": avg(unreachable, "expanded_precision"),
            "motif_precision": avg(unreachable, "motif_precision"),
            "motif_precision@1": avg(unreachable, "motif_precision@1"),
            "motif_precision@3": avg(unreachable, "motif_precision@3"),
        },
    }
    result = {
        "scenario": scenario,
        "protocol": "图优先：Hop 节点查询 + BehaviorObservable 技术入口 + Cypher 子图扩展；不是文本向量检索",
        "extract_seconds": round(extract_s, 2),
        "graph_query_seconds": round(query_s, 2),
        "summary": summary,
        "rows": rows,
    }
    dest = Path(args.out) if args.out else ROOT / f"output/rule-kg/v1/graph_retrieval_{scenario}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
