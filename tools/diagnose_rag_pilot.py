#!/usr/bin/env python
"""诊断 RAG 试点的小束选择：哪些 GT 边被覆盖、哪些被预算排除。"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(ROOT / "tools"))

import settings as cfg  # noqa: E402
from closure import extract_raw_closure  # noqa: E402
from domain.edge import edge_key  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from routing.prepare import PreFilter  # noqa: E402
from rules.library import load_library_file, _role_cuts  # noqa: E402
from rules.online import MatchIndex  # noqa: E402
from rag.graph_retrieve import RuleGraphRetriever  # noqa: E402
from rag.neo4j_kg import DEFAULT_DATABASE  # noqa: E402
from experiments.rag_judge import BUNDLE_MAX, MAX_BUNDLES, _bundle_key, _edge_evidence  # noqa: E402
import score_graph_product as eg  # noqa: E402


def main() -> None:
    cfg.load_dotenv()
    sc = sys.argv[1] if len(sys.argv) > 1 else "7_DB_Bruteforce_Datawipe"
    fold = ROOT / f"output/navigator-baseline/distill/fold-libraries/{sc}.json"
    patterns, audit = load_library_file(fold)
    admitted = set(audit.get("selected") or [])
    cuts = _role_cuts(audit)

    raw, stats, deps = extract_raw_closure(sc, return_deps=True, log=lambda s: None)
    anchors = {tuple(t) for t in (stats.get("anchor_triples") or [])}
    confirmed = {edge_key(e): dict(e) for e in raw if edge_key(e) in anchors}
    pool = CandidatePool(raw)
    tf = pool.facts
    clean, _ = PreFilter(tf).apply([e for e in raw if edge_key(e) not in anchors])
    cands = [e for e in clean if edge_key(e) not in confirmed]
    cp = CandidatePool(clean, facts=pool.facts)
    matcher = MatchIndex(cp, tf, role_cuts=cuts)

    retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), DEFAULT_DATABASE, sc)
    cache: Dict[Any, Any] = {}
    records: List[Dict[str, Any]] = []
    for e in cands:
        rec = _edge_evidence(e, matcher, retriever, cache)
        rec["key"] = edge_key(e)
        records.append(rec)
    retriever.close()

    groups = collections.defaultdict(list)
    for rec in records:
        groups[_bundle_key(rec["edge"])].append(rec)
    bundles = []
    for key in sorted(groups, key=lambda x: str(x)):
        items = groups[key]
        for i in range(0, len(items), BUNDLE_MAX):
            bundles.append(items[i:i + BUNDLE_MAX])
    bundles.sort(key=lambda b: (-sum(1 for r in b if r["motifs"]), -len(b)))
    selected = bundles[:MAX_BUNDLES]
    covered_keys = {r["key"] for b in selected for r in b}
    covered = sum(1 for r in records if r["key"] in covered_keys)

    _gt, gt_triples = eg.load_gt(str(ROOT / f"groundtruth/{sc}.groundtruth.json"))
    gtkeys = {t[:3] for t in gt_triples}
    gt_covered = gtkeys & covered_keys
    print(json.dumps({
        "scenario": sc,
        "candidate_edges": len(records),
        "selected_bundles": len(selected),
        "covered_edges": covered,
        "coverage_rate": covered / len(records) if records else 0,
        "gt_edges": len(gtkeys),
        "gt_covered": len(gt_covered),
        "gt_upper_bound_recall": len(gt_covered) / len(gtkeys) if gtkeys else 0,
    }, ensure_ascii=False, indent=1))

    print("\nselected bundles:")
    for i, b in enumerate(selected, 1):
        e = b[0]["edge"]
        key = (e.get("src_label"), e.get("syscall"), e.get("dst_label"), tuple(sorted(e.get("rels") or [])))
        n_gt = sum(1 for r in b if r["key"] in gtkeys)
        n_motif = sum(1 for r in b if r["motifs"])
        print(f"  {i:02d} size={len(b)} motifs={n_motif} gt={n_gt} key={key}")

    print("\nGT edges NOT covered by selected bundles:")
    missing = sorted(gtkeys - covered_keys)
    print("  count", len(missing))
    for k in missing[:15]:
        print("  ", k)


if __name__ == "__main__":
    main()
