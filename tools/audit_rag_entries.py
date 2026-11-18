"""只读审计规则检索入口及实际提示词中的规则卡，不调用模型或写数据库。"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
import eval_graph_retrieval as egr  # noqa: E402


def build_scenario_context(scenario: str, fold_dir: Path) -> Tuple[Any, Dict[Tuple, Any], Dict[str, Any]]:
    fold_path = fold_dir / f"{scenario}.json"
    patterns, audit = load_library_file(fold_path)
    admitted = set(audit.get("selected") or [])
    role_cuts = _role_cuts(audit)
    raw_edges, stats, _deps = extract_raw_closure(scenario, return_deps=True, log=lambda s: None)
    anchor_keys = {tuple(t) for t in (stats.get("anchor_triples") or [])}
    final_confirmed = {edge_key(e): dict(e) for e in raw_edges if edge_key(e) in anchor_keys}
    pool = CandidatePool(raw_edges)
    clean_unexcluded, _ = PreFilter(pool.facts).apply(
        [e for e in raw_edges if edge_key(e) not in anchor_keys])
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, pool.facts, role_cuts=role_cuts)
    matched_all = matcher.match(patterns or [], admitted=admitted,
                                seed_edges=final_confirmed, return_all=True)
    return matcher, matched_all, audit

def audit_gt_edges(scenario, retriever, matcher, matched_all, limit):
    gt = json.loads((ROOT / "groundtruth" / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    rows = []
    for edge in egr.gt_edge_rows(gt):
        expected = {str(m.get("id")) for m in matched_all.get((edge["src"], edge["syscall"], edge["dst"]), [])}
        res = retriever.retrieve_rules(matcher.role_of(edge["src"]), edge["syscall"], matcher.role_of(edge["dst"]), limit=limit)
        rows.append({"edge": f"{edge['src']} --{edge['syscall']}--> {edge['dst']}",
                     "symbolic_reachable": bool(expected), "exact_nonempty": bool(res["exact"]),
                     "partial_nonempty": bool(res["partial"]), "no_evidence": not res["motifs"],
                     "rule_ids": [g["motif"]["motif_id"] for g in res["motifs"]]})
    return {"scenario": scenario, "rows": rows}


def parse_listing_cards(listing):
    out = {}
    parts = re.split(r"(?m)^(B\d+)｜", listing)
    for i in range(1, len(parts), 2):
        body = parts[i + 1]
        cards = re.findall(r"R\d+｜形态 (MOTIF_[0-9a-f]+)｜", body)
        out[parts[i]] = {"rules": len(cards), "motif_ids": cards}
    return out


def audit_traces(scenario, path):
    if not path.is_file():
        return {"scenario": scenario, "trace": str(path), "missing": True}
    cards, verdicts = {}, {}
    batches = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if "listing" in rec and "items" in rec:
            batches += 1
            cards.update(parse_listing_cards(rec["listing"]))
            verdicts.update({bid: row.get("verdict") for bid, row in (rec.get("result", {}).get("verdicts") or {}).items()})
        elif rec.get("kind") == "detail":
            verdicts.update({str(row["id"]): row.get("verdict") for row in rec.get("detail", []) if row.get("id")})
    return {"scenario": scenario, "trace": str(path), "batches": batches, "bundles": len(cards),
            "rule_card_bundles": sum(bool(c["rules"]) for c in cards.values()),
            "no_card_bundles": sum(not c["rules"] for c in cards.values()),
            "all_with_rule_card": sum(bool(c["rules"]) and verdicts.get(bid) == "all" for bid, c in cards.items())}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(ROOT / "tmp/rule-rag-audit"))
    ap.add_argument("--fold-dir", default=str(cfg.fold_library_dir()))
    ap.add_argument("--trace-dir", default=str(ROOT / "output/provenance-runs"))
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--scenarios", nargs="*", default=None)
    args = ap.parse_args()
    cfg.load_dotenv()
    results, traces = [], []
    for scenario in args.scenarios or sorted(p.stem for p in Path(args.fold_dir).glob("*.json")):
        matcher, matched, _ = build_scenario_context(scenario, Path(args.fold_dir))
        retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), args.database, scenario)
        try:
            results.append(audit_gt_edges(scenario, retriever, matcher, matched, args.limit))
        finally:
            retriever.close()
        traces.append(audit_traces(scenario, Path(args.trace_dir) / f"{scenario}_rag.trace.jsonl"))
    rows = [row for result in results for row in result["rows"]]
    summary = {"gt_edges": len(rows), **{key: sum(bool(row[key]) for row in rows)
               for key in ["symbolic_reachable", "exact_nonempty", "partial_nonempty", "no_evidence"]}}
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in [("gt_entry_split.json", results), ("card_sources.json", traces), ("summary.json", summary)]:
        (out / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
