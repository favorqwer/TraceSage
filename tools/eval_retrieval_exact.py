#!/usr/bin/env python
"""精确检索评测：用 MatchIndex 在真实候选池上算正确规则集。

流程与 B1 一致：
闭包 -> 锚点确认 -> 静态初筛 -> MatchIndex(return_all=True) -> 每条 GT 边的精确正确基模集合。
然后比较：
- 符号通道：命中即可达，rank=1；
- dense 通道：Qwen3-Embedding-4B FP8 检索 top-k；
- hybrid：符号 rank1 + dense RRF。

用法：
    "C:/.../python.exe" tools/eval_retrieval_exact.py --scenario 7_DB_Bruteforce_Datawipe --top-k 10
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))
sys.path.insert(0, str(ROOT / "tools"))

from closure import extract_raw_closure  # noqa: E402
from domain.edge import edge_key  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from routing.prepare import PreFilter  # noqa: E402
from rules.library import load_library_file, _role_cuts  # noqa: E402
from rules.online import MatchIndex  # noqa: E402
from rag.embed import QUERY_INSTRUCTION, Qwen3Embedder  # noqa: E402
from rag.index import CosineIndex  # noqa: E402
from rag.query import edge_text, motif_text  # noqa: E402
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
                "phase": phase.get("phase") or phase.get("id") or "",
                "effect": edge.get("effect"),
            })
    return out


def rank_of(order: List[str], correct: set[str]) -> Optional[int]:
    for i, doc_id in enumerate(order, 1):
        if doc_id in correct:
            return i
    return None


def rrf_rank(symbolic: List[str], dense_ids: List[str], correct: set[str], k: int = 60) -> Optional[int]:
    scores: Dict[str, float] = {}
    for mid in symbolic:
        scores[mid] = scores.get(mid, 0.0) + 1.0 / (k + 1)
    for r, mid in enumerate(dense_ids, 1):
        scores[mid] = scores.get(mid, 0.0) + 1.0 / (k + r)
    order = sorted(scores, key=lambda x: (-scores[x], x))
    return rank_of(order, correct)


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    reachable = sum(1 for r in rows if r["correct_motifs"])
    out: Dict[str, Any] = {
        "n_gt_edges": n,
        "reachable_edges": reachable,
        "symbolic_reachable_rate": (reachable / n) if n else 0.0,
    }
    for channel in ("dense", "hybrid"):
        for k in (1, 5, 10):
            hit = sum(1 for r in rows if r.get(f"{channel}_rank") and r[f"{channel}_rank"] <= k)
            out[f"{channel}_hit@{k}"] = (hit / n) if n else 0.0
            out[f"{channel}_hit@{k}_reachable"] = (hit / reachable) if reachable else 0.0
        rr = sum(1.0 / r[f"{channel}_rank"] for r in rows if r.get(f"{channel}_rank"))
        out[f"{channel}_mrr"] = (rr / n) if n else 0.0
        out[f"{channel}_mrr_reachable"] = (rr / reachable) if reachable else 0.0
    out["symbolic_hit@1"] = out["symbolic_reachable_rate"]
    out["symbolic_hit@5"] = out["symbolic_reachable_rate"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="7_DB_Bruteforce_Datawipe")
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--top-k", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    scenario = args.scenario
    fold_path = Path(args.fold_dir) / f"{scenario}.json"
    patterns, audit = load_library_file(fold_path)
    admitted = set(audit.get("selected") or [])
    role_cuts = _role_cuts(audit)

    t0 = time.time()
    raw_edges, stats, _deps = extract_raw_closure(scenario, return_deps=True, log=lambda s: None)
    anchor_keys = {tuple(t) for t in (stats.get("anchor_triples") or [])}
    final_confirmed = {edge_key(e): dict(e) for e in raw_edges if edge_key(e) in anchor_keys}
    pool = CandidatePool(raw_edges)
    tf = pool.facts
    channel_input = [e for e in raw_edges if edge_key(e) not in anchor_keys]
    clean_unexcluded, _ = PreFilter(tf).apply(channel_input)
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, tf, role_cuts=role_cuts)
    matched_all = matcher.match(patterns or [], admitted=admitted,
                                seed_edges=final_confirmed, return_all=True)
    extract_s = time.time() - t0

    gt = json.loads((Path(args.gt_dir) / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    gt_edges = gt_edge_rows(gt)

    motifs = [m for m in patterns if str(m.get("id")) in admitted]
    docs = [{"id": str(m["id"]), "text": motif_text(m), "motif": m} for m in motifs]
    embedder = Qwen3Embedder()
    t1 = time.time()
    doc_vecs = embedder.encode([d["text"] for d in docs], batch_size=args.batch_size)
    encode_docs_s = time.time() - t1
    index = CosineIndex(docs, doc_vecs)
    t2 = time.time()
    query_vecs = embedder.encode([edge_text(e) for e in gt_edges], instruction=QUERY_INSTRUCTION,
                                 batch_size=args.batch_size)
    encode_queries_s = time.time() - t2

    rows: List[Dict[str, Any]] = []
    for edge, qv in zip(gt_edges, query_vecs):
        key = (edge["src"], edge["syscall"], edge["dst"])
        correct = {str(m["id"]) for m in matched_all.get(key, [])}
        hits = index.search(qv, top_k=max(args.top_k, 10))
        dense_ids = [h.doc_id for h in hits]
        dense_rank = rank_of(dense_ids, correct)
        sym_ids = sorted(correct)
        hybrid_rank = rrf_rank(sym_ids, dense_ids, correct)
        rows.append({
            "edge": edge_text(edge),
            "phase": edge.get("phase"),
            "correct_motifs": sym_ids,
            "symbolic_reachable": bool(correct),
            "dense_rank": dense_rank,
            "hybrid_rank": hybrid_rank,
            "dense_top": [{"id": h.doc_id, "score": round(h.score, 4)} for h in hits[:args.top_k]],
        })
    embedder.close()

    result = {
        "scenario": scenario,
        "protocol": "精确：MatchIndex(return_all=True) 在闭包+初筛后的候选池上算正确基模；dense 用同一批 admitted 规则卡",
        "n_motifs": len(motifs),
        "extract_seconds": round(extract_s, 2),
        "encode_docs_seconds": round(encode_docs_s, 2),
        "encode_queries_seconds": round(encode_queries_s, 2),
        "summary": summarize(rows),
        "rows": rows,
    }
    dest = Path(args.out) if args.out else ROOT / f"output/rule-kg/v1/retrieval_exact_{scenario}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
