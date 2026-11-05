#!/usr/bin/env python
"""Dense 检索离线评测（粗粒度正确性）。

口径限制：
- 正确性判定只看 GT 边的 syscall/action 是否在规则卡的 syscall_chain 中，
  且 GT 两端顶点种类（P/F/N）是否出现在规则卡角色链前缀中；
- 这不是 `MatchIndex` 的精确角色串匹配，不能当作最终 G3 结论；
- 先用于验证检索栈是否工作、dense 通道是否能排到可匹配规则。

用法：
    "C:/.../python.exe" tools/eval_dense_retrieval.py --scenario 7_DB_Bruteforce_Datawipe --top-k 10
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))

from rag.embed import QUERY_INSTRUCTION, Qwen3Embedder  # noqa: E402
from rag.index import CosineIndex  # noqa: E402
from rag.query import edge_text, motif_text  # noqa: E402


def label_of(endpoint: Any) -> str:
    s = str(endpoint or "")
    if s.startswith("p:"):
        return "P"
    if s.startswith("f:"):
        return "F"
    if s.startswith("n:"):
        return "N"
    return "?"


def role_prefix(role: str) -> str:
    return str(role or "").split(".", 1)[0]


def coarse_match(motif: Dict[str, Any], edge: Dict[str, Any]) -> bool:
    sc = str(edge.get("syscall") or edge.get("action") or "").lower()
    if sc not in {str(x).lower() for x in (motif.get("syscall_chain") or [])}:
        return False
    roles = {role_prefix(r) for r in (motif.get("role_chain") or [])}
    return label_of(edge.get("src")) in roles and label_of(edge.get("dst")) in roles


def gt_edges(gt: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for phase in gt.get("attack_path") or []:
        out.extend(phase.get("edges") or [])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="7_DB_Bruteforce_Datawipe")
    ap.add_argument("--kg", default=str(ROOT / "output/rule-kg/v1/folds"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--top-k", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--out", default=str(ROOT / "output/rule-kg/v1/dense_retrieval_eval.json"))
    args = ap.parse_args()

    kg_path = Path(args.kg) / f"{args.scenario}.json"
    kg = json.loads(kg_path.read_text(encoding="utf-8"))
    motifs = [m for m in kg.get("motifs") or [] if m.get("admitted")]
    docs = [{"id": m["motif_id"], "text": motif_text(m), "motif": m} for m in motifs]
    gt = json.loads((Path(args.gt_dir) / f"{args.scenario}.groundtruth.json").read_text(encoding="utf-8"))
    edges = gt_edges(gt)

    embedder = Qwen3Embedder()
    t0 = time.time()
    doc_vecs = embedder.encode([d["text"] for d in docs], batch_size=args.batch_size)
    encode_docs_s = time.time() - t0
    index = CosineIndex(docs, doc_vecs)

    t1 = time.time()
    query_vecs = embedder.encode([edge_text(e) for e in edges], instruction=QUERY_INSTRUCTION,
                                 batch_size=args.batch_size)
    encode_queries_s = time.time() - t1

    rows = []
    hits_at = {1: 0, 5: 0, 10: 0}
    rr_sum = 0.0
    reachable = 0
    for edge, qv in zip(edges, query_vecs):
        correct_ids = {m["motif_id"] for m in motifs if coarse_match(m, edge)}
        if correct_ids:
            reachable += 1
        hits = index.search(qv, top_k=max(args.top_k, 10))
        rank = next((i + 1 for i, h in enumerate(hits) if h.doc_id in correct_ids), None)
        if rank:
            rr_sum += 1.0 / rank
            for k in hits_at:
                if rank <= k:
                    hits_at[k] += 1
        rows.append({
            "edge": edge_text(edge),
            "correct_motifs": sorted(correct_ids),
            "rank": rank,
            "top": [{"id": h.doc_id, "score": round(h.score, 4)} for h in hits[:args.top_k]],
        })
    embedder.close()

    n = len(edges)
    result = {
        "scenario": args.scenario,
        "claim_status": "not_final",
        "claim_note": "粗粒度正确性代理（syscall/action + 顶点种类前缀）会高估可达率；不得用于 G3 结论或论文数字。",
        "protocol": "粗粒度：syscall/action 精确 + 顶点种类前缀；不是 MatchIndex 精确角色串匹配",
        "n_gt_edges": n,
        "n_motifs": len(motifs),
        "reachable_edges": reachable,
        "reachable_rate": (reachable / n) if n else 0.0,
        "hit_at": {f"hit@{k}": (hits_at[k] / n if n else 0.0) for k in hits_at},
        "hit_at_reachable": {f"hit@{k}": (hits_at[k] / reachable if reachable else 0.0) for k in hits_at},
        "mrr": (rr_sum / n if n else 0.0),
        "mrr_reachable": (rr_sum / reachable if reachable else 0.0),
        "encode_docs_seconds": round(encode_docs_s, 2),
        "encode_queries_seconds": round(encode_queries_s, 2),
        "rows": rows,
    }
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
