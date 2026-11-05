#!/usr/bin/env python
"""技术级检索评测：检验 dense 能否在符号不可达边上补出正确 ATT&CK 技术。

答案键：`groundtruth/attack-technique-map.json`（人工草稿，只用于评测，不进入检索）。
两条 dense 路径：
1. 直接检索 ATT&CK 技术文档；
2. 检索规则卡，再把规则卡的 `techniques` 展开成技术集合。
并单独报告「符号 MatchIndex 不可达」子集上的命中率。

用法：
    "C:/.../python.exe" tools/eval_technique_retrieval.py --scenario 7_DB_Bruteforce_Datawipe --top-k 10
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(ROOT / "tools"))

from closure import extract_raw_closure  # noqa: E402
from domain.edge import edge_key  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from routing.prepare import PreFilter  # noqa: E402
from rules.library import load_library_file, _role_cuts  # noqa: E402
from rules.online import MatchIndex  # noqa: E402
from rag.embed import QUERY_INSTRUCTION, Qwen3Embedder  # noqa: E402
from rag.rerank import Qwen3Reranker  # noqa: E402
from rag.index import CosineIndex  # noqa: E402
from rag.query import edge_text, motif_text, technique_text  # noqa: E402
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


def tech_match(retrieved: Set[str], correct: Set[str], broad: bool = True) -> bool:
    if retrieved & correct:
        return True
    if not broad:
        return False
    for r in retrieved:
        for c in correct:
            if parent_of(r) == c or parent_of(c) == r:
                return True
    return False


def motif_tech_ids(motif: Dict[str, Any]) -> Set[str]:
    return {str(t.get("technique_id")) for t in (motif.get("techniques") or []) if t.get("technique_id")}


def gt_edge_rows(gt: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for phase in gt.get("attack_path") or []:
        phase_id = str(phase.get("id") or "")
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
                "phase_id": phase_id,
                "phase": phase.get("phase") or phase_id,
                "effect": edge.get("effect"),
            })
    return out


def enrich_edge(edge: Dict[str, Any], record: Optional[Dict[str, Any]],
                process_context: Dict[str, Any]) -> str:
    text = edge_text(edge)
    if not record:
        return text
    extra = []
    if record.get("rels"):
        extra.append("关系 " + "+".join(str(x) for x in record["rels"]))
    if record.get("network_protocol"):
        extra.append("协议 " + str(record["network_protocol"]))
    if record.get("bytes"):
        extra.append("字节 " + str(record["bytes"]))
    owners = []
    for pid in (record.get("member_processes") or [])[:2]:
        meta = process_context.get(str(pid)) or {}
        owner = str(meta.get("owner") or "")
        args = str(meta.get("owner_args") or "")
        if owner:
            owners.append(owner + ((" " + args[:120]) if args else ""))
    if owners:
        extra.append("进程 " + " / ".join(owners))
    return text + ("；" + "；".join(extra) if extra else "")


def load_tech_vectors(embedder: Qwen3Embedder, docs: List[Dict[str, Any]],
                      cache: Path, batch_size: int) -> np.ndarray:
    ids = [d["id"] for d in docs]
    if cache.is_file():
        data = np.load(cache, allow_pickle=True)
        if list(data["ids"]) == ids:
            return data["vectors"]
    vectors = embedder.encode([d["text"] for d in docs], batch_size=batch_size)
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache, ids=np.array(ids, dtype=object), vectors=vectors)
    return vectors


def summarize(rows: List[Dict[str, Any]], k: int) -> Dict[str, Any]:
    n = len(rows)
    reachable = [r for r in rows if r["symbolic_reachable"]]
    unreachable = [r for r in rows if not r["symbolic_reachable"]]

    def rate(items, key):
        return (sum(1 for r in items if r.get(key)) / len(items)) if items else 0.0

    out: Dict[str, Any] = {
        "n_gt_edges": n,
        "symbolic_reachable": len(reachable),
        "symbolic_reachable_rate": len(reachable) / n if n else 0.0,
        "symbolic_technique_hit": rate(rows, "symbolic_technique_hit"),
    }
    for channel in ("dense_tech", "dense_motif_tech", "hybrid_motif_tech", "rerank_tech"):
        for scope, items in (("all", rows), ("reachable", reachable), ("unreachable", unreachable)):
            out[f"{channel}_hit@{k}_{scope}"] = rate(items, f"{channel}_hit")
    # MRR for direct technique retrieval (vector and reranked)
    for channel in ("dense_tech", "rerank_tech"):
        for scope, items in (("all", rows), ("reachable", reachable), ("unreachable", unreachable)):
            rr = sum(1.0 / r[f"{channel}_rank"] for r in items if r.get(f"{channel}_rank"))
            out[f"{channel}_mrr_{scope}"] = rr / len(items) if items else 0.0
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="7_DB_Bruteforce_Datawipe")
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--technique-map", default=str(ROOT / "groundtruth/attack-technique-map.json"))
    ap.add_argument("--attack", default=str(ROOT / "output/rule-kg/v1/attack.json"))
    ap.add_argument("--top-k", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--rerank", action="store_true",
                    help="用 Qwen3-Reranker-0.6B FP16 对 dense 技术 top-k 重排")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

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

    edge_by_key = {edge_key(e): e for e in clean_unexcluded}
    pctx = deps.record.process_context
    gt = json.loads((Path(args.gt_dir) / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    gt_edges = gt_edge_rows(gt)
    tech_map = json.loads(Path(args.technique_map).read_text(encoding="utf-8"))["scenarios"][scenario]
    attack = json.loads(Path(args.attack).read_text(encoding="utf-8"))
    techniques = attack["techniques"]

    motif_docs = [{"id": str(m["id"]), "text": motif_text(m), "motif": m}
                  for m in patterns if str(m.get("id")) in admitted]
    tech_docs = [{"id": tid, "text": technique_text(t), "technique": t}
                 for tid, t in techniques.items()]

    embedder = Qwen3Embedder()
    t1 = time.time()
    motif_vecs = embedder.encode([d["text"] for d in motif_docs], batch_size=args.batch_size)
    encode_motifs_s = time.time() - t1
    t2 = time.time()
    tech_vecs = load_tech_vectors(embedder, tech_docs,
                                  ROOT / "output/rule-kg/v1/technique_vectors.npz",
                                  args.batch_size)
    encode_techs_s = time.time() - t2
    motif_index = CosineIndex(motif_docs, motif_vecs)
    tech_index = CosineIndex(tech_docs, tech_vecs)

    queries = [enrich_edge(e, edge_by_key.get((e["src"], e["syscall"], e["dst"])), pctx)
               for e in gt_edges]
    t3 = time.time()
    query_vecs = embedder.encode(queries, instruction=QUERY_INSTRUCTION, batch_size=args.batch_size)
    encode_queries_s = time.time() - t3

    reranker = None
    if args.rerank:
        embedder.close()
        reranker = Qwen3Reranker()

    rows: List[Dict[str, Any]] = []
    for edge, qv in zip(gt_edges, query_vecs):
        key = (edge["src"], edge["syscall"], edge["dst"])
        correct = {str(t) for t in (tech_map.get(edge["phase_id"], {}).get("techniques") or [])}
        sym_motifs = matched_all.get(key, [])
        sym_tech = set().union(*[motif_tech_ids(m) for m in sym_motifs]) if sym_motifs else set()

        dense_tech_hits = tech_index.search(qv, top_k=args.top_k)
        dense_motif_hits = motif_index.search(qv, top_k=args.top_k)
        dense_tech_ids = [h.doc_id for h in dense_tech_hits]
        dense_tech_rank = next((i + 1 for i, tid in enumerate(dense_tech_ids)
                                if tech_match({tid}, correct, broad=True)), None)
        rerank_tech_ids: List[str] = []
        rerank_tech_rank = None
        if reranker is not None and dense_tech_hits:
            scores = reranker.score(queries[len(rows)],
                                    [h.doc["text"][:600] for h in dense_tech_hits])
            order = sorted(range(len(dense_tech_hits)), key=lambda i: -scores[i])
            dense_tech_hits = [dense_tech_hits[i] for i in order]
            rerank_tech_ids = [h.doc_id for h in dense_tech_hits]
            rerank_tech_rank = next((i + 1 for i, tid in enumerate(rerank_tech_ids)
                                     if tech_match({tid}, correct, broad=True)), None)
        dense_motif_tech_union = set()
        dense_motif_tech_rank = None
        for i, h in enumerate(dense_motif_hits, 1):
            ids = motif_tech_ids(h.doc.get("motif") or {})
            dense_motif_tech_union |= ids
            if dense_motif_tech_rank is None and tech_match(ids, correct, broad=True):
                dense_motif_tech_rank = i
        hybrid_union = sym_tech | dense_motif_tech_union
        rows.append({
            "phase": edge["phase_id"],
            "edge": queries[len(rows)],
            "correct_techniques": sorted(correct),
            "symbolic_reachable": bool(sym_motifs),
            "symbolic_motifs": [m.get("id") for m in sym_motifs],
            "symbolic_techniques": sorted(sym_tech),
            "symbolic_technique_hit": bool(correct) and tech_match(sym_tech, correct, broad=True),
            "dense_tech_top": dense_tech_ids,
            "dense_tech_rank": dense_tech_rank,
            "dense_tech_hit": dense_tech_rank is not None,
            "rerank_tech_top": rerank_tech_ids,
            "rerank_tech_rank": rerank_tech_rank,
            "rerank_tech_hit": rerank_tech_rank is not None,
            "dense_motif_top": [h.doc_id for h in dense_motif_hits],
            "dense_motif_techniques": sorted(dense_motif_tech_union),
            "dense_motif_tech_rank": dense_motif_tech_rank,
            "dense_motif_tech_hit": dense_motif_tech_rank is not None,
            "hybrid_motif_tech_hit": bool(correct) and tech_match(hybrid_union, correct, broad=True),
        })
    if reranker is not None:
        reranker.close()
    embedder.close()

    result = {
        "scenario": scenario,
        "protocol": "技术答案键为人工草稿；dense 直接检索技术 + 规则卡展开技术；broad 匹配含父子技术",
        "n_motifs": len(motif_docs),
        "n_techniques": len(tech_docs),
        "extract_seconds": round(extract_s, 2),
        "encode_motifs_seconds": round(encode_motifs_s, 2),
        "encode_techniques_seconds": round(encode_techs_s, 2),
        "encode_queries_seconds": round(encode_queries_s, 2),
        "summary": summarize(rows, args.top_k),
        "rows": rows,
    }
    dest = Path(args.out) if args.out else ROOT / f"output/rule-kg/v1/technique_retrieval_{scenario}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, ensure_ascii=False, indent=2))
    print(f"written {dest}")


if __name__ == "__main__":
    main()
