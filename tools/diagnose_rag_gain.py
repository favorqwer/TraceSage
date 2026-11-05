#!/usr/bin/env python
"""诊断 RAG 相对 B1 的束级差异：证据覆盖、判定翻转、守卫降级。"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent


def load_lines(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def last_detail(lines: List[Dict[str, Any]]) -> Dict[str, Any]:
    det = [d for d in lines if d.get("kind") == "detail"]
    return det[-1] if det else {}


def latest_batches(lines: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    idxs = [i for i, d in enumerate(lines) if d.get("kind") == "detail"]
    if not idxs:
        return []
    last = idxs[-1]
    prev = idxs[-2] if len(idxs) > 1 else -1
    return [d for d in lines[prev + 1:last] if d.get("kind") != "detail"]


def sig(r: Dict[str, Any]) -> str:
    sample = (r.get("sample") or [[]])[0]
    return json.dumps([
        r.get("level"), r.get("size"), r.get("programs"), r.get("rels"),
        r.get("syscall"), r.get("dirs"), sample,
    ], ensure_ascii=False, sort_keys=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    args = ap.parse_args()
    sc = args.scenario
    b1_lines = load_lines(ROOT / f"tmp/frozen_runs/b1/{sc}_b1.trace.jsonl")
    rag_lines = load_lines(ROOT / f"tmp/rag-pilot/{sc}_rag.trace.jsonl")
    b1_det = last_detail(b1_lines).get("detail") or []
    rag_det = last_detail(rag_lines).get("detail") or []
    rag_batches = latest_batches(rag_lines)

    ev_by_id: Dict[str, List[str]] = {}
    for b in rag_batches:
        for it in b.get("items") or []:
            ev_by_id[str(it.get("id"))] = list(it.get("rag_rule_ids") or [])

    b1_by_sig = {sig(r): r for r in b1_det}
    rag_by_sig = {sig(r): r for r in rag_det}

    lost = []
    gained = []
    for s, a in b1_by_sig.items():
        b = rag_by_sig.get(s)
        if not b:
            continue
        av = str(a.get("verdict") or "")
        bv = str(b.get("verdict") or "")
        if av == "all" and bv != "all":
            lost.append((a, b, ev_by_id.get(str(b.get("id")), [])))
        elif av != "all" and bv == "all":
            gained.append((a, b, ev_by_id.get(str(b.get("id")), [])))

    print(json.dumps({
        "scenario": sc,
        "b1_bundles": len(b1_det), "rag_bundles": len(rag_det),
        "matched": sum(1 for s in b1_by_sig if s in rag_by_sig),
        "rag_bundles_with_evidence": sum(1 for b in rag_batches for it in (b.get("items") or []) if it.get("rag_rule_ids")),
        "rag_items": sum(len(b.get("items") or []) for b in rag_batches),
        "lost_bundles": len(lost), "lost_edges": sum(int(b.get("size") or 0) for _, b, _ in lost),
        "gained_bundles": len(gained), "gained_edges": sum(int(b.get("size") or 0) for _, b, _ in gained),
    }, ensure_ascii=False, indent=1))

    print("\n--- B1 all -> RAG 非 all（召回损失）---")
    for a, b, ev in sorted(lost, key=lambda x: -(x[1].get("size") or 0))[:12]:
        print(f"size={b.get('size')} B1={a.get('verdict')} RAG={b.get('verdict')} "
              f"evidence={len(ev)} reason={str(b.get('reason'))[:90]}")
    print("\n--- B1 非 all -> RAG all（召回增益）---")
    for a, b, ev in sorted(gained, key=lambda x: -(x[1].get("size") or 0))[:12]:
        print(f"size={b.get('size')} B1={a.get('verdict')} RAG={b.get('verdict')} "
              f"evidence={len(ev)} reason={str(b.get('reason'))[:90]}")

    # 证据/无证据束的判定分布
    counts = Counter()
    for r in rag_det:
        ev = ev_by_id.get(str(r.get("id")), [])
        counts[("evidence" if ev else "no_evidence", str(r.get("verdict")))] += 1
    print("\n--- RAG 证据 vs 无证据的判定分布 ---")
    for k, v in sorted(counts.items()):
        print(k, v)


if __name__ == "__main__":
    main()
