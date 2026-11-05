#!/usr/bin/env python
"""对比 B1 与 RAG 全量替换的 10 场景结果。

B1 读取 tmp/frozen_runs/summary_b1.json；RAG 读取 tmp/rag-pilot/logs/<场景>.log
里的最后一行 RAG_RESULT。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent


def load_b1(path: Path) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["scenario"]: r for r in data.get("results") or []}


def load_rag(log_dir: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for log in sorted(log_dir.glob("*.log")):
        text = log.read_text(encoding="utf-8", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.startswith("RAG_RESULT ")]
        if not lines:
            continue
        try:
            row = json.loads(lines[-1][len("RAG_RESULT "):])
        except json.JSONDecodeError:
            continue
        row["scenario"] = log.stem
        out[row["scenario"]] = row
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--b1", default=str(ROOT / "tmp/frozen_runs/summary_b1.json"))
    ap.add_argument("--rag-dir", default=str(ROOT / "tmp/rag-pilot/logs"))
    ap.add_argument("--out", default=str(ROOT / "tmp/rag-pilot/summary_rag.json"))
    args = ap.parse_args()

    b1 = load_b1(Path(args.b1))
    rag = load_rag(Path(args.rag_dir))
    scenarios = sorted(set(b1) | set(rag),
                       key=lambda s: int(s.split("_", 1)[0]) if s.split("_", 1)[0].isdigit() else 10**9)

    rows: List[Dict[str, Any]] = []
    print("| 场景 | B1 召回 | B1 查准 | RAG 召回 | RAG 查准 | Δ召回(步) | Δ查准(点) | B1调用 | RAG调用 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for sc in scenarios:
        a = b1.get(sc, {})
        b = rag.get(sc, {})
        if not a or not b:
            print(f"| {sc} | 缺数据 | 缺数据 | 缺数据 | 缺数据 | — | — | — | — |")
            continue
        dr = int(b.get("steps_hit", 0)) - int(a.get("steps_hit", 0))
        dp = (float(b.get("precision") or 0) - float(a.get("precision") or 0)) * 100
        print(f"| {sc} | {a.get('recall', 0):.2%} | {a.get('precision', 0):.2%} | "
              f"{b.get('recall', 0):.2%} | {b.get('precision', 0):.2%} | {dr:+d} | {dp:+.2f} | "
              f"{a.get('llm_calls')} | {b.get('llm_calls')} |")
        rows.append({"scenario": sc, "b1": a, "rag": b, "delta_steps": dr, "delta_precision": dp})

    def micro(items, side):
        steps = sum(int(r[side].get("steps_hit") or 0) for r in items)
        total = sum(int(r[side].get("steps_total") or 0) for r in items)
        correct = sum(int(r[side].get("correct_edges") or 0) for r in items)
        reported = sum(int(r[side].get("reported_triples") or 0) for r in items)
        calls = sum(int(r[side].get("llm_calls") or 0) for r in items)
        return {"steps_hit": steps, "steps_total": total,
                "recall": steps / total if total else 0.0,
                "correct_edges": correct, "reported_triples": reported,
                "precision": correct / reported if reported else 0.0,
                "llm_calls": calls}

    m1, mr = micro(rows, "b1"), micro(rows, "rag")
    print("\n== 微平均 ==")
    print(f"B1 : 召回 {m1['steps_hit']}/{m1['steps_total']} = {m1['recall']:.2%}；"
          f"查准 {m1['correct_edges']}/{m1['reported_triples']} = {m1['precision']:.2%}；调用 {m1['llm_calls']}")
    print(f"RAG: 召回 {mr['steps_hit']}/{mr['steps_total']} = {mr['recall']:.2%}；"
          f"查准 {mr['correct_edges']}/{mr['reported_triples']} = {mr['precision']:.2%}；调用 {mr['llm_calls']}")
    print(f"RAG − B1: 召回 {mr['steps_hit'] - m1['steps_hit']:+d} 步；"
          f"查准 {(mr['precision'] - m1['precision']) * 100:+.2f} 点；"
          f"正确边 {mr['correct_edges'] - m1['correct_edges']:+d}；"
          f"上报边 {mr['reported_triples'] - m1['reported_triples']:+d}")

    out = {"rows": rows, "b1_micro": m1, "rag_micro": mr}
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"written {dest}")


if __name__ == "__main__":
    main()
