"""对比 B0/B1 冻结重跑结果（只读）。

用法：
    .venv/Scripts/python.exe tools/compare_frozen_runs.py
    ... --b0 tmp/frozen_runs/summary_b0.json --b1 tmp/frozen_runs/summary_b1.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def by_scenario(summary: dict) -> dict:
    return {r["scenario"]: r for r in summary.get("results") or []}


def pct(value) -> str:
    return "—" if value is None else f"{float(value) * 100:.2f}%"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--b0", default="tmp/frozen_runs/summary_b0.json")
    ap.add_argument("--b1", default="tmp/frozen_runs/summary_b1.json")
    args = ap.parse_args()

    b0 = by_scenario(load(Path(args.b0)))
    b1 = by_scenario(load(Path(args.b1)))
    scenarios = sorted(
        set(b0) | set(b1),
        key=lambda s: int(s.split("_", 1)[0]) if s.split("_", 1)[0].isdigit() else 10**9,
    )

    print("| 场景 | B0 召回 | B0 查准 | B1 召回 | B1 查准 | Δ召回(步) | Δ查准(点) |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for sc in scenarios:
        a, b = b0.get(sc, {}), b1.get(sc, {})
        dr = (b.get("steps_hit", 0) - a.get("steps_hit", 0))
        dp = ((b.get("precision") or 0) - (a.get("precision") or 0)) * 100
        print(f"| {sc} | {pct(a.get('recall'))} | {pct(a.get('precision'))} | "
              f"{pct(b.get('recall'))} | {pct(b.get('precision'))} | {dr:+d} | {dp:+.2f} |")

    print("\n== 微平均 ==")
    for label, summary in (("B0", load(Path(args.b0))), ("B1", load(Path(args.b1)))):
        micro = summary.get("micro") or {}
        print(f"{label}: 召回 {micro.get('steps_hit')}/{micro.get('steps_total')} = "
              f"{pct(micro.get('recall'))}；查准 {micro.get('correct_edges')}/"
              f"{micro.get('reported_triples')} = {pct(micro.get('precision'))}；"
              f"LLM 调用 {micro.get('llm_calls')}；耗时 {micro.get('elapsed')}s")

    m0 = load(Path(args.b0)).get("micro") or {}
    m1 = load(Path(args.b1)).get("micro") or {}
    print(f"B1 − B0: 召回 {m1.get('steps_hit', 0) - m0.get('steps_hit', 0):+d} 步；"
          f"查准 {((m1.get('precision') or 0) - (m0.get('precision') or 0)) * 100:+.2f} 点；"
          f"正确边 {m1.get('correct_edges', 0) - m0.get('correct_edges', 0):+d}；"
          f"上报边 {m1.get('reported_triples', 0) - m0.get('reported_triples', 0):+d}")


if __name__ == "__main__":
    main()
