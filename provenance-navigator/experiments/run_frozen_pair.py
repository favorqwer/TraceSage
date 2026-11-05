"""B0/B1 冻结版批量重跑。

用途：用同一份冻结代码重跑 10 场景的 B0（空 2 跳标签）与 B1（真 2 跳），
产出逐场景结果与微平均，供 G0 检查点核对。

用法：
    .venv/Scripts/python.exe provenance-navigator/experiments/run_frozen_pair.py --group b1
    .venv/Scripts/python.exe provenance-navigator/experiments/run_frozen_pair.py --group b0 --scenarios 7_DB_Bruteforce_Datawipe
    .venv/Scripts/python.exe provenance-navigator/experiments/run_frozen_pair.py --group both --resume

产物：
    tmp/frozen_runs/<b0|b1>/<场景>_<b0|b1>.json
    tmp/frozen_runs/<b0|b1>/<场景>_<b0|b1>.trace.jsonl
    tmp/frozen_runs/summary_<b0|b1>.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import experiments.run_v4_frozen as m  # noqa: E402


def scenario_order() -> list[str]:
    return sorted(
        m.cfg.available_scenarios(),
        key=lambda s: int(s.split("_", 1)[0]) if s.split("_", 1)[0].isdigit() else 10**9,
    )


def micro(results: list[dict]) -> dict:
    steps_hit = sum(int(r.get("steps_hit") or 0) for r in results)
    steps_total = sum(int(r.get("steps_total") or 0) for r in results)
    correct = sum(int(r.get("correct_edges") or 0) for r in results)
    reported = sum(int(r.get("reported_triples") or 0) for r in results)
    return {
        "scenarios": len(results),
        "steps_hit": steps_hit,
        "steps_total": steps_total,
        "recall": steps_hit / steps_total if steps_total else 0.0,
        "correct_edges": correct,
        "reported_triples": reported,
        "precision": correct / reported if reported else 0.0,
        "llm_calls": sum(int(r.get("llm_calls") or 0) for r in results),
        "elapsed": sum(float(r.get("elapsed") or 0.0) for r in results),
    }


def run_group(group: str, scenarios: list[str], resume: bool) -> dict:
    m.USE_MOTIF_EVIDENCE = True
    m.CONTENT_BINDING = False
    m.SPLIT_EVIDENCE = False
    m.ANCHOR_PAIR_CONFIRM = False
    m.SUBGRAPH_EVIDENCE = False
    m.STRUCTURED_OUTPUT = False
    m.REAL_2HOP = group == "b1"
    m.VARIANT = "v4_real_2hop" if group == "b1" else "v4_empty_2hop"

    results: list[dict] = []
    for i, sc in enumerate(scenarios, 1):
        fold = str(m.REPO_ROOT / f"output/navigator-baseline/distill/fold-libraries/{sc}.json")
        out = m.REPO_ROOT / f"tmp/frozen_runs/{group}/{sc}_{group}.json"
        gt = str(m.REPO_ROOT / f"groundtruth/{sc}.groundtruth.json")
        t0 = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {group} {i}/{len(scenarios)} {sc} 开始", flush=True)
        try:
            if resume and out.exists():
                ev = m.scorer.evaluate(str(out), gt, scenario=sc)
                res = {
                    "scenario": sc, "recall": ev["recall"], "steps_hit": ev["steps_hit"],
                    "steps_total": ev["steps_total"], "must_hit": ev["must_hits"],
                    "must_total": ev["gt_edges"], "rules_hit": ev["rule_hits"],
                    "rules_total": ev["rules_total"], "precision": ev["precision"],
                    "correct_edges": ev["correct_edges"],
                    "reported_triples": ev["reported_triples"],
                    "confirmed_edges": None, "llm_calls": None,
                    "elapsed": round(time.time() - t0, 1), "report_file": str(out),
                    "resumed": True,
                }
            else:
                res = m.run_single_scenario(sc, fold, str(out))
        except Exception as exc:  # 单场景失败不拖垮整批；如实记录，不补数字
            res = {
                "scenario": sc, "error": f"{type(exc).__name__}: {exc}",
                "recall": 0.0, "precision": 0.0, "steps_hit": 0, "steps_total": 0,
                "must_hit": 0, "must_total": 0, "rules_hit": [], "rules_total": 0,
                "correct_edges": 0, "reported_triples": 0, "confirmed_edges": None,
                "llm_calls": None, "elapsed": round(time.time() - t0, 1),
                "report_file": str(out), "failed": True,
            }
        res["group"] = group
        results.append(res)
        if res.get("failed"):
            print(f"[{time.strftime('%H:%M:%S')}] {group} {i}/{len(scenarios)} {sc} 失败：{res['error']}", flush=True)
            continue
        print(f"[{time.strftime('%H:%M:%S')}] {group} {i}/{len(scenarios)} {sc} "
              f"召回 {res['recall']:.4%} 查准 {res['precision']:.4%} "
              f"调用 {res.get('llm_calls')} 耗时 {res.get('elapsed')}s", flush=True)

    summary = {"group": group, "code_version": "b1-frozen-9c11503",
               "real_2hop": group == "b1", "results": results, "micro": micro(results)}
    dest = m.REPO_ROOT / f"tmp/frozen_runs/summary_{group}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[{time.strftime('%H:%M:%S')}] {group} 汇总 {json.dumps(summary['micro'], ensure_ascii=False)}", flush=True)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", choices=["b0", "b1", "both"], required=True)
    ap.add_argument("--scenarios", nargs="*", default=None)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    scenarios = args.scenarios or scenario_order()
    groups = ["b0", "b1"] if args.group == "both" else [args.group]
    for group in groups:
        run_group(group, scenarios, args.resume)


if __name__ == "__main__":
    main()
