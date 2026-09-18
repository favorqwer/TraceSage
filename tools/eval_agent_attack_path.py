#!/usr/bin/env python
"""Agent 溯源报告 vs GT：召回/查准评估（与 tools/evaluate_gt.py 同一口径）。

用法:
    # 单个场景
    python tools/eval_agent_attack_path.py --report <results/场景.json> \
        --gt groundtruth/<场景>.groundtruth.json
    # 整个结果目录
    python tools/eval_agent_attack_path.py --all --results-dir <dir> \
        --gt-dir groundtruth [--json-out output/.../agent-metrics.json]

输入:
    - agent 报告 JSON：`{"scenario":..., "edges":[{"src","syscall","dst","confidence"?}, ...]}`；
      `edges` 也可以直接放在顶层数组（此时用 --scenario 指定场景名）。
    - GT：groundtruth/<场景>.groundtruth.json（attack_path）

口径（与 evaluate_gt.py 完全一致）:
    - 边 = (源内容, syscall, 目标内容) 精确三元组，同类边多实例去重后只算一条；
    - 召回 = 命中 GT 边数 / GT 边数；
    - 查准 = 命中数 / agent 报告去重后的内容三元组数（多出边一律计入分母）。
    - 缺 syscall 的边无法比对，计入 skipped 并在报告末尾提示（不计入分母）。
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import evaluate_gt as eg  # noqa: E402

CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


def load_agent_report(path, scenario=None, min_confidence=None):
    """agent 报告 -> (scenario, {(src,syscall,dst): dict}, skipped)。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        edges = data
        scenario = scenario or Path(path).stem
    else:
        edges = data.get("edges") or []
        scenario = scenario or data.get("scenario") or Path(path).stem
    triples = {}
    skipped = 0
    dropped_confidence = 0
    for edge in edges:
        src, dst = edge.get("src"), edge.get("dst")
        syscall = edge.get("syscall")
        if not src or not dst or not syscall:
            skipped += 1
            continue
        if min_confidence:
            have = edge.get("confidence")
            if have is not None and CONFIDENCE_ORDER.get(str(have).lower(), 0) < CONFIDENCE_ORDER[min_confidence]:
                dropped_confidence += 1
                continue
        triples.setdefault((src, syscall, dst), edge)
    return scenario, triples, skipped, dropped_confidence


def evaluate(report_path, gt_path, min_confidence=None, scenario=None):
    scenario, triples, skipped, dropped = load_agent_report(report_path, scenario, min_confidence)
    gt, gt_triples = eg.load_gt(gt_path)
    hits = [g for g in gt_triples if (g[0], g[1], g[2]) in triples]
    missed = [g for g in gt_triples if (g[0], g[1], g[2]) not in triples]
    gt_keys = {(g[0], g[1], g[2]) for g in gt_triples}
    extras = sorted(k for k in triples if k not in gt_keys)
    return {
        "scenario": scenario,
        "report": str(report_path),
        "gt": str(gt_path),
        "gt_edges": len(gt_triples),
        "reported_triples": len(triples),
        "hits": len(hits),
        "misses": len(missed),
        "extra_triples": len(extras),
        "skipped_edges": skipped,
        "dropped_by_confidence": dropped,
        "recall": len(hits) / len(gt_triples) if gt_triples else 0.0,
        "precision": len(hits) / len(triples) if triples else 0.0,
        "missed_list": [{"src": m[0], "syscall": m[1], "dst": m[2], "phase": m[3]} for m in missed],
        "extra_list": [{"src": e[0], "syscall": e[1], "dst": e[2]} for e in extras],
    }


def print_report(result):
    print(f"\n== {result['scenario']} ==")
    print(f"report: {result['report']}")
    print(f"gt:     {result['gt']}")
    print(
        f"召回 {result['hits']}/{result['gt_edges']} = {result['recall']:.1%}   "
        f"查准 {result['hits']}/{result['reported_triples']} = {result['precision']:.1%}"
    )
    if result["skipped_edges"]:
        print(f"警告: {result['skipped_edges']} 条边缺 src/dst/syscall，无法比对，已排除")
    if result["dropped_by_confidence"]:
        print(f"信息: 按 --min-confidence 过滤掉 {result['dropped_by_confidence']} 条边")
    if result["missed_list"]:
        print(f"未召回 ({len(result['missed_list'])}):")
        for m in result["missed_list"]:
            print(f"  [{m['phase']}] {m['src']} --{m['syscall']}--> {m['dst']}")
    if result["extra_list"]:
        print(f"多出边 ({len(result['extra_list'])}):")
        for e in result["extra_list"]:
            print(f"  {e['src']} --{e['syscall']}--> {e['dst']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", help="单个 agent 报告 JSON")
    ap.add_argument("--gt", help="对应 GT JSON")
    ap.add_argument("--all", action="store_true", help="批量：--results-dir 下每个 <场景>.json 对 --gt-dir/<场景>.groundtruth.json")
    ap.add_argument("--results-dir", default=str(ROOT / "output" / "agent-vs-engine" / "results"))
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--scenario", help="报告顶层是数组时用于指定场景名")
    ap.add_argument("--min-confidence", choices=["high", "medium", "low"],
                    help="只统计该置信度及以上的边（未标注 confidence 的边保留）")
    ap.add_argument("--json-out", help="把逐场景指标写入该 JSON（含合计 micro）")
    args = ap.parse_args()

    results = []
    if args.all:
        results_dir = Path(args.results_dir)
        gt_dir = Path(args.gt_dir)
        if not results_dir.is_dir():
            sys.exit(f"结果目录不存在: {results_dir}")
        for report_path in sorted(results_dir.glob("*.json")):
            scenario = report_path.stem
            gt_path = gt_dir / f"{scenario}.groundtruth.json"
            if not gt_path.exists():
                print(f"跳过 {report_path.name}: 找不到 {gt_path.name}")
                continue
            res = evaluate(report_path, gt_path, args.min_confidence, scenario)
            results.append(res)
            print_report(res)
    else:
        if not args.report or not args.gt:
            ap.error("需要 --report 与 --gt（或 --all）")
        res = evaluate(args.report, args.gt, args.min_confidence, args.scenario)
        results.append(res)
        print_report(res)

    if results:
        tot_gt = sum(r["gt_edges"] for r in results)
        tot_hits = sum(r["hits"] for r in results)
        tot_tri = sum(r["reported_triples"] for r in results)
        print("\n== 合计（micro，未过滤项按 --min-confidence 处理）==")
        print(f"场景数 {len(results)}  召回 {tot_hits}/{tot_gt} = "
              f"{(tot_hits/tot_gt if tot_gt else 0):.1%}  查准 {tot_hits}/{tot_tri} = "
              f"{(tot_hits/tot_tri if tot_tri else 0):.1%}")
        if args.json_out:
            out = {
                "convention": "边=(源内容,syscall,目标内容) 精确三元组；召回=命中/GT；查准=命中/报告去重三元组（无豁免清单）",
                "min_confidence": args.min_confidence,
                "scenarios": [{k: v for k, v in r.items() if k not in ("missed_list", "extra_list")} for r in results],
                "totals": {
                    "gt_edges": tot_gt,
                    "hits": tot_hits,
                    "reported_triples": tot_tri,
                    "recall_micro": (tot_hits / tot_gt if tot_gt else 0.0),
                    "precision_micro": (tot_hits / tot_tri if tot_tri else 0.0),
                },
                "details": {r["scenario"]: {"missed": r["missed_list"], "extra": r["extra_list"]} for r in results},
            }
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json_out).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"指标已写入 {args.json_out}")


if __name__ == "__main__":
    main()
