#!/usr/bin/env python
"""Agent 溯源报告 vs GT：召回/查准评估。

用法:
    # 单个场景
    python tools/score_report_product.py --report <results/场景.json> \
        --gt groundtruth/<场景>.groundtruth.json
    # 整个结果目录
    python tools/score_report_product.py --all --results-dir <dir> \
        --gt-dir groundtruth [--json-out output/.../agent-metrics.json]

输入:
    - agent 报告 JSON：`{"scenario":..., "edges":[{"src","syscall","dst"}, ...]}`；
      `edges` 也可以直接放在顶层数组（此时用 --scenario 指定场景名）。
    - GT：groundtruth/<场景>.groundtruth.json（attack_path：必须集合 edges + 可能集合 rules）

口径（与 score_graph_product.py 完全一致）:
    - 边 = (源内容, syscall, 目标内容) 精确三元组，同类边多实例去重后只算一条；
    - 召回（按步骤）= (命中的必须条目数 + 命中的规则数) / (必须条目数 + 规则数)；
    - 查准（按边）= (报告里命中必须条目的边数 + 满足某条规则的边数) / 报告去重后的内容三元组数；
    - 规则 action 允许写动作名（send/recv/create/mmap_exec…）或 syscall 名，动作名按
      rules_match.ACTION_TO_SYSCALLS 展开后判定；规则里的 effect / bytes 条件只看报告边
      是否自带对应字段，带就严格判，不带就披露（effect_unchecked / edge_attrs_skipped）；
    - 规则条件里的端点种类（process/file/network）从场景库（-v2）的顶点标签判定；
    - 缺 syscall 的边无法比对，计入 skipped 并在报告末尾提示（不计入分母）。
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import score_graph_product as eg  # noqa: E402
import rules_match as rm  # noqa: E402


def report_syscall(edge):
    """报告边 -> 参与比对用的 syscall 名。

    标准报告直接带 `syscall`（-v2 图的边属性）。只带 `action` 的旧式报告按
    rules_match.ACTION_TO_SYSCALLS 反推；反推不唯一（如 send -> sendto/sendfile）
    就返回 None，由调用方计 skipped——宁可排除，不靠猜。
    """
    syscall = edge.get("syscall")
    if syscall:
        return syscall
    action = edge.get("action")
    if not action:
        return None
    candidates = rm.ACTION_TO_SYSCALLS.get(action)
    if not candidates:
        return action
    return next(iter(candidates)) if len(candidates) == 1 else None


def report_effects(edge):
    """报告边的成败口径：优先单数 effect，其次复数 effects；多值展开为多个四元组。

    评测协议要求四元组 (源, 系统调用, 目标, 成败)。报告边若聚合了成功与失败两类实例，
    必须分别计入，不能统一写成 None，否则「成败从未核验」。
    """
    if edge.get("effect") is not None:
        return [edge.get("effect")]
    effects = edge.get("effects")
    if isinstance(effects, (list, tuple)):
        return list(effects) if effects else [None]
    return [effects] if effects is not None else [None]


def load_agent_report(path, scenario=None):
    """agent 报告 -> (scenario, {(src,syscall,dst): dict}, skipped)。

    报告里的其它字段（含模型自报的把握）一律不读：评分只看内容三元组。
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        edges = data
        scenario = scenario or Path(path).stem
    else:
        edges = data.get("edges") or []
        scenario = scenario or data.get("scenario") or Path(path).stem
    # 去重单位 = 四元组（源, 系统调用, 目标, 成败）：同一三元组可能同时存在成功与失败两条，
    # 若按三元组去重会丢掉其中一条，导致「GT 说成功、报告只剩失败」这种假漏报。
    quads = {}
    skipped = 0
    for edge in edges:
        src = eg.strip_endpoint_key(edge.get("src"))
        dst = eg.strip_endpoint_key(edge.get("dst"))
        syscall = report_syscall(edge)
        if not src or not dst or not syscall:
            skipped += 1
            continue
        for effect in report_effects(edge):
            quads.setdefault((src, syscall, dst, effect), edge)
    return scenario, quads, skipped


def evaluate(report_path, gt_path, scenario=None):
    scenario, quads, skipped = load_agent_report(report_path, scenario)
    gt, gt_triples = eg.load_gt(gt_path)
    rules = rm.load_rules(gt)
    kinds = rm.VertexKinds.for_gt(gt)
    rows = []
    for (src, syscall, dst, effect), edge in quads.items():
        attrs = {"bytes": edge["bytes"]} if edge.get("bytes") is not None else None
        rows.append((src, syscall, dst, effect, attrs))
    met = rm.evaluate_report(gt_triples, rules, rows, kinds=kinds)
    return {
        "scenario": scenario,
        "report": str(report_path),
        "gt": str(gt_path),
        "gt_edges": met["gt_edges"],
        "rules_total": met["rules_total"],
        "steps_total": met["steps_total"],
        "steps_hit": met["steps_hit"],
        "must_hits": len(met["must_hits"]),
        "rule_hits": met["rule_hits"],
        "rule_misses": met["rule_misses"],
        "reported_triples": met["reported_triples"],
        "correct_edges": met["correct_edges"],
        "extra_triples": len(met["extras"]),
        "skipped_edges": skipped,
        "recall_steps": met["recall_steps"],
        "recall": met["recall_steps"],
        "precision_edges": met["precision_edges"],
        "precision": met["precision_edges"],
        "kinds_degraded": met["kinds_degraded"],
        "edge_attrs_skipped": met["edge_attrs_skipped"],
        "effect_unchecked": met["effect_unchecked"],
        "missed_list": [{"src": m[0], "syscall": m[1], "dst": m[2], "effect": m[3], "phase": m[4]}
                        for m in met["must_misses"]],
        "extra_list": [{"src": e[0], "syscall": e[1], "dst": e[2], "effect": e[3]} for e in met["extras"]],
    }


def print_report(result):
    print(f"\n== {result['scenario']} ==")
    print(f"report: {result['report']}")
    print(f"gt:     {result['gt']}")
    print(
        f"召回（按步骤） {result['steps_hit']}/{result['steps_total']} = {result['recall_steps']:.1%}   "
        f"（必须条目 {result['must_hits']}/{result['gt_edges']}，规则 "
        f"{len(result['rule_hits'])}/{result['rules_total']}）"
    )
    print(
        f"查准（按边）   {result['correct_edges']}/{result['reported_triples']} = "
        f"{result['precision_edges']:.1%}"
    )
    if result.get("kinds_degraded"):
        print("提示: 未取到场景库的顶点种类，规则里的 vertex 条件未参与判定")
    if result.get("effect_unchecked"):
        print(f"提示: 规则 {', '.join(result['effect_unchecked'])} 写了 effect 条件，"
              "但报告边不带成败，该条件按「不否决」处理")
    if result.get("edge_attrs_skipped"):
        print(f"提示: 规则 {', '.join(result['edge_attrs_skipped'])} 的 edge 数值条件"
              "缺报告边属性，未参与判定")
    if result["skipped_edges"]:
        print(f"警告: {result['skipped_edges']} 条边缺 src/dst/syscall，无法比对，已排除")
    if result["missed_list"]:
        print(f"未召回的必须条目 ({len(result['missed_list'])}):")
        for m in result["missed_list"]:
            print(f"  [{m['phase']}] {m['src']} --{m['syscall']}--> {m['dst']}")
    if result["rule_misses"]:
        print(f"未命中的规则: {', '.join(result['rule_misses'])}")
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
            res = evaluate(report_path, gt_path, scenario)
            results.append(res)
            print_report(res)
    else:
        if not args.report or not args.gt:
            ap.error("需要 --report 与 --gt（或 --all）")
        res = evaluate(args.report, args.gt, args.scenario)
        results.append(res)
        print_report(res)

    if results:
        tot_steps = sum(r["steps_total"] for r in results)
        tot_steps_hit = sum(r["steps_hit"] for r in results)
        tot_correct = sum(r["correct_edges"] for r in results)
        tot_tri = sum(r["reported_triples"] for r in results)
        print("\n== 合计（micro）==")
        print(f"场景数 {len(results)}  召回（按步骤）{tot_steps_hit}/{tot_steps} = "
              f"{(tot_steps_hit/tot_steps if tot_steps else 0):.1%}  查准（按边）{tot_correct}/{tot_tri} = "
              f"{(tot_correct/tot_tri if tot_tri else 0):.1%}")
        if args.json_out:
            out = {
                "convention": "边=(源内容,syscall,目标内容) 精确三元组；召回按步骤（必须条目 + 规则），查准按边（命中条目边 + 满足规则的边）/报告去重三元组（无豁免清单）；规则 action 支持动作名与 syscall 名两种词表",
                "scenarios": [{k: v for k, v in r.items() if k not in ("missed_list", "extra_list")} for r in results],
                "totals": {
                    "gt_edges": sum(r["gt_edges"] for r in results),
                    "rules_total": sum(r["rules_total"] for r in results),
                    "steps_total": tot_steps,
                    "steps_hit": tot_steps_hit,
                    "reported_triples": tot_tri,
                    "correct_edges": tot_correct,
                    "recall_steps_micro": (tot_steps_hit / tot_steps if tot_steps else 0.0),
                    "precision_edges_micro": (tot_correct / tot_tri if tot_tri else 0.0),
                },
                "details": {r["scenario"]: {"missed": r["missed_list"], "extra": r["extra_list"],
                                            "rule_misses": r["rule_misses"]} for r in results},
            }
            Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json_out).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"指标已写入 {args.json_out}")


if __name__ == "__main__":
    main()
