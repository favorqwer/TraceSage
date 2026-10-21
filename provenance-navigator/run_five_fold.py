import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from closure import extract_raw_closure, list_scenarios
from judge import LlmJudge
from orchestrator import RouterOrchestrator, build_report, save_report
from rules import OfflineDistiller, FrequentSubgraphMiner


def make_pool_provider():
    """训练候选池提供器：同一运行期内每个场景只现算一次轻量闭包（绝不使用历史运行产物）。"""
    cache = {}

    def provider(sc):
        if sc not in cache:
            t0 = time.time()
            edges, _stats = extract_raw_closure(sc, light=True)
            cache[sc] = edges
            print(f"    [训练池] {sc}: 候选边 {len(edges)} 条 (闭包耗时 {time.time() - t0:.2f}s)")
        return cache[sc]

    return provider


def run_single_fold(test_sc: str, train_scs: list, tmp_dir: Path, pool_provider,
                    mode: str = "hybrid", tag: str = None,
                    load_distilled: bool = False, gt_dir: str = "groundtruth") -> dict:
    if tag is None:
        tag = mode
    start_time = time.time()
    gt_path = os.path.join(gt_dir, f"{test_sc}.groundtruth.json")

    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"未找到真值标准文件: {gt_path}")

    need_deps = mode in ("hybrid", "llm-only")

    # 1. 自主连接 Neo4j 展开反向因果闭包（含 POI 锚点三元组）
    t_closure_0 = time.time()
    deps = None
    if need_deps:
        raw_edges, closure_stats, deps = extract_raw_closure(test_sc, return_deps=True)
    else:
        raw_edges, closure_stats = extract_raw_closure(test_sc, return_deps=False)
    t_closure = time.time() - t_closure_0
    anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]

    confirmed_edges = []
    unexcluded_edges = raw_edges
    excluded_edges = []

    # 2. 离线统计蒸馏（仅在 rules 和 hybrid 模式下执行；llm-only 旁路跳过）
    patterns = []
    pool_sizes = {}
    if mode in ("rules", "hybrid"):
        distill_audit = tmp_dir / f"distill_fold_{tag}_{test_sc}.json"
        if load_distilled and distill_audit.exists():
            with open(distill_audit, "r", encoding="utf-8") as f:
                audit = json.load(f)
            distilled_ids = set(audit.get("distilled_ids", []))
            considered_map = {c["id"]: c for c in audit.get("considered", [])}
            miner = FrequentSubgraphMiner(min_support=1)
            raw_motifs = miner.mine(train_scs)
            patterns = []
            for m in raw_motifs:
                if m["id"] in distilled_ids:
                    c = considered_map.get(m["id"], {})
                    full_m = dict(m)
                    full_m.update({
                        "train_precision": c.get("train_precision", 1.0),
                        "bayes_precision": c.get("bayes_precision", 1.0),
                        "bayes_lift": c.get("bayes_lift", 1.0),
                    })
                    patterns.append(full_m)
            pool_sizes = audit.get("pool_sizes", {})
            print(f"    [规则复用] 已从 {distill_audit.name} 复用留一蒸馏基模 {len(patterns)} 条")
        else:
            distiller = OfflineDistiller()
            patterns = distiller.distill(train_scs, pool_provider=pool_provider)
            distill_audit = tmp_dir / f"distill_fold_{tag}_{test_sc}.json"
            audit_payload = dict(distiller.last_report)
            audit_payload["test_scenario"] = test_sc
            with open(distill_audit, "w", encoding="utf-8") as f:
                json.dump(audit_payload, f, indent=2, ensure_ascii=False)
            pool_sizes = distiller.last_report.get("pool_sizes", {})

    # 3. 神经符号混合路由（含 POI 锚点强制确认）
    t_route_0 = time.time()
    llm_judge = LlmJudge(deps=deps) if (need_deps and deps is not None) else None
    router = RouterOrchestrator(patterns, llm_judge=llm_judge, mode=mode)
    route_result = router.route(confirmed_edges, unexcluded_edges, anchor_triples=anchor_triples)
    t_route = time.time() - t_route_0
    elapsed = time.time() - start_time
    llm_calls = (deps.budget.calls if (deps and deps.budget) else 0)

    # 4. 构造三段式报告并落盘
    report = build_report(
        scenario_name=test_sc,
        confirmed_edges=route_result["confirmed"],
        unexcluded_edges=route_result["unexcluded"],
        excluded_edges=route_result.get("excluded", excluded_edges),
        pruned_count=route_result["pruned_count"],
        promoted_count=route_result["promoted_count"],
        elapsed_seconds=elapsed,
        llm_calls=llm_calls,
        llm_enabled=need_deps,
        anchor_confirmed_count=route_result["anchor_confirmed_count"],
        promoted_by_motif=route_result["promoted_by_motif"],
        matcher_min_conf=route_result.get("matcher_min_conf"),
        conf_filtered_count=route_result.get("conf_filtered_count", 0),
        mode=mode,
    )

    report_out = tmp_dir / f"{tag}_{test_sc}.json"
    save_report(report, str(report_out))

    # 5. 执行官方工具评测打分
    eval_out = tmp_dir / f"eval_{tag}_{test_sc}.json"
    cmd = [
        sys.executable,
        "tools/eval_agent_attack_path.py",
        "--report", str(report_out),
        "--gt", gt_path,
        "--json-out", str(eval_out),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with open(eval_out, "r", encoding="utf-8") as f:
        eval_data = json.load(f)["scenarios"][0]

    return {
        "scenario": test_sc,
        "train_scenarios": train_scs,
        "raw_closure_edges": len(raw_edges),
        "anchor_confirmed": route_result["anchor_confirmed_count"],
        "distilled_motifs": [m["id"] for m in patterns],
        "promoted_by_motif": route_result["promoted_by_motif"],
        "distill_pool_sizes": pool_sizes,
        "pruned_noise": route_result["pruned_count"],
        "promoted_rules": route_result["promoted_count"],
        "llm_confirmed": route_result["llm_confirmed_count"],
        "llm_calls": llm_calls,
        "confirmed_edges": len(report["edges"]),
        "unexcluded_edges": len(report["unexcluded"]),
        "hit": eval_data["steps_hit"],
        "total": eval_data["steps_total"],
        "recall": eval_data["recall"],
        "correct": eval_data["correct_edges"],
        "reported": eval_data["reported_triples"],
        "precision": eval_data["precision"],
        "extra": eval_data["extra_triples"],
        "closure_time": t_closure,
        "route_time": t_route,
        "elapsed": elapsed,
    }


def main():
    parser = argparse.ArgumentParser(description="五折留一交叉评测运行器")
    parser.add_argument("--mode", choices=["rules", "hybrid", "llm-only"], default=None,
                        help="评测模式：rules (纯规则), hybrid (智能路由), llm-only (纯大模型)")
    parser.add_argument("--use-llm", action="store_true", help="兼容参数：等价于 --mode hybrid")
    parser.add_argument("--db-suffix", default="", help="数据库后缀（例如 -v2）")
    parser.add_argument("--load-distilled", action="store_true", help="复用已存在的逐折离线蒸馏基模审计文件，跳过耗时的基模重复挖掘与检验")
    parser.add_argument("--gt-dir", default="groundtruth", help="GT 真值标准目录（默认为 groundtruth）")
    args = parser.parse_args()

    mode = args.mode
    if mode is None:
        mode = "hybrid" if args.use_llm else "rules"

    if args.db_suffix:
        os.environ["NAVIGATOR_DB_SUFFIX"] = args.db_suffix
    tag = f"{mode}{args.db_suffix}"

    mode_name_map = {
        "rules": "纯蒸馏规则模式（0次大模型调用）",
        "hybrid": "智能导航模式（神经符号协同）",
        "llm-only": "纯大语言模型模式（旁路规则截流）",
    }
    mode_name = mode_name_map[mode]

    tmp_dir = Path("tmp/provenance_router_runs")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    all_scenarios = list_scenarios()
    pool_provider = make_pool_provider()

    print("==========================================================================================")
    print(f"       Provenance-Navigator 评测：{mode_name} [mode={mode}, tag={tag}]")
    print(f"       五折留一：每折训练集 = 其余 {len(all_scenarios) - 1} 个场景；训练候选池运行期内现算")
    print("==========================================================================================")

    results = []
    for i, test_sc in enumerate(all_scenarios):
        train_scs = [s for s in all_scenarios if s != test_sc]
        print(f"[{i+1}/{len(all_scenarios)}] 正在测试场景: {test_sc} ...")
        res = run_single_fold(test_sc, train_scs, tmp_dir, pool_provider, mode=mode, tag=tag,
                              load_distilled=args.load_distilled, gt_dir=args.gt_dir)
        results.append(res)
        print(f"  -> 原生候选: {res['raw_closure_edges']} | 锚点: {res['anchor_confirmed']} | "
              f"初筛剥离: {res['pruned_noise']} | "
              f"规则确认: {res['promoted_rules']} | 模型确认: {res['llm_confirmed']} (调用: {res['llm_calls']}次) | "
              f"确认边: {res['confirmed_edges']} | "
              f"召回: {res['hit']}/{res['total']} ({res['recall']*100:.1f}%) | "
              f"查准: {res['correct']}/{res['reported']} ({res['precision']*100:.1f}%) | "
              f"耗时: {res['elapsed']:.2f}s")
        print(f"     入选基模: {', '.join(res['distilled_motifs']) or '无'}")

    print("\n" + "="*115)
    print(f"{'场景':<35} | {'召回 (步骤)':<18} | {'查准 (边)':<16} | {'确认边':<8} | {'模型调用':<8} | {'耗时':<8}")
    print("="*115)

    tot_hit = sum(r["hit"] for r in results)
    tot_total = sum(r["total"] for r in results)
    tot_correct = sum(r["correct"] for r in results)
    tot_reported = sum(r["reported"] for r in results)
    tot_calls = sum(r["llm_calls"] for r in results)
    tot_elapsed = sum(r["elapsed"] for r in results)

    for r in results:
        sc = r["scenario"]
        rec_s = f"{r['recall']*100:.1f}% ({r['hit']}/{r['total']})"
        prec_s = f"{r['precision']*100:.1f}% ({r['correct']}/{r['reported']})"
        print(f"{sc:<35} | {rec_s:<18} | {prec_s:<16} | {r['confirmed_edges']:<8} | {r['llm_calls']:<8} | {r['elapsed']:.1f}s")

    print("="*115)
    micro_rec = tot_hit / tot_total * 100 if tot_total else 0
    micro_prec = tot_correct / tot_reported * 100 if tot_reported else 0

    print(f"{'合计 (Micro)':<35} | "
          f"{micro_rec:.1f}% ({tot_hit}/{tot_total}) | "
          f"{micro_prec:.1f}% ({tot_correct}/{tot_reported}) | "
          f"{sum(r['confirmed_edges'] for r in results):<8} | {tot_calls:<8} | "
          f"{tot_elapsed:.2f}s")
    print("="*115)

    summary_file = tmp_dir / f"summary_{tag}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump({
            "mode": mode_name,
            "mode_key": mode,
            "protocol": "五折留一：训练集 = 其余场景；训练候选池运行期内现算轻量闭包；锚点强制确认已启用",
            "results": results,
            "micro": {
                "hit": tot_hit,
                "total": tot_total,
                "recall": micro_rec / 100,
                "correct": tot_correct,
                "reported": tot_reported,
                "precision": micro_prec / 100,
                "calls": tot_calls,
                "elapsed": tot_elapsed,
            }
        }, f, indent=2, ensure_ascii=False)
    print(f"\n完整评测结果已写入: {summary_file}")


if __name__ == "__main__":
    main()
