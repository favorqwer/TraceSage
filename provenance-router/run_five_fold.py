import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from prouter.layers.l1_reach import extract_raw_closure
from prouter.layers.l2_router.router import HybridRouter
from prouter.layers.l2_router.llm_judge import LlmJudge
from prouter.layers.l3_express.report import build_report, save_report
from prouter.offline.distiller import OfflineDistiller

ALL_SCENARIOS = [
    "1_Web_Exploit_Ransomware",
    "2_SSH_Spray_Lateral_Exfiltration",
    "3_Phishing_Beacon_Cryptomining",
    "4_Repo_Poisoning_Backdoor",
    "5_Exposed_Service_Pivot",
]


def run_single_fold(test_sc: str, train_scs: list, tmp_dir: Path, use_llm: bool = False) -> dict:
    start_time = time.time()
    gt_path = f"groundtruth/{test_sc}.groundtruth.json"

    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"未找到真值标准文件: {gt_path}")

    # 1. 自主连接 Neo4j 展开反向因果闭包
    t_closure_0 = time.time()
    deps = None
    if use_llm:
        raw_edges, closure_stats, deps = extract_raw_closure(test_sc, return_deps=True)
    else:
        raw_edges, closure_stats = extract_raw_closure(test_sc, return_deps=False)
    t_closure = time.time() - t_closure_0

    confirmed_edges = []
    unexcluded_edges = raw_edges
    excluded_edges = []

    # 2. 离线抽象图模式提炼（留一原则）
    distiller = OfflineDistiller()
    patterns = distiller.distill(train_scs)

    # 3. 神经符号混合路由
    t_route_0 = time.time()
    llm_judge = LlmJudge(deps=deps) if (use_llm and deps is not None) else None
    router = HybridRouter(patterns, llm_judge=llm_judge)
    route_result = router.route(confirmed_edges, unexcluded_edges)
    t_route = time.time() - t_route_0
    elapsed = time.time() - start_time

    # 4. 构造三段式报告并落盘
    report = build_report(
        scenario_name=test_sc,
        confirmed_edges=route_result["confirmed"],
        unexcluded_edges=route_result["unexcluded"],
        excluded_edges=route_result.get("excluded", excluded_edges),
        pruned_count=route_result["pruned_count"],
        promoted_count=route_result["promoted_count"],
        elapsed_seconds=elapsed,
    )

    mode_prefix = "hybrid" if use_llm else "rules"
    report_out = tmp_dir / f"{mode_prefix}_{test_sc}.json"
    save_report(report, str(report_out))

    # 5. 执行官方工具评测打分
    eval_out = tmp_dir / f"eval_{mode_prefix}_{test_sc}.json"
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

    llm_calls = (deps.budget.calls if (deps and deps.budget) else 0)

    return {
        "scenario": test_sc,
        "train_scenarios": train_scs,
        "raw_closure_edges": len(raw_edges),
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
    parser.add_argument("--use-llm", action="store_true", help="启用大语言模型慢速语义通道（智能路由模式）")
    args = parser.parse_args()

    mode_name = "智能路由模式（神经符号协同）" if args.use_llm else "纯蒸馏规则模式（0次大模型调用）"
    tmp_dir = Path("tmp/provenance_router_runs")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    print("==========================================================================================")
    print(f"       Provenance-Router 评测：{mode_name}")
    print("==========================================================================================")

    results = []
    for i, test_sc in enumerate(ALL_SCENARIOS):
        train_scs = [s for j, s in enumerate(ALL_SCENARIOS) if j != i]
        print(f"[{i+1}/5] 正在测试场景: {test_sc} ...")
        res = run_single_fold(test_sc, train_scs, tmp_dir, use_llm=args.use_llm)
        results.append(res)
        print(f"  -> 原生候选: {res['raw_closure_edges']} | 初筛剥离: {res['pruned_noise']} | "
              f"规则确认: {res['promoted_rules']} | 模型确认: {res['llm_confirmed']} (调用: {res['llm_calls']}次) | "
              f"确认边: {res['confirmed_edges']} | "
              f"召回: {res['hit']}/{res['total']} ({res['recall']*100:.1f}%) | "
              f"查准: {res['correct']}/{res['reported']} ({res['precision']*100:.1f}%) | "
              f"耗时: {res['elapsed']:.2f}s")

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

    summary_file = tmp_dir / f"summary_{'hybrid' if args.use_llm else 'rules'}.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump({
            "mode": mode_name,
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
