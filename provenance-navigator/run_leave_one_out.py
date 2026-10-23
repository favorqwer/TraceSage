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
from rules import OfflineDistiller
from rules import offline as distill_frozen
from pipeline import investigate, load_rule_matcher


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
                    gt_dir: str = "groundtruth",
                    rules_from: str = "frozen",
                    library: tuple = None) -> dict:
    if tag is None:
        tag = mode
    start_time = time.time()
    gt_path = os.path.join(gt_dir, f"{test_sc}.groundtruth.json")
    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"未找到真值标准文件: {gt_path}")

    report_out = tmp_dir / f"{tag}_{test_sc}.json"
    report, audit = investigate(
        test_sc,
        mode=mode,
        rules_from=rules_from,
        output_report=str(report_out),
        pool_provider=pool_provider,
        train_scenarios=train_scs,
        library=library,
        return_audit=True,
    )

    eval_out = tmp_dir / f"eval_{tag}_{test_sc}.json"
    cmd = [
        sys.executable,
        "tools/score_report_product.py",
        "--report", str(report_out),
        "--gt", gt_path,
        "--json-out", str(eval_out),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with open(eval_out, "r", encoding="utf-8") as f:
        eval_data = json.load(f)["scenarios"][0]

    lib = audit.get("library_audit") or {}
    stats = report.get("stats") or {}
    return {
        "scenario": test_sc,
        "train_scenarios": train_scs,
        "distill_source": rules_from,
        "distill_artifact": lib.get("path") or ("(fresh)" if rules_from == "fresh" else ""),
        "raw_closure_edges": audit.get("raw_closure_edges", 0),
        "anchor_confirmed": stats.get("anchor_confirmed_count", 0),
        "distilled_motifs": lib.get("distilled_ids") or [],
        "promoted_by_motif": stats.get("promoted_by_motif") or {},
        "distill_pool_sizes": lib.get("pool_sizes") or {},
        "pruned_noise": stats.get("pruned_noise_count", 0),
        "promoted_rules": stats.get("promoted_count", 0),
        "llm_confirmed": audit.get("llm_confirmed_count", 0),
        "llm_calls": stats.get("llm_calls", 0),
        "confirmed_edges": len(report.get("edges") or []),
        "unexcluded_edges": len(report.get("unexcluded") or []),
        "hit": eval_data["steps_hit"],
        "total": eval_data["steps_total"],
        "recall": eval_data["recall"],
        "correct": eval_data["correct_edges"],
        "reported": eval_data["reported_triples"],
        "precision": eval_data["precision"],
        "extra": eval_data["extra_triples"],
        "closure_time": audit.get("closure_seconds", 0.0),
        "route_time": audit.get("route_seconds", 0.0),
        "elapsed": time.time() - start_time,
    }


def main():
    parser = argparse.ArgumentParser(description="全场景评测运行器（规则库由全部场景蒸馏一次生成，所有场景共用）")
    parser.add_argument("--mode", choices=["rules", "hybrid", "llm-only"], default=None,
                        help="评测模式：rules (纯规则), hybrid (智能路由), llm-only (纯大模型)")
    parser.add_argument("--use-llm", action="store_true", help="兼容参数：等价于 --mode hybrid")
    parser.add_argument("--db-suffix", default="", help="数据库后缀（例如 -v2）")
    parser.add_argument("--rules-from", choices=["fresh", "frozen"], default="frozen",
                        help="基模来源：frozen = 读 config/rules-library.json 的冻结产物（默认，不建训练池、不蒸馏）；"
                             "fresh = 本轮现蒸馏（只在重新冻结时用）")
    parser.add_argument("--freeze", action="store_true",
                        help="现蒸馏后把规则库写入 provenance-navigator/config/rules-library.json"
                             "（只能与 --rules-from fresh 同用）")
    parser.add_argument("--freeze-only", action="store_true",
                        help="只蒸馏并写规则库，不跑评测（隐含 --freeze；只能与 --rules-from fresh 同用）")
    parser.add_argument("--gt-dir", default="groundtruth", help="GT 真值标准目录（默认为 groundtruth）")
    args = parser.parse_args()

    mode = args.mode
    if mode is None:
        mode = "hybrid" if args.use_llm else "rules"

    if args.freeze and args.rules_from != "fresh":
        raise SystemExit("[阻断] --freeze 只能与 --rules-from fresh 同用（规则库本身就是 fresh 的产物）")
    if args.freeze_only:
        args.freeze = True
        if args.rules_from != "fresh":
            raise SystemExit("[阻断] --freeze-only 只能与 --rules-from fresh 同用")
    if args.freeze and mode not in ("rules", "hybrid"):
        raise SystemExit("[阻断] llm-only 模式不蒸馏基模，--freeze 无意义")

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
    print(f"       规则库：全部场景蒸馏成一份，所有场景共用（{len(all_scenarios)} 个场景）")
    print("==========================================================================================")

    # 规则库：一份给所有场景用；fresh = 用全部场景蒸馏一次（可落盘），frozen = 直接读文件
    library = None
    if mode in ("rules", "hybrid"):
        if args.rules_from == "frozen":
            patterns, audit = distill_frozen.load_library()
            library = (patterns, audit)
            print(f"       规则库：{audit['path']}\n"
                  f"         生成于 {audit.get('generated_at')}，训练场景 {len(audit['train_scenarios'])} 个，"
                  f"入选规则 {len(patterns)} 条")
        else:
            print(f"       现蒸馏：训练集 = 全部 {len(all_scenarios)} 个场景")
            distiller = OfflineDistiller(rule_matcher=load_rule_matcher())
            patterns = distiller.distill(all_scenarios, pool_provider=pool_provider)
            report = dict(distiller.last_report)
            if args.freeze:
                out = distill_frozen.save_library(patterns, report, all_scenarios)
                report["path"] = str(out)
                print(f"       规则库已写入 {out}（入选规则 {len(patterns)} 条 / 候选 {report.get('mined_raw_count')}）")
            else:
                report["path"] = "(未落盘)"
            library = (patterns, report)
            if args.freeze_only:
                print("       --freeze-only：只生成规则库，不跑评测")
                return

    results = []
    for i, test_sc in enumerate(all_scenarios):
        train_scs = [s for s in all_scenarios if s != test_sc]
        print(f"[{i+1}/{len(all_scenarios)}] 正在测试场景: {test_sc} ...")
        res = run_single_fold(test_sc, train_scs, tmp_dir, pool_provider, mode=mode, tag=tag,
                              gt_dir=args.gt_dir, rules_from=args.rules_from, library=library)
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
            "protocol": ("规则库统一：全部场景蒸馏成一份规则库，所有场景共用；"
                         + ("本轮读自 config/rules-library.json" if args.rules_from == "frozen"
                            else "本轮现蒸馏")
                         + "；锚点强制确认已启用"),
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
