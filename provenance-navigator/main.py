import argparse
import json
import os
import sys
import time
from pathlib import Path

# 将项目目录加入 sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from closure import extract_raw_closure, list_scenarios
from judge import LlmJudge
from orchestrator import RouterOrchestrator, build_report, save_report
from rules import OfflineDistiller


def _extract_train_pools(train_scenarios):
    """训练候选池：运行期内逐场景现算轻量闭包（绝不使用历史运行产物顶替）。"""
    pools = {}
    for sc in train_scenarios:
        t0 = time.time()
        edges, stats = extract_raw_closure(sc, light=True)
        pools[sc] = edges
        print(f"  [训练池] {sc}: 候选边 {len(edges)} 条 (闭包耗时 {time.time() - t0:.2f}s)")
    return pools


def run_scenario(scenario_name: str, input_report: str = None, output_report: str = None,
                 mode: str = "hybrid", use_llm: bool = None):
    start_time = time.time()
    if not output_report:
        output_report = f"output/agent-runs/{scenario_name}.json"

    # 兼容老版 --use-llm 布尔值
    if use_llm is not None:
        mode = "hybrid" if use_llm else "rules"

    all_scenarios = list_scenarios()
    if scenario_name not in all_scenarios:
        raise KeyError(f"未知场景 {scenario_name}；可选场景: {all_scenarios}")
    train_scenarios = [s for s in all_scenarios if s != scenario_name]

    # 1. 第一层：获取反向因果闭包候选边（或从已有报告加载）
    deps = None
    anchor_triples = []
    need_deps = mode in ("hybrid", "llm-only")

    if input_report:
        if not os.path.exists(input_report):
            raise FileNotFoundError(f"未找到输入候选文件: {input_report}")
        with open(input_report, "r", encoding="utf-8") as f:
            data = json.load(f)
        confirmed_edges = data.get("edges", [])
        unexcluded_edges = data.get("unexcluded", [])
        excluded_edges = data.get("excluded", [])
        print(f"[{scenario_name}] 从已有报告加载: {input_report} (确认边={len(confirmed_edges)}, 未排除={len(unexcluded_edges)})")
    else:
        print(f"[{scenario_name}] 正在直连 Neo4j 图数据库，从 POI 终点事件自主展开反向因果闭包...")
        if need_deps:
            raw_edges, closure_stats, deps = extract_raw_closure(scenario_name, return_deps=True)
        else:
            raw_edges, closure_stats = extract_raw_closure(scenario_name, return_deps=False)
        anchor_triples = [tuple(t) for t in closure_stats.get("anchor_triples") or []]
        confirmed_edges = []
        unexcluded_edges = raw_edges
        excluded_edges = []
        print(f"[{scenario_name}] 因果闭包完成: 原始候选边={len(raw_edges)} 条 "
              f"(闭包耗时: {closure_stats['closure_time_seconds']:.2f}s, POI 锚点 {len(anchor_triples)} 条)")

    # 2. 离线统计蒸馏（仅在 rules 和 hybrid 模式下需要蒸馏基模；llm-only 旁路跳过）
    patterns = []
    if mode in ("rules", "hybrid"):
        print(f"[{scenario_name}] 离线统计蒸馏：训练场景 {', '.join(train_scenarios)}")
        pools = _extract_train_pools(train_scenarios)
        distiller = OfflineDistiller()
        patterns = distiller.distill(train_scenarios, pool_provider=lambda sc: pools[sc])
        audit_path = Path("tmp/provenance_router_runs") / f"distill_single_{scenario_name}.json"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_payload = dict(distiller.last_report)
        audit_payload["test_scenario"] = scenario_name
        audit_path.write_text(json.dumps(audit_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[{scenario_name}] 蒸馏完成：候选基模 {len(distiller.candidate_motifs)} 个 → 入选 {len(patterns)} 个"
              f"（审计: {audit_path}）")

    # 3. 神经符号调度编排（含 POI 锚点强制确认）
    t_route_0 = time.time()
    llm_judge = LlmJudge(deps=deps) if (need_deps and deps is not None) else None
    router = RouterOrchestrator(patterns, llm_judge=llm_judge, mode=mode)
    route_result = router.route(confirmed_edges, unexcluded_edges, anchor_triples=anchor_triples)
    route_time = time.time() - t_route_0

    elapsed = time.time() - start_time
    llm_calls = (deps.budget.calls if (deps and deps.budget) else 0)

    # 4. 生成三段式报告并落盘
    report = build_report(
        scenario_name=scenario_name,
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

    Path(output_report).parent.mkdir(parents=True, exist_ok=True)
    save_report(report, output_report)
    print(f"[{scenario_name}] 调查完成（模式: {mode}）:")
    print(f"  已确认边数: {len(report['edges'])} 条 (锚点强制确认 {route_result['anchor_confirmed_count']} 条)")
    print(f"  因果初筛剥离背景: {route_result['pruned_count']} 条")
    print(f"  抽象基模与桥接确认: {route_result['promoted_count']} 条 "
          f"({', '.join(f'{k}×{v}' for k, v in route_result['promoted_by_motif'].items()) or '无'})")
    print(f"  大模型仲裁确认: {route_result['llm_confirmed_count']} 条 (模型调用: {llm_calls} 次)")
    print(f"  未排除保留候选边: {len(report['unexcluded'])} 条")
    print(f"  总耗时: {elapsed:.2f} 秒 (图闭包: {elapsed - route_time:.2f}s, 符号路由: {route_time:.3f}s)")
    print(f"  输出报告: {output_report}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Provenance-Navigator 神经符号因果拓扑与离线蒸馏导航系统")
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--input", default=None, help="可选：输入已有候选池文件（若不提供，则自主直连 Neo4j 数据库展开闭包调查）")
    parser.add_argument("--output", default=None, help="输出报告文件 (默认输出 output/agent-runs/<场景>.json)")
    parser.add_argument("--mode", choices=["rules", "hybrid", "llm-only"], default=None,
                        help="运行模式：rules (纯规则), hybrid (智能路由), llm-only (纯大模型)")
    parser.add_argument("--use-llm", action="store_true", help="兼容参数：等价于 --mode hybrid")
    args = parser.parse_args()

    mode = args.mode
    if mode is None:
        mode = "hybrid" if args.use_llm else "rules"

    run_scenario(args.scenario, args.input, args.output, mode=mode)


if __name__ == "__main__":
    main()
