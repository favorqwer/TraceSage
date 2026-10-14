import argparse
import json
import os
import sys
import time
from pathlib import Path

# 将项目目录加入 sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from prouter.layers.l1_reach import extract_raw_closure
from prouter.layers.l2_router.router import HybridRouter
from prouter.layers.l2_router.llm_judge import LlmJudge
from prouter.layers.l3_express.report import build_report, save_report
from prouter.offline.distiller import OfflineDistiller


def run_scenario(scenario_name: str, input_report: str = None, output_report: str = None, use_llm: bool = False):
    start_time = time.time()
    if not output_report:
        output_report = f"output/agent-runs/{scenario_name}.json"

    # 1. 第一层：获取反向因果闭包候选边
    deps = None
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
        if use_llm:
            raw_edges, closure_stats, deps = extract_raw_closure(scenario_name, return_deps=True)
        else:
            raw_edges, closure_stats = extract_raw_closure(scenario_name, return_deps=False)
        confirmed_edges = []
        unexcluded_edges = raw_edges
        excluded_edges = []
        print(f"[{scenario_name}] 因果闭包完成: 原始候选边={len(raw_edges)} 条 (闭包耗时: {closure_stats['closure_time_seconds']:.2f}s)")

    # 2. 离线抽象图模式加载
    distiller = OfflineDistiller()
    patterns = distiller.distill([])

    # 3. 第二层：神经符号混合分流
    t_route_0 = time.time()
    llm_judge = LlmJudge(deps=deps) if (use_llm and deps is not None) else None
    router = HybridRouter(patterns, llm_judge=llm_judge)
    route_result = router.route(confirmed_edges, unexcluded_edges)
    route_time = time.time() - t_route_0

    elapsed = time.time() - start_time

    # 4. 第三层：生成三段式报告并落盘
    report = build_report(
        scenario_name=scenario_name,
        confirmed_edges=route_result["confirmed"],
        unexcluded_edges=route_result["unexcluded"],
        excluded_edges=route_result.get("excluded", excluded_edges),
        pruned_count=route_result["pruned_count"],
        promoted_count=route_result["promoted_count"],
        elapsed_seconds=elapsed,
    )

    Path(output_report).parent.mkdir(parents=True, exist_ok=True)
    save_report(report, output_report)
    llm_calls = (deps.budget.calls if (deps and deps.budget) else 0)
    print(f"[{scenario_name}] 调查完成:")
    print(f"  已确认边数: {len(report['edges'])} 条")
    print(f"  因果初筛剥离背景: {route_result['pruned_count']} 条")
    print(f"  抽象模式确定性确认: {route_result['promoted_count']} 条")
    print(f"  大模型仲裁确认: {route_result['llm_confirmed_count']} 条 (模型调用: {llm_calls} 次)")
    print(f"  未排除保留候选边: {len(report['unexcluded'])} 条")
    print(f"  总耗时: {elapsed:.2f} 秒 (图闭包: {elapsed - route_time:.2f}s, 符号路由: {route_time:.3f}s)")
    print(f"  输出报告: {output_report}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Provenance-Router 神经符号因果拓扑与离线蒸馏路由系统")
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--input", default=None, help="可选：输入已有候选池文件（若不提供，则自主直连 Neo4j 数据库展开闭包调查）")
    parser.add_argument("--output", default=None, help="输出报告文件 (默认输出 output/agent-runs/<场景>.json)")
    parser.add_argument("--use-llm", action="store_true", help="启用大语言模型慢速分流仲裁（神经符号协同模式）")
    args = parser.parse_args()

    run_scenario(args.scenario, args.input, args.output, use_llm=args.use_llm)


if __name__ == "__main__":
    main()
