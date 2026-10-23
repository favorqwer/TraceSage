"""单场景 CLI：只解析参数并调用 `pipeline.investigate`。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline import investigate  # noqa: E402


def run_scenario(scenario_name: str, input_report: str = None, output_report: str = None,
                 mode: str = "hybrid", use_llm: bool = None, rules_from: str = "frozen"):
    """兼容旧调用：`use_llm` 为真等价于 hybrid。"""
    if use_llm is not None:
        mode = "hybrid" if use_llm else "rules"
    return investigate(
        scenario_name,
        mode=mode,
        rules_from=rules_from,
        input_report=input_report,
        output_report=output_report,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provenance-Navigator 神经符号因果拓扑与离线蒸馏导航系统"
    )
    parser.add_argument("--scenario", required=True, help="场景全名")
    parser.add_argument("--input", default=None,
                        help="可选：输入已有候选池文件（不提供则直连 Neo4j 展开闭包）")
    parser.add_argument("--output", default=None,
                        help="输出报告文件（默认 output/navigator-runs/<场景>.json）")
    parser.add_argument("--mode", choices=["rules", "hybrid", "llm-only"], default=None,
                        help="运行模式：rules / hybrid / llm-only")
    parser.add_argument("--use-llm", action="store_true", help="兼容参数：等价于 --mode hybrid")
    parser.add_argument("--rules-from", choices=["frozen", "fresh"], default="frozen",
                        help="规则库来源：frozen = 读冻结产物（默认）；fresh = 现蒸馏")
    args = parser.parse_args()

    mode = args.mode or ("hybrid" if args.use_llm else "rules")
    investigate(
        args.scenario,
        mode=mode,
        rules_from=args.rules_from,
        input_report=args.input,
        output_report=args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
