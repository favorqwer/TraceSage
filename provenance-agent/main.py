"""provenance-agent 入口（只做命令行与文件落盘）。

用法：
    # 单场景
    python main.py --scenario 6_SQLite_Pipeline_Pollution
    # 六场景批量
    python main.py --all
    # 只跑确定性层（不调 LLM）：验证 POI / 步骤 / 展开 / 上游候选
    python main.py --scenario 1_Multi_Stage_Data_Exfiltration --dry-run

架构：五层（结构可达 / 压缩与准备 / 语义判别 / 全局校验 / 表达），编排在 `pagent/orchestration/`，
装配与流程顺序在 `pagent/app.py`。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from pagent import app
from pagent.core import scenarios, settings
from pagent.core.llm import make_model, set_raw_log
from pagent.core.trace import write_trace

OUTPUT_DIR = settings.REPO_ROOT / "output" / "agent"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="基于溯源图的攻击溯源 agent（五层：展开 → 装批 → 判定 → 复核 → 报告）")
    parser.add_argument("--scenario", help="场景名（见 provenance-agent/config/scenarios.json）")
    parser.add_argument("--all", action="store_true", help="跑全部场景")
    parser.add_argument("--run-id", default="", help="运行 id（默认按时间生成；不复用）")
    parser.add_argument("--min-confidence", type=float, default=0.5, help="判定为相关的最低置信度")
    parser.add_argument("--model", default=None, help="覆盖 OPENAI_MODEL")
    parser.add_argument("--dry-run", action="store_true", help="只跑确定性层（POI/展开/上游），不调 LLM")
    parser.add_argument("--out-dir", default=str(OUTPUT_DIR),
                        help="报告输出目录（仅真实运行；--dry-run 一律写 tmp/provenance-agent/dry-run/）")
    return parser.parse_args(argv)


def run_one(scenario_name: str, args: argparse.Namespace) -> dict:
    scenario = scenarios.load_scenario(scenario_name)
    run_id = args.run_id or f"{scenario_name}-{time.strftime('%Y%m%d-%H%M%S')}"
    if args.model:
        os.environ["OPENAI_MODEL"] = args.model

    deps = app.build_deps(scenario, run_id, model=None if args.dry_run else make_model(),
                          min_confidence=args.min_confidence)
    if not args.dry_run:
        set_raw_log(settings.LOG_DIR / f"llm-{run_id}.jsonl")   # 原始输出度量（每次调用的长度 + 样本）

    try:
        result = app.run_once(deps, dry_run=args.dry_run)
        report = result["report"]
        stats = result["stats"]

        out_dir = (settings.WORK_DIR / "dry-run") if args.dry_run else Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{scenario.name}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        write_trace(settings.LOG_DIR / f"trace-{run_id}.jsonl", deps.trace)
        deps.record.dump(settings.STATE_DIR / f"record-{run_id}.json")
        print(f"[{scenario.name}] 完成：确认 {len(report.get('edges') or [])} 条边；"
              f"停止原因 {result['stop_reason']}；墙钟 {stats['wall_seconds']}s；"
              f"模型调用 {(deps.budget.to_dict() or {}).get('calls')}；输出 {out_dir / (scenario.name + '.json')}")
        return report
    finally:
        deps.graph.close()
        set_raw_log(None)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings.load_dotenv()
    if args.all:
        names = scenarios.available_scenarios()
    elif args.scenario:
        names = [args.scenario]
    else:
        print("必须指定 --scenario 或 --all", file=sys.stderr)
        return 2
    reports = []
    for name in names:
        reports.append(run_one(name, args))
    if len(reports) > 1:
        summary = {
            "runs": [
                {"scenario": r.get("scenario"), "edges": len(r.get("edges") or []),
                 "stop_reason": r.get("stop_reason"), "stats": r.get("stats")} for r in reports
            ]
        }
        path = Path(args.out_dir) / "SUMMARY.json"
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"汇总：{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
