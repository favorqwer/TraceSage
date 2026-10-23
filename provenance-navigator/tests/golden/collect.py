"""阶段 0：采集行为基线（不改生产代码）。

对每个场景用当次代码跑 rules + frozen，把报告里的已确认/未排除/已排除边集合与
stats（去掉时间字段）写成一份可按场景比较的 JSON。

用法：
    python tests/golden/collect.py --output-dir tmp/refactor-golden/run1
    python tests/golden/collect.py --output-dir tmp/refactor-golden/run1 --only 1_Web_Exploit_Ransomware
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

NAV_DIR = Path(__file__).resolve().parents[2]
if str(NAV_DIR) not in sys.path:
    sys.path.insert(0, str(NAV_DIR))

from closure import list_scenarios  # noqa: E402
from main import run_scenario  # noqa: E402

_TIME_STATS = ("elapsed_seconds", "timestamp", "closure_time_seconds")


def _edge_row(edge: dict) -> list:
    """报告里的边按（源、系统调用、目标、成败集合）归一，顺序无关。"""
    return [
        str(edge.get("src") or ""),
        str(edge.get("syscall") or ""),
        str(edge.get("dst") or ""),
        sorted(str(x) for x in (edge.get("effects") or [])),
    ]


def _collect_report(report_path: Path) -> dict:
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    stats = {k: v for k, v in (data.get("stats") or {}).items() if k not in _TIME_STATS}
    out = {
        "scenario": data.get("scenario"),
        "edges": sorted(_edge_row(e) for e in (data.get("edges") or [])),
        "unexcluded": sorted(_edge_row(e) for e in (data.get("unexcluded") or [])),
        "excluded": sorted(_edge_row(e) for e in (data.get("excluded") or [])),
        "stats": stats,
    }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="采集导航器行为基线")
    parser.add_argument("--output-dir", required=True, help="基线输出目录（例如 tmp/refactor-golden/run1）")
    parser.add_argument("--only", default="", help="只跑指定场景，逗号分隔；默认全部")
    parser.add_argument("--mode", default="rules", choices=["rules", "hybrid", "llm-only"])
    parser.add_argument("--rules-from", default="frozen", choices=["frozen", "fresh"])
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = NAV_DIR.parent / out_dir
    golden_dir = out_dir / "golden"
    report_dir = out_dir / "reports"
    golden_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    all_scenarios = list_scenarios()
    wanted = [s.strip() for s in args.only.split(",") if s.strip()]
    if wanted:
        unknown = [s for s in wanted if s not in all_scenarios]
        if unknown:
            print(f"[阻断] 未知场景：{unknown}；可选：{all_scenarios}")
            return 2
        scenarios = wanted
    else:
        scenarios = all_scenarios

    print(f"[collect] 输出 {out_dir}；场景 {len(scenarios)} 个；mode={args.mode} rules_from={args.rules_from}")
    started_all = time.time()
    for idx, scenario in enumerate(scenarios, 1):
        t0 = time.time()
        report_path = report_dir / f"{scenario}.json"
        try:
            run_scenario(
                scenario,
                output_report=str(report_path),
                mode=args.mode,
                rules_from=args.rules_from,
            )
        except Exception as exc:  # 阻断诚实：任何场景失败立即停止
            print(f"[阻断] {scenario} 运行失败：{type(exc).__name__}: {exc}")
            return 1

        try:
            row = _collect_report(report_path)
        except Exception as exc:
            print(f"[阻断] {scenario} 报告读取失败：{type(exc).__name__}: {exc}")
            return 1

        golden_path = golden_dir / f"{scenario}.json"
        with open(golden_path, "w", encoding="utf-8") as f:
            json.dump(row, f, ensure_ascii=False, indent=1)

        elapsed = time.time() - t0
        size_mb = report_path.stat().st_size / (1024 * 1024)
        print(
            f"[{idx}/{len(scenarios)}] {scenario}: "
            f"确认 {len(row['edges'])} / 未排除 {len(row['unexcluded'])} / 已排除 {len(row['excluded'])}；"
            f"耗时 {elapsed:.1f}s；报告 {size_mb:.1f}MB；基线 {golden_path}"
        )
        # 单场景处理完就释放，避免 10 个场景同时留在内存里
        del row
        gc.collect()

    print(f"[collect] 完成：{len(scenarios)} 个场景，总耗时 {time.time() - started_all:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
