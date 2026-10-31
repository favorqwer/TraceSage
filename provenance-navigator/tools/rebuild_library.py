"""重算规则库名单。

默认（快，约 0.1 秒）：只读现有覆盖表，重跑贪心，生成新版本。
  用途：改了贪心准则、想看效果、做对比实验。

--from-scratch（慢，约 7 分钟）：抽全部场景闭包，重建覆盖表，再选名单。
  用途：首次建库、标准答案变更后重建。

用法：
  python provenance-navigator/tools/rebuild_library.py
  python provenance-navigator/tools/rebuild_library.py --from-scratch
  python provenance-navigator/tools/rebuild_library.py --library <指定版本> --out <输出路径>
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

NAV = Path(__file__).resolve().parents[1]
REPO = NAV.parent
for p in (str(NAV), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

from closure import list_scenarios
from pipeline import load_rule_matcher, make_pool_provider
from rules.offline import OfflineDistiller, latest_path, save_library


def _print_stats(rep: dict, elapsed: float, title: str) -> None:
    st = rep["stats"]
    print()
    print("=" * 74)
    print(title)
    print(f"  候选形态      : {st['candidate_rules']} 条")
    print(f"  准入形态      : {st['selected_rules']} 条")
    print(f"  全局边键      : {st['global_key_count']}")
    print(f"  攻击边        : {st['pos_key_count']}")
    print(f"  随机基准查准率: {st['baseline_precision']:.6f}")
    print(f"  攻击边覆盖率  : {st['coverage_rate'] * 100:.1f}%")
    print(f"  累计报告边    : {st['cum_report_edges']}")
    print(f"  贪心步数      : {len(rep['greedy_trace'])}")
    print(f"  耗时          : {elapsed:.2f} 秒")
    print("=" * 74)


def main() -> None:
    ap = argparse.ArgumentParser(description="重算规则库名单（默认只读覆盖表）")
    ap.add_argument("--from-scratch", action="store_true",
                    help="抽全部场景闭包重建覆盖表（慢，约 7 分钟，需要数据库）")
    ap.add_argument("--from-coverage", action="store_true",
                    help="从既有覆盖表重建（改角色表/改准则后用，不查数据库，约 4 分钟）")
    ap.add_argument("--library", default=None, help="基线规则库路径（默认读 latest.txt）")
    ap.add_argument("--out", default=None, help="输出路径（默认生成新版本条目）")
    ap.add_argument("--no-latest", action="store_true", help="不更新 latest.txt 指针")
    ap.add_argument("--dry-run", action="store_true", help="只计算不落盘")
    ap.add_argument("--scenario", action="append", default=None, help="--from-scratch 时限定场景")
    args = ap.parse_args()

    d = OfflineDistiller(rule_matcher=load_rule_matcher())
    t0 = time.time()

    if args.from_coverage:
        base = args.library or str(latest_path())
        print(f"[从覆盖表重建] {base}（不查图）")
        d.rebuild_from_coverage(base)
        title = "[从覆盖表重建] 完成"
    elif args.from_scratch:
        scenarios = args.scenario or list(list_scenarios())
        print(f"[全量重建] 抽 {len(scenarios)} 个场景闭包并重建覆盖表")
        d.build_all(scenarios, pool_provider=make_pool_provider())
        title = "[全量重建] 完成"
    else:
        base = args.library or str(latest_path())
        print(f"[重算名单] 读覆盖表：{base}")
        d.reselect(base)
        title = "[重算名单] 完成"

    elapsed = time.time() - t0
    rep = d.last_report
    _print_stats(rep, elapsed, title)

    trace = rep["greedy_trace"]
    print(f"{'步':>3s} {'形态':16s} {'新增攻':>6s} {'新增报':>7s} {'边际查准率':>10s} {'累计覆盖':>9s}")
    for t in trace[:15]:
        print(f"{t['step']:3d} {t['rule']:16s} {t['gain']:6d} {t['report']:7d} "
              f"{t['efficiency'] * 100:9.3f}% {t['cum_gain']:9d}")
    if len(trace) > 15:
        print(f"  … 其余 {len(trace) - 15} 步省略")

    if args.dry_run:
        print("\n--dry-run：未落盘")
        return

    out = save_library(rep, out_path=args.out, make_latest=not args.no_latest)
    print(f"\n新版本已写入：{out}")
    cov = out.with_name(out.stem + ".coverage.json.gz")
    print(f"  主文件   : {out.stat().st_size / 1024:.0f} KB")
    if cov.is_file():
        print(f"  覆盖表   : {cov.stat().st_size / 1024 / 1024:.1f} MB")
    payload = json.loads(out.read_text(encoding="utf-8"))
    print(f"  schema={payload['schema']}  motifs={len(payload['motifs'])}  "
          f"selected={len(payload['selected'])}  digest={payload['fingerprint']['digest'][:16]}…")
    if not args.no_latest:
        print(f"  latest.txt → {out.name}")


if __name__ == "__main__":
    main()
