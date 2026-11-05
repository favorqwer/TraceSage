"""接入一个新场景：只查它一次图，历史场景零图查询，追加后立即重算名单。

做七步：
  1 读新场景标准答案 → 攻击边键集合
  2 抽新场景闭包                                        （唯一一次图查询）
  3 剥静态只读背景，打 pos/ignore/neg 三值标签
  4 用全部场景标准答案重新枚举形态，按指纹去重
  5 新出现的形态在全部历史场景重放匹配，补齐位图        （只读覆盖表）
  6 新场景的边、标签、全部形态命中追加进覆盖表
  7 立刻重算名单（约 0.1 秒）→ 生成新版本

用法：
  python provenance/tools/ingest_scenario.py --scenario 11_XXX_Attack
  python provenance/tools/ingest_scenario.py --scenario X --base <基线库> --no-latest
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

NAV = Path(__file__).resolve().parents[1]
REPO = NAV.parent
for p in (str(NAV), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

from pipeline import load_rule_matcher, make_pool_provider
from rules.offline import OfflineDistiller, latest_path, save_library


def main() -> None:
    ap = argparse.ArgumentParser(description="接入一个新场景并重算名单")
    ap.add_argument("--scenario", required=True, help="新场景全名（与 groundtruth/<名>.groundtruth.json 一致）")
    ap.add_argument("--base", default=None, help="基线规则库（默认读 latest.txt）")
    ap.add_argument("--out", default=None, help="输出路径（默认生成新版本条目）")
    ap.add_argument("--no-latest", action="store_true", help="不更新 latest.txt 指针")
    args = ap.parse_args()

    base = args.base or str(latest_path())
    print(f"基线规则库：{base}")
    print(f"新场景    ：{args.scenario}")
    print()
    print("[1-6/7] 抽闭包 → 打标签 → 挖形态 → 新形态全场景重放 → 追加覆盖表 …")

    t0 = time.time()
    d = OfflineDistiller(rule_matcher=load_rule_matcher())
    d.ingest(base, args.scenario, pool_provider=make_pool_provider())
    rep = d.last_report
    ingest_elapsed = time.time() - t0

    replay = rep.get("replay_counts") or {}
    print(f"  完成，耗时 {ingest_elapsed:.1f} 秒")
    print(f"  新形态在历史场景补齐：{len(replay)} 条形态，合计 {sum(replay.values())} 个边位")

    st = rep["stats"]
    print()
    print("=" * 74)
    print("[7/7] 重算名单（已包含在上面耗时里）")
    print(f"  场景数        : {len(rep['train_scenarios'])}")
    print(f"  候选形态      : {st['candidate_rules']} 条")
    print(f"  准入形态      : {st['selected_rules']} 条")
    print(f"  全局边键      : {st['global_key_count']}")
    print(f"  攻击边        : {st['pos_key_count']}")
    print(f"  攻击边覆盖率  : {st['coverage_rate'] * 100:.1f}%")
    print(f"  累计报告边    : {st['cum_report_edges']}")
    print("=" * 74)

    out = save_library(rep, out_path=args.out, make_latest=not args.no_latest)
    print(f"\n新版本：{out}")
    cov = out.with_name(out.stem + ".coverage.json.gz")
    print(f"  主文件 : {out.stat().st_size / 1024:.0f} KB")
    if cov.is_file():
        print(f"  覆盖表 : {cov.stat().st_size / 1024 / 1024:.1f} MB")
    if not args.no_latest:
        print(f"  latest.txt → {out.name}")


if __name__ == "__main__":
    main()
