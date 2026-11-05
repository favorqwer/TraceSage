"""阶段 0：比较两份行为基线（逐场景逐边）。

用法：
    python tests/golden/compare.py --left tmp/refactor-golden/run1 --right tmp/refactor-golden/run2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

NAV_DIR = Path(__file__).resolve().parents[2]


def _load(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _freeze(value):
    """把带列表的行转成可哈希结构（只用于集合比较与差异展示）。"""
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in value.items()))
    return value


def _diff_list(left: list, right: list, limit: int = 10):
    # 只比较边的三元组（源、系统调用、目标）；报告字段 effects 的有无不属于判定行为
    lset = {tuple(_freeze(v) for v in row[:3]) for row in left}
    rset = {tuple(_freeze(v) for v in row[:3]) for row in right}
    only_l = sorted(lset - rset)
    only_r = sorted(rset - lset)
    return only_l[:limit], only_r[:limit], len(only_l), len(only_r)


def main() -> int:
    parser = argparse.ArgumentParser(description="比较两份导航器行为基线")
    parser.add_argument("--left", required=True)
    parser.add_argument("--right", required=True)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    left_dir, right_dir = Path(args.left), Path(args.right)
    if not left_dir.is_absolute():
        left_dir = NAV_DIR.parent / left_dir
    if not right_dir.is_absolute():
        right_dir = NAV_DIR.parent / right_dir

    left_files = {p.name for p in (left_dir / "golden").glob("*.json")}
    right_files = {p.name for p in (right_dir / "golden").glob("*.json")}
    if left_files != right_files:
        print(f"[不一致] 基线文件集合不同：仅左 {sorted(left_files - right_files)}；"
              f"仅右 {sorted(right_files - left_files)}")
        return 1

    failed = 0
    for name in sorted(left_files):
        left = _load(left_dir / "golden" / name)
        right = _load(right_dir / "golden" / name)
        scenario = left.get("scenario") or name
        problems = []

        for section in ("edges", "unexcluded", "excluded"):
            only_l, only_r, n_l, n_r = _diff_list(left.get(section, []), right.get(section, []),
                                                  limit=args.limit)
            if n_l or n_r:
                problems.append(f"{section}: 仅左 {n_l} 条 / 仅右 {n_r} 条")
                for row in only_l:
                    problems.append(f"    仅左: {row}")
                for row in only_r:
                    problems.append(f"    仅右: {row}")

        if left.get("stats") != right.get("stats"):
            problems.append("stats 不同")
            keys = sorted(set(left.get("stats", {})) | set(right.get("stats", {})))
            for key in keys:
                lv, rv = left.get("stats", {}).get(key), right.get("stats", {}).get(key)
                if lv != rv:
                    problems.append(f"    {key}: 左={lv!r} 右={rv!r}")

        if problems:
            failed += 1
            print(f"[不一致] {scenario}")
            for line in problems:
                print(f"  {line}")
        else:
            print(f"[一致] {scenario}: 确认 {len(left['edges'])} / 未排除 {len(left['unexcluded'])} / "
                  f"已排除 {len(left['excluded'])}")

    if failed:
        print(f"[结论] {failed}/{len(left_files)} 个场景不一致")
        return 1
    print(f"[结论] {len(left_files)} 个场景完全一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
