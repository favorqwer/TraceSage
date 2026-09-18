#!/usr/bin/env python3
"""批量跑「日志清单 -> 图清单 -> 覆盖度缺口报告」。

    python tools/run_coverage.py                      # 全部场景，已有的清单直接复用
    python tools/run_coverage.py --only 2,3           # 只跑指定场景
    python tools/run_coverage.py --force              # 重跑全部（含清单）
    python tools/run_coverage.py --scenario 2 --force # 重跑单个场景

产物：
    output/inventory/<场景>.log-inventory.json     （日志侧全量清单）
    output/inventory/<场景>.db-inventory.json      （图侧清单）
    output/coverage/<场景>.coverage-gap.md|json    （缺口报告）
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PREFIX = "tracesage-"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input-dir", default=str(ROOT / "input" / "sysdig"))
    ap.add_argument("--inventory-dir", default=str(ROOT / "output" / "inventory"))
    ap.add_argument("--coverage-dir", default=str(ROOT / "output" / "coverage"))
    ap.add_argument("--only", default=None, help="逗号分隔的场景序号，如 1,2")
    ap.add_argument("--scenario", default=None, help="只跑单个场景序号")
    ap.add_argument("--force", action="store_true", help="忽略已有清单，全部重跑")
    ap.add_argument("--max-lines", type=int, default=None, help="透传给 log_inventory（试跑）")
    args = ap.parse_args()

    only = set()
    if args.scenario:
        only.add(args.scenario)
    if args.only:
        only.update(x.strip() for x in args.only.split(",") if x.strip())

    files = sorted(Path(args.input_dir).glob("*.jsonl"), key=lambda p: p.name)
    if only:
        files = [f for f in files if f.stem.split("_")[0] in only]
    if not files:
        print("没有匹配的场景", file=sys.stderr)
        return 1

    inv_dir = Path(args.inventory_dir)
    cov_dir = Path(args.coverage_dir)
    py = sys.executable
    failures = []
    for f in files:
        stem = f.stem
        db = DB_PREFIX + stem.lower().replace("_", "-")
        log_inv = inv_dir / f"{stem}.log-inventory.json"
        db_inv = inv_dir / f"{stem}.db-inventory.json"
        print(f"\n######## {stem} -> {db} ########", flush=True)

        if args.force or not log_inv.exists() or args.max_lines is not None:
            cmd = [py, str(ROOT / "tools" / "log_inventory.py"), str(f),
                   "-o", str(log_inv)]
            if args.max_lines is not None:
                cmd += ["--max-lines", str(args.max_lines)]
            r = subprocess.run(cmd)
            if r.returncode:
                failures.append(stem)
                continue
        else:
            print(f"[skip] 复用 {log_inv}", flush=True)

        if args.force or not db_inv.exists():
            r = subprocess.run([py, str(ROOT / "tools" / "db_inventory.py"), db,
                                "-o", str(db_inv)])
            if r.returncode:
                failures.append(stem)
                continue
        else:
            print(f"[skip] 复用 {db_inv}", flush=True)

        r = subprocess.run([py, str(ROOT / "tools" / "coverage_gap.py"),
                            "--log", str(log_inv), "--db-inventory", str(db_inv),
                            "--out-dir", str(cov_dir)])
        if r.returncode:
            failures.append(stem)

    if failures:
        print(f"\n失败场景：{failures}", file=sys.stderr)
        return 1
    print("\n全部完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
