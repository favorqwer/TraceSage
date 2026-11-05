#!/usr/bin/env python
"""从留一折库构建 Rule KG v1 快照（不写 Neo4j）。

用法：
    .venv/Scripts/python.exe tools/build_rule_kg.py \
        --fold-dir output/navigator-baseline/distill/fold-libraries \
        --out output/rule-kg/v1 \
        --version kg-v1

输出：
    output/rule-kg/v1/folds/<场景>.json
    output/rule-kg/v1/manifest.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))

from rag.build_kg import build_all_folds  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--out", default=str(ROOT / "output/rule-kg/v1"))
    ap.add_argument("--version", default="kg-v1")
    ap.add_argument("--include-candidates", action="store_true",
                    help="把未入选形态以 admitted=false 一并存档（检索仍只用 selected）")
    ap.add_argument("--observables", default=str(ROOT / "provenance/config/attack-observables.seed.json"),
                    help="BehaviorObservable 映射表；传空字符串可跳过技术链接")
    args = ap.parse_args()

    manifest = build_all_folds(
        args.fold_dir, args.out, version=args.version,
        include_candidates=args.include_candidates,
        observables_path=args.observables or None)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
