#!/usr/bin/env python
"""把 Rule KG 快照写入 Neo4j 独立数据库 `trace-rules-kg-v1`。

用法：
    .venv/Scripts/python.exe tools/build_rule_kg_neo4j.py --folds 7_DB_Bruteforce_Datawipe
    .venv/Scripts/python.exe tools/build_rule_kg_neo4j.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance"))

import settings as cfg  # noqa: E402
from rag.neo4j_kg import DEFAULT_DATABASE, RuleKGStore  # noqa: E402


def load_cases(scenario: str) -> Dict[str, Dict[str, Any]]:
    gt_path = ROOT / "groundtruth" / f"{scenario}.groundtruth.json"
    if not gt_path.is_file():
        return {scenario: {"description": "", "attack_phases": []}}
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    phases = [str(p.get("phase") or "") for p in (gt.get("attack_path") or [])]
    return {scenario: {"description": scenario, "attack_phases": phases}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kg-dir", default=str(ROOT / "output/rule-kg/v1"))
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--folds", nargs="*", default=None)
    args = ap.parse_args()

    cfg.load_dotenv()
    kg_dir = Path(args.kg_dir)
    fold_files = sorted((kg_dir / "folds").glob("*.json"))
    if args.folds:
        wanted = set(args.folds)
        fold_files = [p for p in fold_files if p.stem in wanted]

    store = RuleKGStore(cfg.neo4j_uri(), cfg.neo4j_auth(), database=args.database)
    try:
        store.ensure_database()
        store.create_constraints()
        for path in fold_files:
            kg = json.loads(path.read_text(encoding="utf-8"))
            fold = str(kg["fold_of"])
            cases: Dict[str, Dict[str, Any]] = {}
            for sc in kg.get("train_scenarios") or []:
                cases.update(load_cases(str(sc)))
            print(f"[{fold}] 导入 cases/fold ...", flush=True)
            store.import_cases(fold, cases)
            store.import_fold(kg)
            print(f"[{fold}] counts {store.counts(fold=fold)}", flush=True)
        print("ALL", json.dumps(store.counts(), ensure_ascii=False))
    finally:
        store.close()


if __name__ == "__main__":
    main()
