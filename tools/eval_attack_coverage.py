#!/usr/bin/env python
"""ATT&CK 行为观测的粗粒度覆盖报告（G2 用）。

口径限制（必须随结果一起报告）：
- 只看 GT 边的 syscall/action 是否命中某个 BehaviorObservable 的 syscall_pattern；
- 角色只按顶点种类（P/F/N）做前缀匹配，不计算完整角色串；
- 因此这是覆盖率上界，不是已验证的检索命中，也不等于 LLM 判定增益。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))

from rag.attack import load_behavior_observables  # noqa: E402


def label_of(endpoint: Any) -> str:
    s = str(endpoint or "")
    if s.startswith("p:"):
        return "P"
    if s.startswith("f:"):
        return "F"
    if s.startswith("n:"):
        return "N"
    return "?"


def role_matches(patterns: List[str], label: str) -> bool:
    if not patterns:
        return True
    return any(str(p).split(".", 1)[0] == label for p in patterns)


def edge_syscall(edge: Dict[str, Any]) -> str:
    return str(edge.get("syscall") or edge.get("action") or "").lower()


def matching_techniques(edge: Dict[str, Any], observables) -> List[str]:
    sc = edge_syscall(edge)
    src_label = label_of(edge.get("src"))
    dst_label = label_of(edge.get("dst"))
    out = []
    for obs in observables:
        if not obs.observable:
            continue
        if sc not in {str(x).lower() for x in obs.syscall_pattern}:
            continue
        if not role_matches(obs.role_pattern, src_label) and not role_matches(obs.role_pattern, dst_label):
            continue
        out.append(obs.technique_id)
    return sorted(set(out))


def gt_edges(gt: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for phase in gt.get("attack_path") or []:
        out.extend(phase.get("edges") or [])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--observables", default=str(ROOT / "provenance-navigator/config/attack-observables.seed.json"))
    ap.add_argument("--out", default=str(ROOT / "output/rule-kg/v1/attack_coverage.json"))
    ap.add_argument("--include-extra", action="store_true",
                    help="同时统计没有折库的额外 GT（如 TC_E3）；默认只统计 10 个攻击场景")
    args = ap.parse_args()

    observables = load_behavior_observables(args.observables)
    gt_dir = Path(args.gt_dir)
    fold_dir = Path(args.fold_dir)
    rows = []
    for gt_path in sorted(gt_dir.glob("*.groundtruth.json")):
        scenario = gt_path.name.replace(".groundtruth.json", "")
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        edges = gt_edges(gt)
        covered = [e for e in edges if matching_techniques(e, observables)]
        techs = sorted({t for e in covered for t in matching_techniques(e, observables)})
        fold_path = fold_dir / f"{scenario}.json"
        if not fold_path.is_file() and not args.include_extra:
            continue
        symbolic = None
        if fold_path.is_file():
            fold = json.loads(fold_path.read_text(encoding="utf-8"))
            cov = fold.get("gt_edge_coverage") or {}
            symbolic = {"covered": cov.get("covered"), "total": cov.get("total")}
        rows.append({
            "scenario": scenario,
            "gt_edges": len(edges),
            "observable_covered": len(covered),
            "observable_rate": (len(covered) / len(edges)) if edges else 0.0,
            "techniques_hit": techs,
            "symbolic_coverage": symbolic,
        })

    total_edges = sum(r["gt_edges"] for r in rows)
    total_obs = sum(r["observable_covered"] for r in rows)
    symbolic_total = sum((r["symbolic_coverage"] or {}).get("total") or 0 for r in rows)
    symbolic_covered = sum((r["symbolic_coverage"] or {}).get("covered") or 0 for r in rows)
    out = {
        "protocol": "粗粒度上界：syscall/action 精确 + 顶点种类前缀；未做完整角色串匹配，不是已验证检索命中",
        "denominators": {
            "gt_edges_all": total_edges,
            "gt_edges_candidate_pool": symbolic_total,
            "note": "observable_rate 的分母是全部 GT 边；symbolic_coverage 的分母是候选池内 GT 边。二者不可直接相减或并排比较；需要统一分母时先重算。",
        },
        "totals": {
            "scenarios": len(rows),
            "gt_edges": total_edges,
            "observable_covered": total_obs,
            "observable_rate": (total_obs / total_edges) if total_edges else 0.0,
            "symbolic_covered": symbolic_covered,
            "symbolic_total": symbolic_total,
            "symbolic_rate": (symbolic_covered / symbolic_total) if symbolic_total else 0.0,
        },
        "scenarios": rows,
    }
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("| 场景 | GT 边 | 行为观测覆盖 | 覆盖率 | 符号覆盖 |")
    print("|---|---:|---:|---:|---:|")
    for r in rows:
        sym = r["symbolic_coverage"] or {}
        print(f"| {r['scenario']} | {r['gt_edges']} | {r['observable_covered']} | "
              f"{r['observable_rate']:.1%} | {sym.get('covered')}/{sym.get('total')} |")
    print(f"\n微平均：{total_obs}/{total_edges} = {out['totals']['observable_rate']:.1%}")
    print(f"written {dest}")


if __name__ == "__main__":
    main()
