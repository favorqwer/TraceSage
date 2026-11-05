#!/usr/bin/env python
"""两证据链只读审计：规则路径和技术路径分开统计。

不调用模型，不写规则库。对每个 GT 攻击边：
- 规则路径：精确对齐、部分对齐，以及离线技术链接的正确性代理；
- 技术路径：T-强、T-弱，以及正确技术命中。

用法：
    .venv/Scripts/python.exe tools/audit_two_channel.py --scenarios 1_Web_Exploit_Ransomware 4_Repo_Poisoning_Backdoor 5_Exposed_Service_Pivot
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(ROOT / "tools"))

import settings as cfg  # noqa: E402
from rag.graph_retrieve import RuleGraphRetriever  # noqa: E402
from rag.neo4j_kg import DEFAULT_DATABASE  # noqa: E402
import eval_graph_retrieval as egr  # noqa: E402
from audit_rag_entries import build_scenario_context  # noqa: E402


def load_motif_techniques(scenario: str) -> Dict[str, List[str]]:
    path = ROOT / "output/rule-kg/v1/folds" / f"{scenario}.json"
    kg = json.loads(path.read_text(encoding="utf-8"))
    out: Dict[str, List[str]] = {}
    for link in kg.get("technique_links") or []:
        mid = str(link.get("motif_id") or "")
        tid = str(link.get("technique_id") or "")
        if mid and tid:
            out.setdefault(mid, []).append(tid)
    return out


def audit_scenario(scenario: str, retriever: RuleGraphRetriever,
                   matcher: Any, matched_all: Dict[Any, Any],
                   technique_map: Dict[str, Any], limit: int) -> Dict[str, Any]:
    gt = json.loads((ROOT / "groundtruth" / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    motif_techs = load_motif_techniques(scenario)
    rows: List[Dict[str, Any]] = []
    for edge in egr.gt_edge_rows(gt):
        key = (edge["src"], edge["syscall"], edge["dst"])
        expected = {str(m.get("id")) for m in (matched_all.get(key) or [])}
        src_role = matcher.role_of(edge["src"])
        dst_role = matcher.role_of(edge["dst"])
        correct = {str(t) for t in
                   (technique_map.get(edge["phase_id"], {}).get("techniques") or [])}

        rules = retriever.retrieve_rules(src_role, edge["syscall"], dst_role, limit=limit)
        exact_ids = [str(g["motif"]["motif_id"]) for g in rules["exact"]]
        partial_ids = [str(g["motif"]["motif_id"]) for g in rules["partial"]]

        def rule_hit(ids: List[str]) -> bool:
            return bool(correct) and any(
                egr.tech_match(set(motif_techs.get(mid) or []), correct) for mid in ids)

        programs = [edge["src"]] if edge["src_label"] == "P" else []
        techs = retriever.retrieve_techniques(
            edge["syscall"], src_role, dst_role,
            edge["src_label"], edge["dst_label"],
            programs=programs, paths=[edge["src"], edge["dst"]])
        strong_ids = {str(t["attack_id"]) for t in techs["strong"]}
        weak_ids = {str(t["attack_id"]) for t in techs["weak"]}

        rows.append({
            "edge": f"{edge['src']} --{edge['syscall']}--> {edge['dst']}",
            "online_symbolic": bool(expected),
            "rule_exact": bool(exact_ids),
            "rule_exact_correct": rule_hit(exact_ids),
            "rule_partial": bool(partial_ids),
            "rule_partial_correct": rule_hit(partial_ids),
            "rule_any": bool(exact_ids or partial_ids),
            "tech_strong": bool(strong_ids),
            "tech_strong_correct": bool(correct) and egr.tech_match(strong_ids, correct),
            "tech_weak": bool(weak_ids),
            "tech_weak_correct": bool(correct) and egr.tech_match(weak_ids, correct),
            "tech_any": bool(strong_ids or weak_ids),
            "both_rule_and_tech": bool(exact_ids or partial_ids) and bool(strong_ids),
            "correct_techniques": sorted(correct),
        })
    return {"scenario": scenario, "rows": rows}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="*", default=[
        "1_Web_Exploit_Ransomware",
        "4_Repo_Poisoning_Backdoor",
        "5_Exposed_Service_Pivot",
    ])
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--technique-map", default=str(ROOT / "groundtruth/attack-technique-map.json"))
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--out", default=str(ROOT / "tmp/rag-audit/two_channel_3scenarios.json"))
    args = ap.parse_args()

    cfg.load_dotenv()
    fold_dir = Path(args.fold_dir)
    tech_map_all = json.loads(Path(args.technique_map).read_text(encoding="utf-8"))["scenarios"]
    results: Dict[str, Any] = {}
    for scenario in args.scenarios:
        t0 = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {scenario} ...", flush=True)
        try:
            matcher, matched_all, _audit = build_scenario_context(scenario, fold_dir)
            retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), args.database, scenario)
            try:
                results[scenario] = audit_scenario(
                    scenario, retriever, matcher, matched_all,
                    tech_map_all.get(scenario, {}), args.limit)
            finally:
                retriever.close()
        except Exception as exc:  # 单场景失败如实记录
            results[scenario] = {"scenario": scenario, "error": f"{type(exc).__name__}: {exc}"}
            print(f"[{time.strftime('%H:%M:%S')}] {scenario} 失败：{exc}", flush=True)
        print(f"[{time.strftime('%H:%M:%S')}] {scenario} 完成 {time.time() - t0:.1f}s", flush=True)

    all_rows = [r for rec in results.values() for r in (rec.get("rows") or [])]
    n = max(1, len(all_rows))

    def rate(key: str) -> float:
        return sum(1 for r in all_rows if r.get(key)) / n

    summary = {
        "scenarios": args.scenarios,
        "gt_edges": len(all_rows),
        "online_symbolic": sum(1 for r in all_rows if r.get("online_symbolic")),
        "rule_exact": sum(1 for r in all_rows if r.get("rule_exact")),
        "rule_exact_correct": sum(1 for r in all_rows if r.get("rule_exact_correct")),
        "rule_partial": sum(1 for r in all_rows if r.get("rule_partial")),
        "rule_partial_correct": sum(1 for r in all_rows if r.get("rule_partial_correct")),
        "rule_any": sum(1 for r in all_rows if r.get("rule_any")),
        "tech_strong": sum(1 for r in all_rows if r.get("tech_strong")),
        "tech_strong_correct": sum(1 for r in all_rows if r.get("tech_strong_correct")),
        "tech_weak": sum(1 for r in all_rows if r.get("tech_weak")),
        "tech_weak_correct": sum(1 for r in all_rows if r.get("tech_weak_correct")),
        "tech_any": sum(1 for r in all_rows if r.get("tech_any")),
        "both_rule_and_tech": sum(1 for r in all_rows if r.get("both_rule_and_tech")),
    }
    for key in list(summary):
        if key in ("scenarios", "gt_edges"):
            continue
        summary[key + "_rate"] = round(rate(key), 4)
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"summary": summary, "results": results},
                               ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print(f"written {dest}", flush=True)


if __name__ == "__main__":
    main()
