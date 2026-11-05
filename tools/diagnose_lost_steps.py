#!/usr/bin/env python
"""只读诊断：把改前命中、改后未命中的 GT 步骤逐条归类。

分类优先级：
1. 守卫降级：改后束的原始判定行带 `_rag_guard`；
2. 证据未覆盖：改后束的规则证据和技术证据都为空；
3. 模型自己改判：有证据，但模型判 mixed/none/unknown；
4. 其他：判 all 但未命中，或束被闸门/调用上限处理。

不调用模型，不写规则库。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(ROOT / "tools"))

import score_report_product as srp  # noqa: E402
import score_graph_product as eg  # noqa: E402
import rules_match as rm  # noqa: E402


def hit_triples(report_path: Path, gt_path: Path) -> Tuple[set, set]:
    scenario, quads, _skipped = srp.load_agent_report(str(report_path))
    gt, gt_triples = eg.load_gt(str(gt_path))
    rules = rm.load_rules(gt)
    kinds = rm.VertexKinds.for_gt(gt)
    rows = []
    for (src, syscall, dst, effect), edge in quads.items():
        attrs = {"bytes": edge["bytes"]} if edge.get("bytes") is not None else None
        rows.append((src, syscall, dst, effect, attrs))
    met = rm.evaluate_report(gt_triples, rules, rows, kinds=kinds)
    hits = {(t[0], t[1], t[2]) for t in met["must_hits"]}
    rule_hits = set()
    for r in met["rule_hits"]:
        rid = r.get("rule_id") if isinstance(r, dict) else str(r)
        if rid:
            rule_hits.add(str(rid))
    return hits, rule_hits


def parse_trace(path: Path) -> Dict[str, Dict[str, Any]]:
    bundles: Dict[str, Dict[str, Any]] = {}
    if not path.is_file():
        return bundles
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "listing" in rec and "items" in rec:
                verdict_rows = (rec.get("result") or {}).get("verdicts") or {}
                for item in rec.get("items") or []:
                    bid = str(item.get("id") or "")
                    if not bid:
                        continue
                    b = bundles.setdefault(bid, {})
                    b["members"] = [tuple(x) for x in (item.get("members") or [])]
                    b["rule_ids"] = list(item.get("rag_rule_ids") or item.get("_rule_ids") or [])
                    b["tech_ids"] = list(item.get("rag_tech_ids") or item.get("_tech_ids") or [])
                    b["level"] = item.get("level")
                    row = verdict_rows.get(bid) or {}
                    if row:
                        b["raw_verdict"] = str(row.get("verdict") or "")
                        b["raw_guard"] = str(row.get("_rag_guard") or "")
            elif rec.get("kind") == "detail":
                for d in rec.get("detail") or []:
                    bid = str(d.get("id") or "")
                    if not bid:
                        continue
                    b = bundles.setdefault(bid, {})
                    b["final_verdict"] = str(d.get("verdict") or "")
                    b["pass"] = int(d.get("pass") or 0)
                    b["detail_level"] = int(d.get("level") or 0)
                    b["reason"] = str(d.get("reason") or "")
    return bundles


def find_bundles(bundles: Dict[str, Dict[str, Any]], triple: Tuple[str, str, str]) -> List[str]:
    src, syscall, dst = triple
    exact = [bid for bid, b in bundles.items()
             if (src, syscall, dst) in (b.get("members") or [])]
    if exact:
        return exact
    by_dst = [bid for bid, b in bundles.items()
              if any(m[1] == syscall and m[2] == dst for m in (b.get("members") or []))]
    if by_dst:
        return by_dst
    return [bid for bid, b in bundles.items()
            if any(m[1] == syscall and m[0] == src for m in (b.get("members") or []))]


def deepest(bundles: Dict[str, Dict[str, Any]], ids: List[str]) -> str:
    if not ids:
        return ""
    return max(ids, key=lambda bid: (
        int(bundles[bid].get("pass") or 0),
        int(bundles[bid].get("detail_level") or bundles[bid].get("level") or 0),
        bid))


def classify(b: Dict[str, Any]) -> str:
    if not b:
        return "未进入任何束"
    if b.get("raw_guard"):
        return "引用守卫降级"
    if not b.get("rule_ids") and not b.get("tech_ids"):
        return "证据未覆盖"
    raw = str(b.get("raw_verdict") or "")
    reason = str(b.get("reason") or "")
    has_hot = "类一致性闸门" in reason
    if raw == "none":
        return "模型判 none（hot_guard 改为 mixed）" if has_hot else "模型判 none"
    if raw == "mixed":
        return "模型判 mixed"
    if raw == "unknown":
        return "模型判 unknown"
    if raw == "all":
        return "其他：判 all 但未命中"
    return "其他：闸门/未判"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="*", default=[
        "1_Web_Exploit_Ransomware",
        "4_Repo_Poisoning_Backdoor",
        "5_Exposed_Service_Pivot",
    ])
    ap.add_argument("--before-dir", default=str(ROOT / "tmp/rag-pilot/before-two-channel"))
    ap.add_argument("--new-dir", default=str(ROOT / "tmp/rag-pilot"))
    ap.add_argument("--before-suffix", default="_rag")
    ap.add_argument("--new-suffix", default="_rag")
    ap.add_argument("--gt-dir", default=str(ROOT / "groundtruth"))
    ap.add_argument("--out", default=str(ROOT / "tmp/rag-audit/lost_steps_classification.json"))
    args = ap.parse_args()

    before_dir = Path(args.before_dir)
    new_dir = Path(args.new_dir)
    all_rows: List[Dict[str, Any]] = []
    per_scenario: Dict[str, Any] = {}

    for scenario in args.scenarios:
        before_report = before_dir / f"{scenario}{args.before_suffix}.json"
        new_report = new_dir / f"{scenario}{args.new_suffix}.json"
        gt_path = Path(args.gt_dir) / f"{scenario}.groundtruth.json"
        before_hits, before_rules = hit_triples(before_report, gt_path)
        new_hits, new_rules = hit_triples(new_report, gt_path)
        lost = sorted(before_hits - new_hits)
        gained = sorted(new_hits - before_hits)
        before_bundles = parse_trace(before_dir / f"{scenario}{args.before_suffix}.trace.jsonl")
        new_bundles = parse_trace(new_dir / f"{scenario}{args.new_suffix}.trace.jsonl")

        rows: List[Dict[str, Any]] = []
        for triple in lost:
            before_ids = find_bundles(before_bundles, triple)
            before_bid = deepest(before_bundles, before_ids)
            new_ids = find_bundles(new_bundles, triple)
            new_bid = deepest(new_bundles, new_ids)
            new_b = new_bundles.get(new_bid) or {}
            category = classify(new_b)
            rows.append({
                "scenario": scenario,
                "edge": f"{triple[0]} --{triple[1]}--> {triple[2]}",
                "src": triple[0], "syscall": triple[1], "dst": triple[2],
                "before_bundle": before_bid,
                "before_verdict": (before_bundles.get(before_bid) or {}).get("final_verdict", ""),
                "new_bundle": new_bid,
                "new_verdict": new_b.get("final_verdict") or new_b.get("raw_verdict", ""),
                "new_guard": new_b.get("raw_guard", ""),
                "new_rule_ids": new_b.get("rule_ids") or [],
                "new_tech_ids": new_b.get("tech_ids") or [],
                "category": category,
            })
        all_rows.extend(rows)
        per_scenario[scenario] = {
            "before_steps": len(before_hits) + len(before_rules),
            "new_steps": len(new_hits) + len(new_rules),
            "net": (len(new_hits) + len(new_rules)) - (len(before_hits) + len(before_rules)),
            "lost_edges": len(lost),
            "gained_edges": len(gained),
            "lost_categories": {c: sum(1 for r in rows if r["category"] == c)
                                for c in sorted({r["category"] for r in rows})},
            "gained": [f"{t[0]} --{t[1]}--> {t[2]}" for t in gained],
        }

    totals = {c: sum(1 for r in all_rows if r["category"] == c)
              for c in sorted({r["category"] for r in all_rows})}
    result = {"per_scenario": per_scenario, "totals": totals, "rows": all_rows}
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({"per_scenario": per_scenario, "totals": totals},
                     ensure_ascii=False, indent=2))
    print(f"\nwritten {dest}")


if __name__ == "__main__":
    main()
