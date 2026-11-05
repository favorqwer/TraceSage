#!/usr/bin/env python
"""只读审计：RAG 两个检索入口的覆盖与实际卡片来源。

不调用大模型，不写 Neo4j 规则库。只做两件事：
1. 用当前代码对 10 个场景的 GT 边重算检索覆盖，区分精确入口与技术入口；
2. 解析已有 RAG 运行记录，统计每个束拿到的是真实规则卡、技术候选退路还是无卡，
   以及退路束被判定为 all 的数量（引用守卫失效的实际范围）。

用法：
    .venv/Scripts/python.exe tools/audit_rag_entries.py --out-dir tmp/rag-audit
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "provenance-navigator"))
sys.path.insert(0, str(ROOT / "tools"))

import settings as cfg  # noqa: E402
from closure import extract_raw_closure  # noqa: E402
from domain.edge import edge_key  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from routing.prepare import PreFilter  # noqa: E402
from rules.library import load_library_file, _role_cuts  # noqa: E402
from rules.online import MatchIndex  # noqa: E402
from rag.graph_retrieve import RuleGraphRetriever  # noqa: E402
from rag.neo4j_kg import DEFAULT_DATABASE  # noqa: E402
import eval_graph_retrieval as egr  # noqa: E402


def scenario_order(fold_dir: Path) -> List[str]:
    names = sorted(p.stem for p in fold_dir.glob("*.json"))
    return sorted(names, key=lambda s: int(s.split("_", 1)[0]) if s.split("_", 1)[0].isdigit() else 10**9)


def build_scenario_context(scenario: str, fold_dir: Path) -> Tuple[Any, Dict[Tuple, Any], Dict[str, Any]]:
    fold_path = fold_dir / f"{scenario}.json"
    patterns, audit = load_library_file(fold_path)
    admitted = set(audit.get("selected") or [])
    role_cuts = _role_cuts(audit)
    raw_edges, stats, _deps = extract_raw_closure(scenario, return_deps=True, log=lambda s: None)
    anchor_keys = {tuple(t) for t in (stats.get("anchor_triples") or [])}
    final_confirmed = {edge_key(e): dict(e) for e in raw_edges if edge_key(e) in anchor_keys}
    pool = CandidatePool(raw_edges)
    clean_unexcluded, _ = PreFilter(pool.facts).apply(
        [e for e in raw_edges if edge_key(e) not in anchor_keys])
    clean_pool = CandidatePool(clean_unexcluded, facts=pool.facts)
    matcher = MatchIndex(clean_pool, pool.facts, role_cuts=role_cuts)
    matched_all = matcher.match(patterns or [], admitted=admitted,
                                seed_edges=final_confirmed, return_all=True)
    return matcher, matched_all, audit


def audit_gt_edges(scenario: str, retriever: RuleGraphRetriever, matcher: Any,
                   matched_all: Dict[Tuple, Any], technique_map: Dict[str, Any],
                   limit: int) -> Dict[str, Any]:
    gt = json.loads((ROOT / "groundtruth" / f"{scenario}.groundtruth.json").read_text(encoding="utf-8"))
    rows: List[Dict[str, Any]] = []
    for edge in egr.gt_edge_rows(gt):
        key = (edge["src"], edge["syscall"], edge["dst"])
        expected = {str(m.get("id")) for m in (matched_all.get(key) or [])}
        src_role = matcher.role_of(edge["src"])
        dst_role = matcher.role_of(edge["dst"])
        res = retriever.retrieve_for_edge(
            src_role, edge["syscall"], dst_role,
            edge["src_label"], edge["dst_label"], limit=limit)
        exact_ids = [g["motif"]["motif_id"] for g in res["exact"]]
        technique_ids = [g["motif"]["motif_id"] for g in res["technique"]]
        combined = res.get("motifs") or (res["exact"] + res["technique"])
        top3 = combined[:3]
        exact_set = set(exact_ids)
        top3_sources = ["exact" if str(g.get("motif", {}).get("motif_id")) in exact_set else "technique"
                        for g in top3]
        correct = {str(t) for t in
                   (technique_map.get(edge["phase_id"], {}).get("techniques") or [])}
        expanded = set()
        for g in combined:
            expanded |= {t.get("attack_id") for t in (g.get("techniques") or []) if t.get("attack_id")}
        candidates = {t["attack_id"] for t in res.get("technique_candidates") or []}

        def hit(ids: set) -> bool:
            return bool(correct) and egr.tech_match(ids, correct)

        rows.append({
            "edge": f"{edge['src']} --{edge['syscall']}--> {edge['dst']}",
            "symbolic_reachable": bool(expected),
            "exact_nonempty": bool(exact_ids),
            "technique_nonempty": bool(technique_ids),
            "exact_beyond_online": bool(exact_ids) and not expected,
            "technique_without_exact": bool(technique_ids) and not exact_ids,
            "top3_sources": top3_sources,
            "top3_card_count": len(top3),
            "tech_candidate_only": not combined and bool(candidates),
            "no_evidence": not combined and not candidates,
            "expanded_hit": hit(expanded),
            "expanded_hit@3": hit(set().union(*[
                {t.get("attack_id") for t in (g.get("techniques") or [])} for g in top3]) if top3 else set()),
            "candidate_hit": hit(candidates),
            "correct_count": len(correct),
        })
    return {"scenario": scenario, "rows": rows}


def parse_listing_cards(listing: str) -> Dict[str, Dict[str, Any]]:
    """从完整提示词里按束解析证据卡。

    返回 {bundle_id: {real, fallback, exact_cards, technique_cards, exact_unknown}}。
    """
    out: Dict[str, Dict[str, Any]] = {}
    parts = re.split(r"(?m)^(B\d+)｜", listing)
    for i in range(1, len(parts), 2):
        bid, body = parts[i], parts[i + 1]
        real = re.findall(r"(?m)^\s+R\d+ \| (MOTIF_[0-9a-f]+) \|", body)
        fallback = re.findall(r"(?m)^\s+R\d+ \| 技术候选", body)
        fallback += re.findall(r"(?m)^\s+T\d+ \| T\d", body)
        alignments = [int(x) for x in re.findall(r"精确对齐 (\d+)", body)]
        exact_cards = sum(1 for x in alignments if x > 0) if alignments else None
        out[bid] = {
            "real": len(real),
            "fallback": len(fallback),
            "exact_cards": exact_cards,
            "technique_cards": (len(alignments) - exact_cards) if alignments else None,
            "has_alignment_field": bool(alignments),
        }
    return out


def audit_traces(scenario: str, trace_path: Path) -> Dict[str, Any]:
    if not trace_path.is_file():
        return {"scenario": scenario, "trace": str(trace_path), "missing": True}
    cards: Dict[str, Dict[str, Any]] = {}
    verdicts: Dict[str, str] = {}
    batches = 0
    with trace_path.open(encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "listing" in rec and "items" in rec:
                batches += 1
                for bid, rec_card in parse_listing_cards(rec["listing"]).items():
                    cards[bid] = rec_card
            elif rec.get("kind") == "detail":
                for d in rec.get("detail") or []:
                    bid = str(d.get("id") or "")
                    if bid:
                        verdicts[bid] = str(d.get("verdict") or "")
    counts = Counter()
    all_in_fallback = 0
    all_in_real = 0
    exact_card_bundles = 0
    technique_only_card_bundles = 0
    mixed_card_bundles = 0
    unknown_source = 0
    for bid, rec in cards.items():
        real, fallback = rec["real"], rec["fallback"]
        if real:
            counts["real_card_bundles"] += 1
            if rec["has_alignment_field"]:
                if rec["exact_cards"] and rec["technique_cards"]:
                    mixed_card_bundles += 1
                elif rec["exact_cards"]:
                    exact_card_bundles += 1
                else:
                    technique_only_card_bundles += 1
            else:
                unknown_source += 1
            if verdicts.get(bid) == "all":
                all_in_real += 1
        elif fallback:
            counts["fallback_only_bundles"] += 1
            if verdicts.get(bid) == "all":
                all_in_fallback += 1
        else:
            counts["no_card_bundles"] += 1
    counts["bundles"] = len(cards)
    counts["batches"] = batches
    counts["verdicts"] = len(verdicts)
    return {
        "scenario": scenario,
        "trace": str(trace_path),
        "counts": dict(counts),
        "all_in_fallback": all_in_fallback,
        "all_in_real": all_in_real,
        "exact_card_bundles": exact_card_bundles,
        "technique_only_card_bundles": technique_only_card_bundles,
        "mixed_card_bundles": mixed_card_bundles,
        "unknown_source_bundles": unknown_source,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=str(ROOT / "tmp/rag-audit"))
    ap.add_argument("--fold-dir", default=str(ROOT / "output/navigator-baseline/distill/fold-libraries"))
    ap.add_argument("--technique-map", default=str(ROOT / "groundtruth/attack-technique-map.json"))
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--scenarios", nargs="*", default=None)
    args = ap.parse_args()

    cfg.load_dotenv()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fold_dir = Path(args.fold_dir)
    tech_map_all = json.loads(Path(args.technique_map).read_text(encoding="utf-8"))["scenarios"]

    gt_results: Dict[str, Any] = {}
    trace_results: Dict[str, Any] = {}
    for scenario in (args.scenarios or scenario_order(fold_dir)):
        t0 = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] {scenario} 读图并建索引 ...", flush=True)
        try:
            matcher, matched_all, _audit = build_scenario_context(scenario, fold_dir)
            retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(), args.database, scenario)
            try:
                gt_results[scenario] = audit_gt_edges(
                    scenario, retriever, matcher, matched_all,
                    tech_map_all.get(scenario, {}), args.limit)
            finally:
                retriever.close()
        except Exception as exc:  # 单场景失败如实记录，不补数字
            gt_results[scenario] = {"scenario": scenario,
                                    "error": f"{type(exc).__name__}: {exc}"}
            print(f"[{time.strftime('%H:%M:%S')}] {scenario} GT 审计失败：{exc}", flush=True)
        trace_path = ROOT / f"tmp/rag-pilot/{scenario}_rag.trace.jsonl"
        trace_results[scenario] = audit_traces(scenario, trace_path)
        print(f"[{time.strftime('%H:%M:%S')}] {scenario} 完成，{time.time() - t0:.1f}s", flush=True)

    (out_dir / "gt_entry_split.json").write_text(
        json.dumps(gt_results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "card_sources.json").write_text(
        json.dumps(trace_results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 汇总
    rows = [r for rec in gt_results.values() for r in (rec.get("rows") or [])]
    un = [r for r in rows if not r["symbolic_reachable"]]
    summary = {
        "gt_edges": len(rows),
        "online_symbolic_reachable": sum(1 for r in rows if r["symbolic_reachable"]),
        "exact_nonempty": sum(1 for r in rows if r["exact_nonempty"]),
        "exact_beyond_online": sum(1 for r in rows if r["exact_beyond_online"]),
        "technique_nonempty": sum(1 for r in rows if r["technique_nonempty"]),
        "technique_without_exact": sum(1 for r in rows if r["technique_without_exact"]),
        "top3_exact_cards": sum(r["top3_sources"].count("exact") for r in rows),
        "top3_technique_cards": sum(r["top3_sources"].count("technique") for r in rows),
        "unreachable_n": len(un),
        "unreachable_tech_nonempty": sum(1 for r in un if r["technique_nonempty"]),
        "unreachable_candidate_hit": sum(1 for r in un if r["candidate_hit"]),
        "unreachable_expanded_hit": sum(1 for r in un if r["expanded_hit"]),
        "unreachable_expanded_hit@3": sum(1 for r in un if r["expanded_hit@3"]),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = ["# RAG 检索入口只读审计", "", "## GT 边级", "",
             "| 指标 | 数量 | 占全部 GT 边 |", "|---|---:|---:|"]
    n = max(1, len(rows))
    for k in ("gt_edges", "online_symbolic_reachable", "exact_nonempty", "exact_beyond_online",
              "technique_nonempty", "technique_without_exact", "top3_exact_cards",
              "top3_technique_cards"):
        lines.append(f"| {k} | {summary[k]} | {summary[k] / n:.1%} |")
    lines += ["", "## 符号不可达边", "",
              "| 指标 | 数量 | 占不可达边 |", "|---|---:|---:|"]
    un_n = max(1, len(un))
    for k in ("unreachable_n", "unreachable_tech_nonempty", "unreachable_candidate_hit",
              "unreachable_expanded_hit", "unreachable_expanded_hit@3"):
        lines.append(f"| {k} | {summary[k]} | {summary[k] / un_n:.1%} |")
    lines += ["", "## 运行记录里的实际卡片", "",
              "| 场景 | 束数 | 真实规则卡束 | 技术候选退路束 | 无卡束 | 退路判 all |",
              "|---|---:|---:|---:|---:|---:|"]
    for sc, rec in trace_results.items():
        c = rec.get("counts") or {}
        lines.append(f"| {sc} | {c.get('bundles', 0)} | {c.get('real_card_bundles', 0)} | "
                     f"{c.get('fallback_only_bundles', 0)} | {c.get('no_card_bundles', 0)} | "
                     f"{rec.get('all_in_fallback', 0)} |")
    (out_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print(f"written {out_dir}", flush=True)


if __name__ == "__main__":
    main()
