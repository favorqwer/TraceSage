"""边级 RAG 判定器：小束 + 图检索证据卡 + 强制引用。

替换 B1 的 LlmJudge.judge，不改变后续图公理、报告与评分。
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import settings as cfg
from llm.client import BudgetCallback, call_json
from llm.verdict_edge import parse_edge_verdicts, validate_citation
from rag.graph_retrieve import RuleGraphRetriever
from rag.neo4j_kg import DEFAULT_DATABASE

BUNDLE_MAX = 20
TOPK = 3
MAX_BUNDLES = 40
SYSTEM = cfg.load_prompt("judge_edge_rag.md").replace(
    "{REASON_MAX_CHARS}", str(cfg.reason_max_chars()))

_TRACE_PATH: Optional[Path] = None
_TRACE_LOCK = threading.Lock()
LAST_COVERAGE: Dict[str, Any] = {}


def set_rag_trace(path: str | Path | None) -> None:
    global _TRACE_PATH
    _TRACE_PATH = Path(path) if path else None


def _trace(record: Dict[str, Any]) -> None:
    if _TRACE_PATH is None:
        return
    with _TRACE_LOCK:
        _TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _TRACE_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _bundle_key(edge: Dict[str, Any]) -> Tuple:
    return (str(edge.get("src_label") or ""), str(edge.get("syscall") or ""),
            str(edge.get("dst_label") or ""), tuple(sorted(edge.get("rels") or [])))


def _make_bundles(edges: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        groups[_bundle_key(edge)].append(edge)
    out: List[List[Dict[str, Any]]] = []
    for key in sorted(groups, key=lambda x: str(x)):
        items = groups[key]
        for i in range(0, len(items), BUNDLE_MAX):
            out.append(items[i:i + BUNDLE_MAX])
    return out


def _edge_evidence(edge: Dict[str, Any], matcher: Any, retriever: RuleGraphRetriever,
                   cache: Dict[Tuple, Dict[str, Any]]) -> Dict[str, Any]:
    src_role = matcher.role_of(edge["src"])
    dst_role = matcher.role_of(edge["dst"])
    key = (src_role, str(edge["syscall"]), dst_role,
           str(edge.get("src_label") or ""), str(edge.get("dst_label") or ""))
    if key not in cache:
        cache[key] = retriever.retrieve_for_edge(
            src_role, str(edge["syscall"]), dst_role,
            str(edge.get("src_label") or ""), str(edge.get("dst_label") or ""), limit=10)
    res = cache[key]
    return {
        "edge": edge,
        "src_role": src_role,
        "dst_role": dst_role,
        "motifs": (res.get("motifs") or [])[:TOPK],
        "technique_candidates": res.get("technique_candidates") or [],
    }


def _tech_text(techniques: List[Dict[str, Any]]) -> str:
    parts = []
    for t in techniques[:4]:
        if not t.get("attack_id"):
            continue
        label = "已人工核验" if t.get("verified") else "未人工核验"
        parts.append(f"{t['attack_id']}({t.get('confidence')}，{label})")
    return "、".join(parts)


def _build_bundle(records: List[Dict[str, Any]], bundle_id: str
                  ) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    rmap: Dict[str, Dict[str, Any]] = {}
    motif_to_rid: Dict[str, str] = {}
    lines = [f"## 本批要判的小束 {bundle_id}（{len(records)} 条边）", ""]
    for rec in records:
        edge = rec["edge"]
        lines.append(f"{rec['id']}: {edge.get('src')} --{edge.get('syscall')}--> "
                     f"{edge.get('dst')} [ {edge.get('src_label')} -> {edge.get('dst_label')} ]")
        for g in rec["motifs"]:
            m = g.get("motif") or {}
            mid = str(m.get("motif_id") or "")
            rid = motif_to_rid.get(mid)
            if rid is None:
                rid = f"R{len(rmap) + 1}"
                motif_to_rid[mid] = rid
                rmap[rid] = g
            align = "精确对齐" if int(g.get("alignment") or 0) >= 2 else "部分对齐"
            lines.append(
                f"  证据 {rid} | {mid} | {align} | 查准={m.get('precision')} | "
                f"攻击命中={m.get('attack_hits')} / 背景命中={m.get('background_hits')}")
            for hop in sorted(g.get("hops") or [], key=lambda h: int(h.get("index") or 0)):
                lines.append(f"    hop{hop.get('index')}: {hop.get('src_role')} "
                             f"--{hop.get('syscall')}--> {hop.get('dst_role')}")
            lines.append("    技术: " + (_tech_text(g.get("techniques") or []) or "无"))
        if not rec["motifs"]:
            cands = rec.get("technique_candidates") or []
            lines.append("  证据：无规则子图；技术候选：" + (_tech_text(cands) or "无"))
        lines.append("")
    lines.append("请逐边给出 attack/benign/uncertain；判 attack 必须引用 R 编号与 hop。")
    return "\n".join(lines), rmap


def _judge_bundle(model: Any, records: List[Dict[str, Any]], budget: Any,
                  bundle_id: str) -> Dict[str, Any]:
    listing, rmap = _build_bundle(records, bundle_id)
    config = {"callbacks": [BudgetCallback(budget, node="rag_edge")]}
    result = call_json(model, SYSTEM, listing, config=config, role="rag_edge")
    if not result.get("_raw_ok", True):
        return {"ok": False, "error": result.get("_error") or "未知错误",
                "calls": 1, "listing": listing, "rmap": rmap,
                "records": records, "verdicts": {}, "invalid": [], "raw": ""}
    verdicts, invalid = parse_edge_verdicts(result, [r["id"] for r in records])
    return {"ok": True, "verdicts": verdicts, "invalid": invalid,
            "listing": listing, "rmap": rmap, "records": records,
            "raw": result.get("_raw_text", "")}


def rag_judge(self, ambiguous_candidates: List[Dict[str, Any]],
              topology_facts: Any = None) -> Dict[str, Any]:
    """替换 LlmJudge.judge；返回 confirmed/excluded/kept/detail。"""
    if not ambiguous_candidates:
        return {"confirmed": [], "excluded": [], "kept": [], "calls": 0,
                "seconds": 0.0, "detail": []}

    from experiments import run_v4_frozen as frozen
    from domain.pool import CandidatePool
    from rules.online import MatchIndex

    inv = self.deps.record
    scenario = str(getattr(frozen, "CURRENT_SCENARIO", "")
                   or getattr(self.deps, "scenario", "") or "")
    matcher = getattr(frozen, "CURRENT_MATCHER", None)
    if matcher is None:
        pool = CandidatePool(ambiguous_candidates)
        matcher = MatchIndex(pool, role_cuts=None)
    retriever = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(),
                                   DEFAULT_DATABASE, scenario)
    cache: Dict[Tuple, Dict[str, Any]] = {}
    records_all: List[Dict[str, Any]] = []
    for edge in ambiguous_candidates:
        rec = _edge_evidence(edge, matcher, retriever, cache)
        rec["key"] = (edge.get("src"), edge.get("syscall"), edge.get("dst"))
        records_all.append(rec)

    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for rec in records_all:
        groups[_bundle_key(rec["edge"])].append(rec)
    bundles: List[List[Dict[str, Any]]] = []
    for key in sorted(groups, key=lambda x: str(x)):
        items = groups[key]
        for i in range(0, len(items), BUNDLE_MAX):
            bundles.append(items[i:i + BUNDLE_MAX])
    # 证据密度优先：有 Motif 的边排前面；其余边在预算内不进入小束，保持 kept。
    bundles.sort(key=lambda b: (-sum(1 for r in b if r["motifs"]), -len(b)))
    selected = bundles[:MAX_BUNDLES]
    covered_keys = {rec["key"] for bundle in selected for rec in bundle}
    covered_edges = sum(1 for rec in records_all if rec["key"] in covered_keys)

    calls_before = int(getattr(self.deps.budget, "calls", 0))
    t0 = time.time()

    def run_one(pair: Tuple[int, List[Dict[str, Any]]]) -> Dict[str, Any]:
        idx, bundle = pair
        for i, rec in enumerate(bundle, 1):
            rec["id"] = f"E{i}"
        return _judge_bundle(self.deps.model, bundle, self.deps.budget, f"RB{idx:04d}")

    try:
        with ThreadPoolExecutor(max_workers=min(cfg.max_concurrency(), max(1, len(selected)))) as pool:
            results = list(pool.map(run_one, enumerate(selected, 1)))
    finally:
        retriever.close()

    confirmed: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    kept: List[Dict[str, Any]] = []
    detail: List[Dict[str, Any]] = []

    for res in results:
        rmap = res.get("rmap") or {}
        verdicts = res.get("verdicts") or {}
        _trace({
            "bundle_id": None,
            "kind": "bundle",
            "ok": res.get("ok"),
            "error": res.get("error", ""),
            "listing": res.get("listing", ""),
            "raw": res.get("raw", ""),
            "verdicts": verdicts,
            "records": [{"id": r["id"], "key": list(r["key"]),
                         "edge": r["edge"].get("src") + " --" + str(r["edge"].get("syscall"))
                         + "--> " + r["edge"].get("dst")} for r in res.get("records") or []],
        })
        for rec in res.get("records") or []:
            key = rec["key"]
            row = verdicts.get(rec["id"])
            label, reason = "uncertain", "模型未给结论"
            rule_id = hop = None
            citation_valid = None
            motif_id = None
            if row:
                label = str(row.get("label") or "uncertain")
                reason = str(row.get("reason") or "")
                rule_id, hop = row.get("rule_id"), row.get("hop")
                if label == "attack":
                    citation_valid, err = validate_citation(row, key, rmap, matcher)
                    if not citation_valid:
                        label = "uncertain"
                        reason = f"引用无效：{err}；{reason}"
                    else:
                        motif_id = (rmap.get(str(rule_id)) or {}).get("motif", {}).get("motif_id")
            origin = "confirmed" if label == "attack" else "excluded" if label == "benign" else "kept"
            edge_rec = dict(inv.edges.get(key, rec["edge"]))
            edge_rec["origin"] = origin
            edge_rec["class"] = "story"
            edge_rec["reason"] = f"RAG 边级：{label}（{reason}）"
            edge_rec["verdict"] = label
            edge_rec["verdict_reason"] = reason
            if motif_id:
                edge_rec["evidence_motif_id"] = motif_id
            if origin == "confirmed":
                confirmed.append(edge_rec)
            elif origin == "excluded":
                excluded.append(edge_rec)
            else:
                kept.append(edge_rec)
            try:
                inv.origin[key] = origin
            except Exception:  # noqa: BLE001
                pass
            detail.append({
                "bundle_id": None, "edge": key, "label": label,
                "rule_id": rule_id, "hop": hop,
                "citation_valid": citation_valid, "motif_id": motif_id,
                "reason": reason, "src_role": rec.get("src_role"),
                "dst_role": rec.get("dst_role"),
            })

    for rec in records_all:
        key = rec["key"]
        if key in covered_keys:
            continue
        edge_rec = dict(inv.edges.get(key, rec["edge"]))
        edge_rec["origin"] = "kept"
        edge_rec["class"] = "story"
        edge_rec["reason"] = "RAG 未覆盖（调用预算）"
        edge_rec["verdict"] = "uncertain"
        edge_rec["verdict_reason"] = "未进入预算内小束"
        kept.append(edge_rec)
        try:
            inv.origin[key] = "kept"
        except Exception:  # noqa: BLE001
            pass
        detail.append({
            "bundle_id": None, "edge": key, "label": "uncertain",
            "rule_id": None, "hop": None, "citation_valid": None,
            "motif_id": None, "reason": "未进入预算内小束",
            "src_role": rec.get("src_role"), "dst_role": rec.get("dst_role"),
        })

    coverage = {
        "total_edges": len(records_all),
        "covered_edges": covered_edges,
        "selected_bundles": len(selected),
        "max_bundles": MAX_BUNDLES,
    }
    global LAST_COVERAGE
    LAST_COVERAGE = dict(coverage)
    LAST_COVERAGE["calls"] = int(getattr(self.deps.budget, "calls", 0)) - calls_before
    LAST_COVERAGE["seconds"] = round(time.time() - t0, 2)
    _trace({"kind": "coverage", **LAST_COVERAGE})
    return {
        "confirmed": confirmed, "excluded": excluded, "kept": kept,
        "calls": LAST_COVERAGE["calls"],
        "seconds": LAST_COVERAGE["seconds"], "detail": detail,
        "coverage": coverage,
    }
