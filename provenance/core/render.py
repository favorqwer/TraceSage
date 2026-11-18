"""层级束渲染：只检索和渲染训练折规则证据。"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

import settings as cfg
from rag.graph_retrieve import RuleGraphRetriever
from rag.motif_likelihood import MotifLikelihoodIndex
from rag.neo4j_kg import DEFAULT_DATABASE
from rag.structure import StructureIndex, merge_rounds

TOPK_RULES = 5

_BASE_RENDER = None
_RETRIEVER: Optional[RuleGraphRetriever] = None
_STRUCT: Optional[StructureIndex] = None
_MOTIF_LR: Optional[MotifLikelihoodIndex] = None
_SCENARIO = ""
_RULE_CACHE: Dict[Tuple, Dict[str, Any]] = {}
_LOCK = threading.Lock()
_EXPLICIT_MATCHER = None
_EXPLICIT_PARENT_MAP: Dict[str, str] = {}


def set_base_render(fn) -> None:
    global _BASE_RENDER
    _BASE_RENDER = fn


def set_matcher(matcher: Any) -> None:
    global _EXPLICIT_MATCHER
    _EXPLICIT_MATCHER = matcher


def set_parent_map(parent_map: Dict[str, str]) -> None:
    global _EXPLICIT_PARENT_MAP
    _EXPLICIT_PARENT_MAP = dict(parent_map or {})


def set_scenario(scenario: str, matcher: Any = None, parent_map: Optional[Dict[str, str]] = None) -> None:
    global _SCENARIO, _RETRIEVER, _STRUCT, _MOTIF_LR, _RULE_CACHE, _EXPLICIT_MATCHER, _EXPLICIT_PARENT_MAP
    _SCENARIO = scenario
    if matcher is not None:
        _EXPLICIT_MATCHER = matcher
    if parent_map is not None:
        _EXPLICIT_PARENT_MAP = dict(parent_map)
    _RETRIEVER = None
    _STRUCT = None
    _MOTIF_LR = MotifLikelihoodIndex(scenario)
    _RULE_CACHE = {}


def close() -> None:
    global _RETRIEVER, _STRUCT, _MOTIF_LR
    if _RETRIEVER is not None:
        _RETRIEVER.close()
        _RETRIEVER = None
    _STRUCT = None
    _MOTIF_LR = None


def _get_retriever() -> RuleGraphRetriever:
    global _RETRIEVER, _STRUCT
    if _RETRIEVER is None:
        _RETRIEVER = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(),
                                        DEFAULT_DATABASE, _SCENARIO)
        _STRUCT = StructureIndex(_RETRIEVER)
    return _RETRIEVER


def _matcher():
    return _EXPLICIT_MATCHER


def _fmt_precision(value: Any) -> str:
    return f"{float(value):.4f}" if value is not None else "无"


def _rule_lines(item: Dict[str, Any], ranked: List[Dict[str, Any]],
                total: int) -> List[str]:
    if not ranked:
        return [cfg.render_section("evidence_rule.md", "empty")]
    lines = [cfg.render_section("evidence_rule.md", "header",
                                SIZE=item.get('size'), TOTAL=total)]
    item["_rule_ids"] = []
    item["_rule_evidence"] = {}
    for idx, rec in enumerate(ranked, 1):
        g = rec["g"]
        m = g.get("motif") or {}
        rid = f"R{idx}"
        mid = str(m.get("motif_id") or "")
        entry = ("exact" if rec["exact"]
                 else ("structure" if rec.get("entry_source") == "structure" else "partial"))
        item["_rule_ids"].append(rid)
        item["_rule_evidence"][rid] = {
            "motif_id": mid,
            "entry_source": entry,
            "hops": [{
                "index": int(h.get("index") or 0),
                "syscall": str(h.get("syscall") or ""),
                "src_role": str(h.get("src_role") or ""),
                "dst_role": str(h.get("dst_role") or ""),
            } for h in sorted(g.get("hops") or [], key=lambda h: int(h.get("index") or 0))],
        }
        aligns = []
        if rec["exact"]:
            aligns.append(cfg.render_section("evidence_rule.md", "align_exact", COUNT=rec['exact']))
        if rec["partial"]:
            aligns.append(cfg.render_section("evidence_rule.md", "align_partial", COUNT=rec['partial']))
        if rec.get("entry_source") == "structure":
            aligns.append(cfg.render_section("evidence_rule.md", "align_structure",
                                             DONE=rec.get('structure'), TOTAL=rec.get('hops_total')))
        lines.append(cfg.render_section(
            "evidence_rule.md", "row", RID=rid, MOTIF=mid,
            ALIGNS=" | ".join(aligns), PRECISION=_fmt_precision(m.get('precision')),
            ATTACK=int(m.get('attack_hits') or 0),
            BACKGROUND=int(m.get('background_hits') or 0),
            IGNORE=int(m.get('ignore_hits') or 0),
            SCENARIOS=len(m.get('support_scenarios') or [])))
        for hop in sorted(g.get("hops") or [], key=lambda h: int(h.get("index") or 0)):
            hop_syscalls = str(hop.get("syscall") or "").split("+")
            mark = (cfg.render_section("evidence_rule.md", "hop_mark")
                    if str(item.get("syscall") or "") in hop_syscalls else "")
            lines.append(cfg.render_section(
                "evidence_rule.md", "hop", INDEX=hop.get('index'), SRC_ROLE=hop.get('src_role'),
                SYSCALL=hop.get('syscall'), DST_ROLE=hop.get('dst_role'), MARK=mark))
    return lines


def _card_lines(item: Dict[str, Any], records: Dict[Any, Any]) -> List[str]:
    matcher = _matcher()
    if matcher is None:
        return []
    members = list(item.get("members") or [])
    if not members:
        return []
    retriever = _get_retriever()
    programs = [str(p) for p in (item.get("programs") or [])]
    member_roles: set = set()
    member_edges: List[tuple] = []
    rules_by_mid: Dict[str, Dict[str, Any]] = {}

    for triple in members:
        edge = records.get(triple)
        if not edge:
            continue
        sc = str(edge.get("syscall") or "")
        s_src = str(edge.get("src") or "")
        s_dst = str(edge.get("dst") or "")

        src_role = matcher.role_of(s_src)
        dst_role = matcher.role_of(s_dst)
        src_label = str(edge.get("src_label") or "")
        dst_label = str(edge.get("dst_label") or "")
        member_roles.add((src_role, sc, dst_role))
        member_edges.append((s_src, sc, s_dst, src_role, dst_role, src_label, dst_label))
        key = (src_role, sc, dst_role, src_label, dst_label, tuple(programs))

        if key not in _RULE_CACHE:
            with _LOCK:
                if key not in _RULE_CACHE:
                    _RULE_CACHE[key] = retriever.retrieve_rules(
                        src_role, sc, dst_role, limit=10)
        for g in (_RULE_CACHE[key].get("motifs") or []):
            mid = str((g.get("motif") or {}).get("motif_id") or "")
            if not mid:
                continue
            rec = rules_by_mid.setdefault(
                mid, {"g": g, "members": set(), "exact": 0, "partial": 0})
            if triple in rec["members"]:
                continue
            rec["members"].add(triple)
            if str(g.get("entry_source")) == "exact":
                rec["exact"] += 1
            else:
                rec["partial"] += 1

    item["_rag_member_roles"] = sorted([list(x) for x in member_roles])

    # ===== 通道一：留一折似然比 LR 排序规则 =====
    for mid, rec in rules_by_mid.items():
        rec["lr"] = _MOTIF_LR.get_lr(mid) if _MOTIF_LR else 0.0
        rec["weighted_lr"] = _MOTIF_LR.get_weighted_lr(mid) if _MOTIF_LR else 0.0

    def rule_rank(rec: Dict[str, Any]):
        g = rec["g"]
        m = g.get("motif") or {}
        prec = m.get("precision")
        return (
            -int(g.get("alignment") or 0),
            -len(rec["members"]),
            -float(rec.get("weighted_lr", rec.get("lr", 0.0))),
            -(float(prec) if prec is not None else -1.0),
            -int(m.get("attack_hits") or 0),
            str(m.get("motif_id") or ""),
        )

    keep_a, keep_b = cfg.rule_mix()
    cap_a = keep_a
    ranked_rules = sorted(rules_by_mid.values(), key=rule_rank)[:cap_a]
    total_rules = len(rules_by_mid)
    if keep_b and _STRUCT is not None:
        secondary = _STRUCT.rank(member_edges, keep_b)
        if secondary:
            total_rules += len(secondary)
            ranked_rules = merge_rounds(ranked_rules, secondary, cap_a, keep_b)
        if os.environ.get("RAG_DEBUG"):
            print(f"[navigator.render] 结构通道 item={item.get('id')} "
                  f"候选={len(secondary)} 混入={max(0, len(ranked_rules) - cap_a)}", flush=True)

    lines: List[str] = []
    lines.extend(_rule_lines(item, ranked_rules, total_rules))
    return lines


def _context_lines(item: Dict[str, Any]) -> List[str]:
    parent_map = _EXPLICIT_PARENT_MAP or {}
    parents = sorted({parent_map[p] for p in (item.get("programs") or []) if p in parent_map})
    lines: List[str] = []
    if parents:
        lines.append(cfg.render_section("listing_context.md", "process",
                                        PARENTS=", ".join(parents[:4])))
    parent = item.get("parent") or {}
    if parent.get("verdict"):
        lines.append(cfg.render_section(
            "listing_context.md", "parent", BID=parent.get('bid'),
            VERDICT=parent.get('verdict'), REASON=str(parent.get('reason') or '')[:60]))
    return lines


def render(items: List[Dict[str, Any]], records: Dict[Any, Any], ref_t: int, **kwargs) -> str:
    base = _BASE_RENDER(items, records, ref_t, **kwargs) if _BASE_RENDER else ""
    lines = base.split("\n")
    out: List[str] = []
    for line in lines:
        out.append(line)
        for item in items:
            if line.startswith(f"{item['id']}｜"):
                out.extend(_context_lines(item))
                out.extend(_card_lines(item, records))
    return "\n".join(out)
