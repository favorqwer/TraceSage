"""层级束渲染钩子：保留 B1 的层级路由，证据分成规则证据和技术证据两段。

- 规则证据：只来自蒸馏规则库（Motif/Hop），按精确/部分对齐排序；
- 技术证据：只来自 BehaviorObservable/Technique，T-强注入，T-弱只记录；
- 两类证据各自编号（R / E），不合并、不互相转化。
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

import settings as cfg
from rag.graph_retrieve import RuleGraphRetriever
from rag.neo4j_kg import DEFAULT_DATABASE

TOPK_RULES = 3
TOPK_TECH = 3

_BASE_RENDER = None
_RETRIEVER: Optional[RuleGraphRetriever] = None
_SCENARIO = ""
_RULE_CACHE: Dict[Tuple, Dict[str, Any]] = {}
_TECH_CACHE: Dict[Tuple, Dict[str, Any]] = {}
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
    global _SCENARIO, _RETRIEVER, _RULE_CACHE, _TECH_CACHE, _EXPLICIT_MATCHER, _EXPLICIT_PARENT_MAP
    _SCENARIO = scenario
    if matcher is not None:
        _EXPLICIT_MATCHER = matcher
    if parent_map is not None:
        _EXPLICIT_PARENT_MAP = dict(parent_map)
    _RETRIEVER = None
    _RULE_CACHE = {}
    _TECH_CACHE = {}


def close() -> None:
    global _RETRIEVER
    if _RETRIEVER is not None:
        _RETRIEVER.close()
        _RETRIEVER = None


def _get_retriever() -> RuleGraphRetriever:
    global _RETRIEVER
    if _RETRIEVER is None:
        _RETRIEVER = RuleGraphRetriever(cfg.neo4j_uri(), cfg.neo4j_auth(),
                                        DEFAULT_DATABASE, _SCENARIO)
    return _RETRIEVER


def _matcher():
    return _EXPLICIT_MATCHER


def _fmt_precision(value: Any) -> str:
    return f"{float(value):.4f}" if value is not None else "无"


def _rule_lines(item: Dict[str, Any], ranked: List[Dict[str, Any]],
                total: int) -> List[str]:
    if not ranked:
        return ["    【规则证据】本束没有规则证据"]
    lines = [f"    【规则证据】(本束成员 {item.get('size')} 条，命中 {total} 条规则)"]
    item["_rule_ids"] = []
    item["_rule_evidence"] = {}
    for idx, rec in enumerate(ranked, 1):
        g = rec["g"]
        m = g.get("motif") or {}
        rid = f"R{idx}"
        mid = str(m.get("motif_id") or "")
        entry = "exact" if rec["exact"] else "partial"
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
            aligns.append(f"精确对齐 {rec['exact']} 条")
        if rec["partial"]:
            aligns.append(f"部分对齐 {rec['partial']} 条")
        lines.append(
            f"      {rid} | {mid} | {' | '.join(aligns)} | "
            f"训练折查准 {_fmt_precision(m.get('precision'))} | "
            f"攻击/背景/忽略 {int(m.get('attack_hits') or 0)}/"
            f"{int(m.get('background_hits') or 0)}/{int(m.get('ignore_hits') or 0)} | "
            f"支持场景 {len(m.get('support_scenarios') or [])} 个")
        for hop in sorted(g.get("hops") or [], key=lambda h: int(h.get("index") or 0)):
            hop_syscalls = str(hop.get("syscall") or "").split("+")
            mark = "  [与束系统调用一致]" if str(item.get("syscall") or "") in hop_syscalls else ""
            lines.append(f"        hop{hop.get('index')}: {hop.get('src_role')} "
                         f"--{hop.get('syscall')}--> {hop.get('dst_role')}{mark}")
    return lines


def _tech_lines(item: Dict[str, Any], ranked: List[Dict[str, Any]],
                total: int) -> List[str]:
    if not ranked:
        return ["    【技术证据】本束没有技术证据"]
    lines = [f"    【技术证据】(本束成员 {item.get('size')} 条，命中 {total} 个技术)"]
    item["_tech_ids"] = []
    item["_tech_evidence"] = {}
    for idx, rec in enumerate(ranked, 1):
        eid = f"E{idx}"
        item["_tech_ids"].append(eid)
        item["_tech_evidence"][eid] = {
            "attack_id": rec["attack_id"],
            "observable_ids": list(rec["strong_observable_ids"]),
            "conditions": list(rec["strong_conditions"]),
            "confidence": float(rec["confidence"]),
        }
        tactics = "、".join(rec.get("tactics") or [])
        title = f"      {eid} | {rec['attack_id']} | {rec.get('name') or ''}"
        if tactics:
            title += f" | 战术 {tactics}"
        lines.append(title)
        lines.append("        命中条件：" + "；".join(rec["strong_conditions"]))
        verified = "含已核验观测" if rec["verified"] else "未人工核验"
        lines.append(f"        观测置信度 {float(rec['confidence']):.2f}"
                     f"（人工设定，{verified}）")
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
    rules_by_mid: Dict[str, Dict[str, Any]] = {}
    techs_by_id: Dict[str, Dict[str, Any]] = {}

    for triple in members:
        edge = records.get(triple)
        if not edge:
            continue
        sc = str(edge.get("syscall") or "")
        src_role = matcher.role_of(edge["src"])
        dst_role = matcher.role_of(edge["dst"])
        src_label = str(edge.get("src_label") or "")
        dst_label = str(edge.get("dst_label") or "")
        member_roles.add((src_role, sc, dst_role))
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

        if key not in _TECH_CACHE:
            with _LOCK:
                if key not in _TECH_CACHE:
                    _TECH_CACHE[key] = retriever.retrieve_techniques(
                        sc, src_role, dst_role, src_label, dst_label,
                        programs=programs,
                        paths=[str(edge.get("src") or ""), str(edge.get("dst") or "")])
        tres = _TECH_CACHE[key]
        for t in (tres.get("strong") or []) + (tres.get("weak") or []):
            tid = str(t.get("attack_id") or "")
            if not tid:
                continue
            rec = techs_by_id.setdefault(tid, {
                "attack_id": tid, "name": str(t.get("name") or ""),
                "tactics": list(t.get("tactics") or []),
                "members": set(), "strong": False,
                "strong_observable_ids": set(), "strong_conditions": set(),
                "confidence": 0.0, "verified": False,
            })
            rec["members"].add(triple)
            rec["strong"] = rec["strong"] or bool(t.get("strong"))
            rec["strong_observable_ids"].update(t.get("strong_observable_ids") or [])
            rec["strong_conditions"].update(t.get("strong_conditions") or [])
            rec["confidence"] = max(rec["confidence"], float(t.get("confidence") or 0.0))
            rec["verified"] = rec["verified"] or bool(t.get("verified"))

    item["_rag_member_roles"] = sorted([list(x) for x in member_roles])

    def rule_rank(rec: Dict[str, Any]):
        g = rec["g"]
        m = g.get("motif") or {}
        prec = m.get("precision")
        return (-int(g.get("alignment") or 0),
                -(float(prec) if prec is not None else -1.0),
                -int(m.get("attack_hits") or 0),
                str(m.get("motif_id") or ""))

    ranked_rules = sorted(rules_by_mid.values(), key=rule_rank)[:TOPK_RULES]

    strong_recs = [r for r in techs_by_id.values() if r["strong"]]
    for rec in strong_recs:
        rec["strong_observable_ids"] = sorted(rec["strong_observable_ids"])
        rec["strong_conditions"] = sorted(rec["strong_conditions"])

    def tech_rank(rec: Dict[str, Any]):
        return (-float(rec["confidence"]), -len(rec["members"]),
                -len(rec["strong_conditions"]), str(rec["attack_id"]))

    ranked_tech = sorted(strong_recs, key=tech_rank)[:TOPK_TECH]
    weak_recs = [r for r in techs_by_id.values() if not r["strong"]]
    item["_tech_weak"] = [{
        "attack_id": r["attack_id"], "name": r["name"],
        "confidence": r["confidence"], "members": len(r["members"]),
    } for r in sorted(weak_recs, key=tech_rank)]

    if os.environ.get("RAG_DEBUG"):
        print(f"[navigator.render] item={item.get('id')} size={item.get('size')} "
              f"members={len(members)} rules={len(rules_by_mid)} "
              f"tech_strong={len(strong_recs)} tech_weak={len(weak_recs)} "
              f"scenario={_SCENARIO!r}", flush=True)

    lines: List[str] = []
    lines.extend(_rule_lines(item, ranked_rules, len(rules_by_mid)))
    lines.extend(_tech_lines(item, ranked_tech, len(strong_recs)))
    return lines


def _context_lines(item: Dict[str, Any]) -> List[str]:
    parent_map = _EXPLICIT_PARENT_MAP or {}
    parents = sorted({parent_map[p] for p in (item.get("programs") or []) if p in parent_map})
    lines: List[str] = []
    if parents:
        lines.append("    【上游执行环境】父进程: " + ", ".join(parents[:4]))
    parent = item.get("parent") or {}
    if parent.get("verdict"):
        lines.append(f"    【父束】{parent.get('bid')} 判定 {parent.get('verdict')}；"
                     f"{str(parent.get('reason') or '')[:60]}")
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
