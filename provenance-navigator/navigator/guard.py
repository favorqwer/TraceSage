"""束级引用守卫：规则证据和技术证据分开校验。

规则证据由 `navigator.render` 写入 `_rule_evidence`：
    {"R1": {"motif_id": "...", "entry_source": "exact|partial",
            "hops": [{"index": 1, "syscall": "read",
                      "src_role": "...", "dst_role": "..."}]}}

技术证据由 `navigator.render` 写入 `_tech_evidence`：
    {"E1": {"attack_id": "T1071", "observable_ids": [...],
            "conditions": [...], "confidence": 0.7}}

判定：
- 规则引用：编号在规则证据里；跳号是整数且在规则里存在；跳的系统调用
  与束一致；精确规则要求源/目标角色都与同一个成员边一致，部分规则要求
  至少一个角色一致。
- 技术引用：编号在技术证据里。技术没有跳号。
- 两类证据都没有时，任何 R/E 引用都算编造；有证据时至少要引用一个有效编号。
- 任何一个被引用的编号无效，结论降级为 mixed。
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

_R_RE = re.compile(r"R\d+")
_E_RE = re.compile(r"E\d+")


def _cited(row: Dict[str, Any], field: str, regex: re.Pattern) -> List[str]:
    out: List[str] = []
    value = str(row.get(field) or "").strip()
    if value:
        out.append(value)
    for match in regex.finditer(str(row.get("reason") or "")):
        out.append(match.group(0))
    seen = set()
    uniq: List[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _hop_syscalls(hop: Dict[str, Any]) -> List[str]:
    return [s for s in str(hop.get("syscall") or "").split("+") if s]


def _hop_matches(hop: Dict[str, Any], member_roles: Iterable[Tuple[str, str, str]],
                 bundle_syscall: str, entry_source: str = "partial") -> bool:
    if bundle_syscall not in _hop_syscalls(hop):
        return False
    roles = list(member_roles)
    if not roles:
        return True
    require_both = str(entry_source) == "exact"
    for src_role, syscall, dst_role in roles:
        if str(syscall) != bundle_syscall:
            continue
        src_ok = str(hop.get("src_role")) == str(src_role)
        dst_ok = str(hop.get("dst_role")) == str(dst_role)
        if (src_ok and dst_ok) if require_both else (src_ok or dst_ok):
            return True
    return False


def _downgrade(row: Dict[str, Any], marker: str) -> None:
    row["verdict"] = "mixed"
    row["_rag_guard"] = marker


def enforce_citations(items: List[Dict[str, Any]],
                      verdicts: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    stats = {"checked": 0, "downgraded": 0, "no_evidence": 0,
             "fabricated_citation": 0, "missing_citation": 0,
             "bad_rule": 0, "bad_hop": 0, "bad_alignment": 0,
             "bad_technique": 0}
    for item in items:
        row = verdicts.get(item["id"])
        if not row or str(row.get("verdict") or "").lower() != "all":
            continue
        rule_ev = item.get("_rule_evidence") or {}
        tech_ev = item.get("_tech_evidence") or {}
        cited_r = _cited(row, "rule_id", _R_RE)
        cited_e = _cited(row, "tech_id", _E_RE)

        if not rule_ev and not tech_ev:
            if cited_r or cited_e:
                stats["fabricated_citation"] += 1
                stats["downgraded"] += 1
                _downgrade(row, "citation without any evidence")
            else:
                stats["no_evidence"] += 1
            continue

        stats["checked"] += 1
        if not cited_r and not cited_e:
            stats["missing_citation"] += 1
            stats["downgraded"] += 1
            _downgrade(row, "all without citation while evidence exists")
            continue

        valid = True
        marker = ""
        member_roles = [tuple(x) for x in (item.get("_rag_member_roles") or [])]
        bundle_syscall = str(item.get("syscall") or "")

        for rid in cited_r:
            ev = rule_ev.get(rid)
            if not ev:
                valid = False
                stats["bad_rule"] += 1
                marker = marker or f"cited rule {rid} not in rule evidence"
                continue
            try:
                hop_no = int(row.get("hop"))
            except (TypeError, ValueError):
                valid = False
                stats["bad_hop"] += 1
                marker = marker or "missing or non-integer hop for rule citation"
                continue
            hop = next((h for h in (ev.get("hops") or [])
                        if int(h.get("index") or 0) == hop_no), None)
            if hop is None:
                valid = False
                stats["bad_hop"] += 1
                marker = marker or f"hop {hop_no} not in cited rule"
                continue
            if not _hop_matches(hop, member_roles, bundle_syscall,
                                str(ev.get("entry_source") or "partial")):
                valid = False
                stats["bad_alignment"] += 1
                marker = marker or "cited hop does not match bundle syscall/roles"

        for eid in cited_e:
            if eid not in tech_ev:
                valid = False
                stats["bad_technique"] += 1
                marker = marker or f"cited technique {eid} not in technique evidence"

        if not valid:
            stats["downgraded"] += 1
            _downgrade(row, marker or "invalid citation")
    return stats
