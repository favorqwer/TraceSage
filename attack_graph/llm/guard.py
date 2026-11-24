"""规则引用校验：编号、跳号和系统调用角色对齐。"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

_R_RE = re.compile(r"R\d+")


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
    kind = str(entry_source)
    if kind == "structure":
        # 结构通道的契约是"顶点类型级走通"，角色档位来自训练场景、不能参与全等比较。
        # 规则编号与跳号是否真实存在仍由 bad_rule / bad_hop 校验。
        return any(str(syscall) == bundle_syscall for _, syscall, _ in roles)
    require_both = kind == "exact"
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
             "bad_rule": 0, "bad_hop": 0, "bad_alignment": 0}
    for item in items:
        row = verdicts.get(item["id"])
        if not row or str(row.get("verdict") or "").lower() != "all":
            continue
        rule_ev = item.get("_rule_evidence") or {}
        cited_r = _cited(row, "rule_id", _R_RE)

        if not rule_ev:
            if cited_r:
                stats["fabricated_citation"] += 1
                stats["downgraded"] += 1
                _downgrade(row, "citation without any evidence")
            else:
                stats["no_evidence"] += 1
            continue

        stats["checked"] += 1
        if not cited_r:
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

        if not valid:
            stats["downgraded"] += 1
            _downgrade(row, marker or "invalid citation")
    return stats
