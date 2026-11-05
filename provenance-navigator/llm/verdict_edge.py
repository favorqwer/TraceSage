"""边级 RAG 判定 JSON 解析与引用校验。"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple

LABELS = ("attack", "benign", "uncertain")


def parse_edge_verdicts(payload: Dict[str, Any], valid_ids: Iterable[str]
                        ) -> Tuple[Dict[str, Dict[str, Any]], list]:
    valid = set(valid_ids)
    out: Dict[str, Dict[str, Any]] = {}
    invalid: list = []
    for row in payload.get("verdicts") or []:
        if not isinstance(row, dict):
            invalid.append(row)
            continue
        eid = str(row.get("id") or "")
        label = str(row.get("label") or "").lower()
        if eid not in valid or label not in LABELS:
            invalid.append(row)
            continue
        out[eid] = {
            "label": label,
            "rule_id": row.get("rule_id"),
            "hop": row.get("hop"),
            "reason": str(row.get("reason") or ""),
        }
    return out, invalid


def validate_citation(row: Dict[str, Any], edge_key: Tuple[str, str, str],
                      evidence: Dict[str, Dict[str, Any]], matcher: Any
                      ) -> Tuple[bool, str]:
    """校验 attack 引用的规则/跳是否真实存在且与边对齐。"""
    rule_id = str(row.get("rule_id") or "")
    ev = evidence.get(rule_id)
    if not ev:
        return False, "rule_id 不在本束证据中"
    try:
        hop_no = int(row.get("hop"))
    except (TypeError, ValueError):
        return False, "hop 不是整数"
    hop = next((h for h in (ev.get("hops") or []) if int(h.get("index")) == hop_no), None)
    if hop is None:
        return False, f"规则 {rule_id} 没有第 {hop_no} 跳"
    src, sc, dst = edge_key
    src_role = matcher.role_of(src)
    dst_role = matcher.role_of(dst)
    if str(hop.get("syscall")) != str(sc):
        return False, "跳的 syscall 与边不一致"
    if str(hop.get("src_role")) != src_role or str(hop.get("dst_role")) != dst_role:
        return False, "跳的角色与边不一致"
    return True, ""
