"""大模型束结论的解析。"""
from __future__ import annotations

from typing import Any

BUNDLE_VERDICTS = ("all", "none", "mixed", "unknown")

def parse_bundle_verdicts(result: dict[str, Any], valid_ids: set[str]
                          ) -> tuple[dict[str, dict[str, Any]], int]:
    """按编号收束级结论；重复/越界/缺失/非法结论都算没给结论，绝不当成无关。"""
    verdicts: dict[str, dict[str, Any]] = {}
    invalid = 0
    for row in result.get("verdicts") or []:
        if not isinstance(row, dict):
            invalid += 1
            continue
        bid = str(row.get("id") or "").strip()
        verdict = str(row.get("verdict") or "").strip().lower()
        if bid not in valid_ids or bid in verdicts or verdict not in BUNDLE_VERDICTS:
            invalid += 1
            continue
        verdicts[bid] = row
    return verdicts, invalid

