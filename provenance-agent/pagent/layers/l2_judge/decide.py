"""单轮结论决策与明细日志（判定层内部，纯代码）。

逐波第一轮判定（可能切成多批投递）把每条边的结论收齐后，最终结论只由这一次判定与阈值决定：

- 判为相关且置信度不低于阈值 → **确认**；
- 判为相关但低于阈值（或判为无关）→ **排除**；
- 模型没有给出结论（缺编号、整批调用失败）→ **未判定**（不等于排除，也不进报告）。

判定明细写审计日志（排查"为什么这条边被排除"的依据）。**没有第二轮复核**：复核被实测证明
在逐波上下文下永远输给第一轮（三场景合计 15 次调用、0 条真边被救回），已整体删除。
"""

from __future__ import annotations

import json
import threading
from typing import Any

from ...contracts import conf, short, triple

_VERDICT_LOG_LOCK = threading.Lock()


def _record(item: dict[str, Any], *, relevant: bool, confidence: float, reason: str,
            process_id: str = "") -> dict[str, Any]:
    return {
        "src": item["src"], "syscall": item["syscall"], "dst": item["dst"],
        "src_label": item.get("src_label"), "dst_label": item.get("dst_label"),
        "instances": item.get("instances"), "bytes": item.get("bytes"),
        "t0": item.get("t0"), "t1": item.get("t1"),
        "event_ids": item.get("event_ids") or [],
        "is_relevant": relevant, "confidence": confidence, "reason": reason,
        "judged": True, "verdict_id": item.get("id"),
        "process_id": process_id or item.get("process_id") or "",
    }


def decide_verdicts(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                    min_confidence: float,
                    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """把第一轮结论分成 确认 / 排除 / 未判定（纯函数，便于单测）。"""
    confirmed: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    unjudged: list[dict[str, Any]] = []
    for item in items:
        verdict = verdicts.get(str(item.get("id")))
        if verdict is None:
            unjudged.append({**item, "reason": "模型没有给出这条边的结论（缺编号或调用失败）"})
            continue
        relevant = bool(verdict.get("is_relevant"))
        confidence = conf(verdict)
        record = _record(item, relevant=relevant, confidence=confidence,
                         reason=short(verdict.get("reason")),
                         process_id=str(item.get("process_id") or ""))
        if relevant and confidence >= min_confidence:
            confirmed.append(record)
        else:
            excluded.append(record)
    return confirmed, excluded, unjudged


# --------------------------------------------------------------------------- #
# 判定明细日志（审计旁路，不进报告状态）
# --------------------------------------------------------------------------- #

def verdict_id(record: dict[str, Any]) -> str:
    """这条边在审计日志里的编号：判定的边用 `verdict_id`，未判定的边只有候选表编号 `id`。"""
    return str(record.get("verdict_id") or record.get("id") or "")


def log_verdicts(path: Any, records: list[dict[str, Any]]) -> None:
    """逐条判定写 JSONL：这是排查"为什么这条真边被排了"的唯一依据。"""
    if not records:
        return
    try:
        with _VERDICT_LOG_LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                for record in records:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - 审计旁路失败不能影响判定
        pass


def verdict_log_record(record: dict[str, Any], *, wave: int) -> dict[str, Any]:
    return {
        "id": verdict_id(record),
        "triple": list(triple(record)),
        "relevant": record.get("is_relevant"),
        "confidence": round(float(record.get("confidence") or 0.0), 3),
        "process_id": record.get("process_id"),
        "wave": wave,
        "reason": short(record.get("reason"), 120),
    }
