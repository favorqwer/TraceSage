"""复核与结论合并（第 4 层内部）：反向提问、两轮合并、判定明细日志。

**当前口径**：复核在**同一批内**进行，看不到整条链、也看不到别的批的结论（跨批全局视角是阶段二要补的）。
不变式：未判定不等于排除；争议边默认保留（两轮不一致时取低置信度并标记争议）；整批调用失败的
二分拆批重试属于编排器的错误处理。
"""

from __future__ import annotations

import json
import threading
from typing import Any

from ...contracts import conf, parse_verdicts, short, triple
from ...core import prompts
from ...core.llm import BudgetCallback, call_json
from ..l2_prepare import render
from .select import PASS2_MARGIN, select_targets

REFUTE_SYSTEM = prompts.load("judge_refute.md")

_VERDICT_LOG_LOCK = threading.Lock()


def _record(item: dict[str, Any], *, relevant: bool, confidence: float, reason: str,
            contested: bool = False, passes: int = 1, step_key: str = "") -> dict[str, Any]:
    return {
        "src": item["src"], "syscall": item["syscall"], "dst": item["dst"],
        "src_label": item.get("src_label"), "dst_label": item.get("dst_label"),
        "instances": item.get("instances"), "bytes": item.get("bytes"),
        "t0": item.get("t0"), "t1": item.get("t1"),
        "event_ids": item.get("event_ids") or [],
        "is_relevant": relevant, "confidence": confidence, "reason": reason,
        "judged": True, "verdict_id": item.get("id"), "passes": passes, "contested": contested,
        "step_key": step_key or item.get("step_key") or "",
    }


def verify(
    model: Any,
    items: list[dict[str, Any]],
    first: dict[str, Any],
    *,
    metas: dict[str, dict[str, Any]],
    poi_t0: Any,
    min_confidence: float,
    budget: Any,
    log: Any = print,
) -> dict[str, Any]:
    """对第一轮结论做复核并合并成最终结论（确认 / 排除 / 未判定）。

    `first` 是第 3 层 `judge_first_pass` 的返回值。返回的 `calls` 只统计本层自己发出的调用
    （复核一次算一次；第一轮的调用由编排器累加）。
    """
    v1: dict[str, dict[str, Any]] = first.get("verdicts") or {}
    invalid1 = int(first.get("invalid") or 0)

    targets = select_targets(items, v1, min_confidence)

    v2: dict[str, dict[str, Any]] = {}
    invalid2 = 0
    n_calls = 0
    if targets:
        # 复核清单**倒序**送（简单的对抗去偏），编号沿用第一轮（不得重新编号）
        refute_listing = render(list(reversed(targets)), metas, poi_t0)
        # 记账节点沿用 "judge"（与旧实现一致：两轮调用都记在同一个节点名下）
        config = {"callbacks": [BudgetCallback(budget, node="judge")]}
        result2 = call_json(model, REFUTE_SYSTEM, refute_listing, config=config, role="refute")
        n_calls += 1
        if result2.get("_raw_ok", True):
            v2, invalid2 = parse_verdicts(result2, {item["id"] for item in targets})
        else:
            log(f"[judge] 二次复核降级：{result2.get('_error')}")

    confirmed: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    unjudged: list[dict[str, Any]] = []
    n_contested = n_recovered = 0
    for item in items:
        vid = item["id"]
        step_key = str(item.get("step_key") or "")
        first_v, second = v1.get(vid), v2.get(vid)
        if first_v is None and second is None:
            unjudged.append({**item, "reason": "两轮判定都没有给出可解析的结论（id 缺失或非法）"})
            continue
        if first_v is not None and second is not None:
            relevant = bool(first_v.get("is_relevant")) or bool(second.get("is_relevant"))
            confidence = min(conf(first_v), conf(second))
            contested = bool(first_v.get("is_relevant")) != bool(second.get("is_relevant"))
            reason = f"①{short(first_v.get('reason'))} ②{short(second.get('reason'))}"
            passes = 2
        else:
            single = first_v if first_v is not None else second
            relevant = bool(single.get("is_relevant"))
            confidence = conf(single)
            contested = False
            reason = short(single.get("reason"))
            passes = 1
            if second is not None:
                n_recovered += 1     # 第一轮漏 id、第二轮救回来
        if contested:
            n_contested += 1
        record = _record(item, relevant=relevant, confidence=confidence, reason=reason,
                         contested=contested, passes=passes, step_key=step_key)
        # 争议边**默认保留**（取低值 + 争议标记）：第二轮的对抗措辞只能降置信度，
        # 不能单独把一条真边挤下阈值——实测场景 1 正是这样丢了 3 条真边。
        if relevant and (confidence >= min_confidence or contested):
            confirmed.append(record)
        else:
            excluded.append(record)

    trace = {
        "step_keys": sorted({str(item.get("step_key") or "") for item in items}),
        "judged": len(items), "confirmed": len(confirmed), "excluded": len(excluded),
        "unjudged": len(unjudged), "pass2_targets": len(targets), "recovered": n_recovered,
        "contested": n_contested, "invalid_ids": invalid1 + invalid2,
    }
    return {"confirmed": confirmed, "excluded": excluded, "unjudged": unjudged,
            "calls": n_calls, "trace": trace}


# --------------------------------------------------------------------------- #
# 判定明细日志（审计旁路，不进报告状态）
# --------------------------------------------------------------------------- #

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


def verdict_log_record(record: dict[str, Any], *, batch: int) -> dict[str, Any]:
    return {
        "id": record.get("verdict_id"),
        "triple": list(triple(record)),
        "relevant": record.get("is_relevant"),
        "confidence": round(float(record.get("confidence") or 0.0), 3),
        "contested": bool(record.get("contested")),
        "passes": record.get("passes"),
        "step_key": record.get("step_key"),
        "batch": batch,
        "reason": short(record.get("reason"), 120),
    }
