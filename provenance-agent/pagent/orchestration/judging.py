"""判定驱动（编排）：第 2 层装批 → 第 3 层第一轮 → 第 4 层复核与合并；含二分拆批重试。

拆批重试是**跨层的错误处理**，所以放在编排层：整批第一轮调用失败时把批一分为二，各自重新走
第 3、4 层；拆到单条仍失败才记未判定（不静默丢，也不误当排除）。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

from ..contracts import short, triple
from ..core import settings
from ..core.trace import trace_event
from ..layers import l2_prepare as l2
from ..layers import l3_semantic as l3
from ..layers import l4_verify as l4
from .register import register_conclusions

if TYPE_CHECKING:
    from ..app import Deps


def judge_all(deps: "Deps") -> dict[str, Any]:
    """把所有候选边打包成大批，丢进一个并发池判定；返回合并后的结论与统计。"""
    inv = deps.record
    to_judge: list[dict[str, Any]] = []
    for edge in inv.edges.values():
        reason = l2.prefilter_reason(edge)
        if reason:
            inv.excluded[triple(edge)] = {
                **edge, "is_relevant": False, "confidence": 0.0, "judged": True, "prefiltered": True,
                "reason": f"确定性粗筛（{reason}；该模式在六个场景的 GT 里零命中）",
            }
        else:
            to_judge.append(edge)

    batches = l2.make_batches(to_judge, settings.judge_batch())
    if inv.excluded:
        deps.log(f"[judge] {len(inv.edges)} 条候选里 {len(inv.excluded)} 条命中系统例行规则，直接判无关（不进 LLM）")
    deps.log(f"[judge] {len(to_judge)} 条待判定 → {len(batches)} 批（每批 ≤{settings.judge_batch()} 条），"
             f"并发 {settings.max_concurrency()}")

    metas = inv.steps
    max_calls = settings.max_llm_calls()
    verdict_path = settings.LOG_DIR / f"verdicts-{deps.record.run_id}.jsonl"
    stats = {"batches": len(batches), "calls": 0, "unjudged_batches": 0}
    t0 = time.time()

    def work(index: int, batch: list[Any]) -> dict[str, Any]:
        if deps.budget.calls >= max_calls:
            # 预算熔断：整批显式记成未判定（不静默丢，也不误当排除）
            return {"confirmed": [], "excluded": [],
                    "unjudged": [{**edge, "reason": "模型调用上限耗尽，未判定"}
                                 for _, edges in batch for edge in edges],
                    "calls": 0, "trace": {"skipped": True}}
        return judge_batch(deps.model, batch, metas=metas, poi_t0=inv.poi_t0,
                           min_confidence=deps.min_confidence, budget=deps.budget, log=deps.log)

    with ThreadPoolExecutor(max_workers=settings.max_concurrency()) as pool:
        futures = {pool.submit(work, i, batch): i for i, batch in enumerate(batches)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - 单批异常不能让整轮崩
                deps.log(f"[judge] 批 {index + 1} 异常：{type(exc).__name__}: {exc}")
                stats["unjudged_batches"] += 1
                continue
            stats["calls"] += int(result.get("calls") or 0)
            if result.get("trace", {}).get("skipped"):
                stats["unjudged_batches"] += 1
            for edge in result["confirmed"]:
                inv.confirmed[triple(edge)] = edge
            for edge in result["excluded"]:
                inv.excluded[triple(edge)] = edge
            for edge in result["unjudged"]:
                inv.unjudged[triple(edge)] = edge
            l4.log_verdicts(verdict_path, [
                l4.verdict_log_record(e, batch=index)
                for e in (result["confirmed"] + result["excluded"] + result["unjudged"])
            ])
            if result["unjudged"]:
                sample = "；".join(f"{e['src']} --{e['syscall']}--> {e['dst']}"
                                   for e in result["unjudged"][:3])
                inv.add_gap(f"第 {index + 1} 批有 {len(result['unjudged'])} 条候选边未完成判定（网关失败/输出不可解析）",
                            f"重跑该批并重新判定：{sample}")
            trace = result.get("trace") or {}
            if trace:
                deps.log(f"[judge] 批 {index + 1}/{len(batches)}（{len(trace.get('step_keys') or [])} 个步骤）："
                         f"判 {trace.get('judged')} → 确认 {trace.get('confirmed')} / 排除 {trace.get('excluded')} / "
                         f"未判定 {trace.get('unjudged')}；复核 {trace.get('pass2_targets')}"
                         f"（救回 {trace.get('recovered')}，争议 {trace.get('contested')}）")
                trace_event(deps.trace, "judge_batch", batch=index, **trace)

    stats["seconds"] = round(time.time() - t0, 1)
    deps.log(f"[judge] 判定完成：确认 {len(inv.confirmed)} / 排除 {len(inv.excluded)} / "
             f"未判定 {len(inv.unjudged)}；{stats['calls']} 次调用，{stats['seconds']}s")
    trace_event(deps.trace, "judge", batches=len(batches), edges=len(to_judge), calls=stats["calls"],
                seconds=stats["seconds"], confirmed=len(inv.confirmed), excluded=len(inv.excluded),
                unjudged=len(inv.unjudged))

    # 登记进记录表（内存）：实体 + in-step / supports / refutes
    register_conclusions(inv)
    return stats


def judge_batch(model: Any, batch: list[tuple[str, list[dict[str, Any]]]], *,
                metas: dict[str, dict[str, Any]], poi_t0: Any, min_confidence: float,
                budget: Any, log: Any = print) -> dict[str, Any]:
    """判一批（可含多个步骤）：第 3 层第一轮 → 第 4 层复核与合并。

    整批第一轮调用失败时二分拆批重试；拆到单条仍失败才记 `unjudged`。
    """
    items = l2.index_items(batch)
    if not items:
        return {"confirmed": [], "excluded": [], "unjudged": [], "calls": 0, "trace": {}}
    listing = l2.render(items, metas, poi_t0)
    first = l3.judge_first_pass(model, items, listing, budget=budget)
    if not first.get("ok"):
        return _split_and_retry(model, batch, metas=metas, poi_t0=poi_t0,
                                min_confidence=min_confidence, budget=budget, log=log,
                                error=str(first.get("error") or "未知错误"))
    result = l4.verify(model, items, first, metas=metas, poi_t0=poi_t0,
                       min_confidence=min_confidence, budget=budget, log=log)
    result["calls"] = int(result.get("calls") or 0) + int(first.get("calls") or 0)
    return result


def _split_and_retry(model: Any, batch: list[tuple[str, list[dict[str, Any]]]], *, metas: Any,
                     poi_t0: Any, min_confidence: float, budget: Any, log: Any,
                     error: str) -> dict[str, Any]:
    """整批调用失败 → 二分拆批重试（大批判定顶到网关超时/限流时靠这一步兜底）。"""
    total = sum(len(edges) for _, edges in batch)
    if total <= 1:
        only = batch[0][1][0]
        item = {**only, "id": "E001"}
        log(f"[judge] 单条边判定失败，记未判定：{error[:80]}")
        return {"confirmed": [], "excluded": [],
                "unjudged": [{**item, "reason": f"LLM 调用失败：{short(error, 80)}"}],
                "calls": 1, "trace": {"failed": 1, "error": short(error, 120)}}

    flat = [(key, edge) for key, edges in batch for edge in edges]
    half = len(flat) // 2
    left, right = _regroup(flat[:half]), _regroup(flat[half:])
    log(f"[judge] 一批 {total} 条调用失败（{error[:60]}），拆成 {half}+{len(flat) - half} 重试")
    out: dict[str, Any] = {"confirmed": [], "excluded": [], "unjudged": [], "calls": 0, "trace": {}}
    for part in (left, right):
        sub = judge_batch(model, part, metas=metas, poi_t0=poi_t0, min_confidence=min_confidence,
                          budget=budget, log=log)
        for key in ("confirmed", "excluded", "unjudged"):
            out[key].extend(sub[key])
        out["calls"] += sub["calls"]
    return out


def _regroup(flat: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, list[dict[str, Any]]]]:
    """把 (步骤键, 边) 列表重新按步骤分组（保持顺序）。"""
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for key, edge in flat:
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(edge)
    return [(key, groups[key]) for key in order]
