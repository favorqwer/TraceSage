"""判定驱动（编排）：逐波推进 → 按“是否相关”定结论。

1. 按「离终点几跳」把候选边分波（一跳一波）；
2. 逐波调用模型：每次请求带任务说明、**调查状态摘要**（第 2 层滚动上下文）、本波全部边，
   每条边下面缩进列出**相关边**（上层顶点上已判过的边及其结论 + 同一对象上时间相邻的边，
   合并成一块、同一条边只出现一次）；波内按批大小切批、
   同一波的所有批共用同一份冻结上下文并发投递；
3. 每波结束后由纯代码更新状态（顶点状态、已确认链、工作面、计数）；
4. 全部波跑完后由纯代码定结论：判为相关 → 确认，否则排除；没给结论 → 未判定。
   置信度不参与结论：模型多写的字段一律忽略（不进日志、不进报告、不参与任何判断）。

失败处理：一批调用失败就整批重发（一批最多尝试 `judge.wave_attempts` 次，默认 2）；
仍失败则该批全部边记为缺失，未判定（不静默丢、不误当排除）。**没有第二轮复核**。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from ..contracts import short, triple
from ..core import settings
from ..core.trace import trace_event
from ..layers import l2_judge as l2
from .register import register_conclusions

if TYPE_CHECKING:
    from ..app import Deps


def judge_all(deps: "Deps") -> dict[str, Any]:
    """把所有候选边逐波判完，按"是否相关"定结论，返回统计。

    候选表就是交给模型的清单：五条结构式规则在**第 1 层遍历期取边时**已经生效，这里不再复核；
    **终点事件不受规则约束**，永远交给模型判定。已经进过排除表的边不重复判定。
    """
    inv = deps.record
    to_judge = [edge for key, edge in inv.edges.items() if key not in inv.excluded]
    view = l2.build_view_index(to_judge)
    header = l2.build_task_header(inv.poi_rows)
    verdict_path = settings.LOG_DIR / f"verdicts-{deps.record.run_id}.jsonl"

    v1: dict[str, dict[str, Any]] = {}
    failures: dict[tuple[str, str, str], str] = {}
    stats: dict[str, Any] = {
        "edges": len(to_judge), "calls": 0, "seconds": 0.0,
        "waves": 0, "wave_details": [], "unjudged_waves": 0,
    }
    if header:
        deps.log(f"[judge] 任务说明 {len(header)} 字符（目标事件 + 时间原点 + 清单口径，所有波共用）")

    t0 = time.time()
    items_all, group_of = _run_waves(deps, to_judge, header=header, view=view, stats=stats,
                                     v1=v1, failures=failures)

    confirmed, excluded, unjudged = l2.decide_verdicts(items_all, v1)
    for item in unjudged:
        reason = failures.get(triple(item))
        if reason:
            item["reason"] = reason

    # ---- 公共尾部：写结论、审计日志、缺口、统计 ----
    for edge in confirmed:
        inv.confirmed[triple(edge)] = edge
    for edge in excluded:
        inv.excluded[triple(edge)] = edge
    for edge in unjudged:
        inv.unjudged[triple(edge)] = edge
    records = confirmed + excluded + unjudged
    l2.log_verdicts(verdict_path, [
        l2.verdict_log_record(edge, wave=int(group_of.get(l2.verdict_id(edge), -1)))
        for edge in records
    ])
    stats["seconds"] = round(time.time() - t0, 1)
    deps.log(f"[judge] 判定完成：确认 {len(inv.confirmed)} / 排除 {len(inv.excluded)} / "
             f"未判定 {len(inv.unjudged)}；{stats['calls']} 次调用，{stats['seconds']}s")

    if unjudged:
        sample = "；".join(f"{e['src']} --{e['syscall']}--> {e['dst']}"
                          for e in unjudged[:settings.audit_sample_n()])
        inv.add_gap(f"{len(unjudged)} 条候选边没有完成判定（网关失败/输出不可解析）",
                    f"重跑并重新判定：{sample}")
    if stats["unjudged_waves"]:
        inv.add_gap(f"有 {stats['unjudged_waves']} 波调用失败（已整波重试）",
                    "看判定日志里失败波次的明细（trace / 判定记录）")

    trace_event(deps.trace, "judge", calls=stats["calls"],
                seconds=stats["seconds"], confirmed=len(inv.confirmed),
                excluded=len(inv.excluded), unjudged=len(inv.unjudged), waves=stats["waves"])
    register_conclusions(inv)
    return stats


# --------------------------------------------------------------------------- #
# 逐波路径
# --------------------------------------------------------------------------- #

def _render_wave(l2: Any, items: list[dict[str, Any]], inv: Any, header: str, view: Any,
                 summary: str, upstream: dict[str, list[dict[str, Any]]], state: Any,
                 wave: int, wave_total: int, wave_dist: int) -> str:
    """渲染一批的文本（完整上下文，不做任何压缩）。

    `wave` / `wave_total` / `wave_dist` 是这批在调查里的位置，只进本批标题。
    """
    return l2.render(items, inv.process_context, inv.poi_t0, header=header, view=view,
                     state_summary=summary, upstream=upstream, verdicts=state.by_triple,
                     wave=wave, wave_total=wave_total, wave_dist=wave_dist)


def _run_waves(deps: "Deps", to_judge: list[dict[str, Any]], *, header: str, view: Any,
               stats: dict[str, Any], v1: dict[str, dict[str, Any]],
               failures: dict[tuple[str, str, str], str],
               ) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """逐波判定：波内按条数上限切批、共用同一份冻结上下文并发投递，波间更新调查状态。

    返回（扁平条目表, 编号到波号）。同一波的多个批只共享上下文，不互相等待；整波判完才更新状态，
    所以第 1 层明细与状态摘要对同一波的所有批是同一份。
    """
    inv = deps.record
    waves, items_all, wave_of = l2.index_waves(l2.make_waves(to_judge))
    state = l2.JudgeState()
    stats["waves"] = len(waves)
    chunk_size = max(1, settings.judge_batch())
    deps.log(f"[judge] {len(to_judge)} 条待判定 → {len(waves)} 波；波内按 {chunk_size} 条切批、"
             f"共用同一份冻结上下文并发投递；每批最多尝试 {settings.wave_attempts()} 次，"
             f"并发 {settings.max_concurrency()}")

    def run_chunk(chunk, summary, upstream, wave_no, wave_total, wave_dist):
        """一批：渲染完整上下文 → 调模型（一批最多尝试几次）→ 只收结论。"""
        listing = _render_wave(l2, chunk, inv, header, view, summary, upstream, state,
                               wave_no, wave_total, wave_dist)
        result: dict[str, Any] | None = None
        calls = 0
        for attempt in range(settings.wave_attempts()):
            result = l2.judge_first_pass(deps.model, chunk, listing, budget=deps.budget)
            calls += 1
            if result.get("ok"):
                break
            deps.log(f"[judge] 一批调用失败（第 {attempt + 1}/{settings.wave_attempts()} 次，"
                     f"{len(chunk)} 条 / {len(listing)} 字符）：{short(result.get('error'))}")
        ok = bool(result and result.get("ok"))
        verdicts = (result or {}).get("verdicts") or {}
        if ok:
            failed = [{"triple": triple(item),
                       "reason": "该批输出缺编号（模型没给出这条边的结论）"}
                      for item in chunk if item["id"] not in verdicts]
        else:
            reason = f"整批调用失败：{short((result or {}).get('error'))}"
            failed = [{"triple": triple(item), "reason": reason} for item in chunk]
        return {"verdicts": verdicts, "failed": failed, "calls": calls, "chars": len(listing),
                "invalid": int((result or {}).get("invalid") or 0), "ok": ok}

    with ThreadPoolExecutor(max_workers=settings.max_concurrency()) as pool:
        for wave in waves:
            index = int(wave["wave"])
            items = wave["items"]
            upstream = {item["id"]: state.upstream(item, settings.upstream_limit())
                        for item in items}
            summary = state.build_summary(chain_limit=settings.state_chain_limit(),
                                          sessions=inv.session_index)
            chunks = l2.chunk_wave(items, chunk_size)
            started = time.time()
            futures = [pool.submit(run_chunk, chunk, summary, upstream, index + 1, len(waves),
                                   int(wave["dist"])) for chunk in chunks]
            results: list[dict[str, Any]] = []
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 - 单批异常不能让整波崩
                    deps.log(f"[judge] 第 {index + 1} 波的一批异常：{type(exc).__name__}: {exc}")
                    results.append({"verdicts": {}, "failed": [], "calls": 0, "chars": 0,
                                    "invalid": 0, "ok": False})

            verdicts: dict[str, dict[str, Any]] = {}
            calls = chars_total = chars_max = invalid = failed_chunks = 0
            ok_all = True
            for result in results:
                calls += int(result.get("calls") or 0)
                chars_total += int(result.get("chars") or 0)
                chars_max = max(chars_max, int(result.get("chars") or 0))
                invalid += int(result.get("invalid") or 0)
                verdicts.update(result.get("verdicts") or {})
                if not result.get("ok"):
                    ok_all = False
                    failed_chunks += 1
                for failed in result.get("failed") or []:
                    failures[tuple(failed.get("triple") or ())] = str(failed.get("reason") or "未判定")
            for item in items:
                if item["id"] not in verdicts:
                    failures.setdefault(triple(item), "该波没有给出这条边的结论")

            v1.update(verdicts)
            registered = state.register(items, verdicts, index)
            stats["calls"] += calls
            if not ok_all:
                stats["unjudged_waves"] += 1
            details = {
                "wave": index, "dist": int(wave["dist"]), "edges": len(items),
                "chunks": len(chunks), "chars": chars_total, "chars_max": chars_max,
                "state_chars": len(summary),
                "seconds": round(time.time() - started, 1),
                "confirmed": registered["confirmed"], "excluded": registered["excluded"],
                "missing": registered["missing"], "invalid": invalid, "ok": ok_all,
                "failed_chunks": failed_chunks,
            }
            stats["wave_details"].append(details)
            deps.log(f"[judge] 第 {index + 1}/{len(waves)} 波（离终点 {details['dist']} 跳）："
                     f"判 {details['edges']} 条（{details['chunks']} 批）→ 确认 {details['confirmed']} / "
                     f"排除 {details['excluded']} / 缺失 {details['missing']}；输入合计 {details['chars']} "
                     f"字符（单批最大 {chars_max}，摘要 {details['state_chars']}），{details['seconds']}s")
            trace_event(deps.trace, "judge_wave", **details)
    return items_all, wave_of
