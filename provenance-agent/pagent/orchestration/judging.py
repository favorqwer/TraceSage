"""判定驱动（编排）：逐级细分推进 → 束级四值判定 → 四道结构闸门 → 因果拓扑桥接。

流程：
1. 把候选表打成五级束（l2_judge.bundles）；第 1 级按风险优先调度（网络边、离锚点近、含写边优先），
   其余各级按确定性结构键排序（保证可复现）；
2. 逐级推进：每级按参数切批、并发投递模型评审（整批通信、四值判定）；
3. 结构闸门限制删边权限：空拆、扇出、类一致性、结构凭证及叶子规则，未通过者一律保留；
4. 因果拓扑桥接：模型评审完成后执行外部攻击源通信桥接与强因果双端实体闭环（零模型调用）；
5. 结果落盘与审计明细记录。
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING, Any

from ..contracts import short
from ..core import settings
from ..core.trace import trace_event
from ..layers import l2_judge as l2
from .register import register_conclusions

if TYPE_CHECKING:
    from ..app import Deps
    from .expand_closure import Prepared

_LOG_LOCK = threading.Lock()


def judge_all(deps: "Deps", prepared: "Prepared") -> dict[str, Any]:
    """编排第二层判定生命周期：逐级判定、锚点强制确认、拓扑桥接与指标沉淀。"""
    inv = deps.record
    t0 = time.time()
    program_of = l2.program_table(inv.process_context)
    keyer = l2.LevelKey(program_of)
    state = l2.BundleState(anchor=l2.anchor_facts(inv.poi_rows), program_of=program_of)

    stats: dict[str, Any] = {
        "candidates": len(inv.edges), "calls": 0, "seconds": 0.0, "levels": [], "passes": [],
        "guards": {"vacuous": 0, "fanout": {"bundles": 0, "edges": 0}, "hot": 0, "warrant": 0},
        "forward": {}, "cap_kept_edges": 0, "missing_bundles": 0, "unjudged_bundles": 0,
        "promoted_bridges": 0,
    }
    detail: list[dict[str, Any]] = []

    # 1. 执行束级逐级判定推进
    triples_first = set(inv.edges)
    first_pass = _judge_pass(
        deps, triples_first, keyer=keyer, state=state, inv=inv,
        stats=stats, detail=detail, pass_no=1, cap_calls=settings.bundle_cap_calls()
    )
    stats["passes"].append(first_pass)
    deps.log(f"[judge] 第一轮：{len(triples_first)} 条候选 → 已确认 "
             f"{sum(1 for o in inv.origin.values() if o == 'confirmed')} / 已排除 "
             f"{sum(1 for o in inv.origin.values() if o == 'excluded')}；"
             f"{first_pass['calls']} 次调用，{first_pass['seconds']}s")

    # 2. 未轮到判定的束默认全量保留（失败即展开原则）
    for key in inv.edges:
        if key not in inv.origin:
            inv.mark([key], "kept")
            stats["unjudged_bundles"] += 1

    # 3. 告警锚点事实强制确认：起点定位命中的终点事件属于客观事实
    _confirm_anchor_poi(inv)

    # 4. 因果拓扑桥接：外部恶意通信桥接 + 强因果双端实体闭环（零额外调用）
    promoted = l2.promote_causal_bridges(inv)
    stats["promoted_bridges"] = promoted
    if promoted > 0:
        deps.log(f"[judge] 因果拓扑桥接：自动提升 {promoted} 条强因果关联边到「已确认」")

    # 5. 结算与指标落盘
    inv.settle()
    stats["seconds"] = round(time.time() - t0, 1)
    stats["strict_confirmed"] = len(inv.confirmed)
    stats["strict_excluded"] = len(inv.excluded)
    stats["strict_kept"] = len(inv.kept)
    _write_detail(inv, detail)

    deps.log(f"[judge] 判定完成：已确认 {len(inv.confirmed)} / 已排除 {len(inv.excluded)} / "
             f"未排除但未确认 {len(inv.kept)}（合计候选 {len(inv.edges)}）；"
             f"{stats['calls']} 次调用，{stats['seconds']}s")
    trace_event(deps.trace, "judge", calls=stats["calls"], seconds=stats["seconds"],
                confirmed=len(inv.confirmed), excluded=len(inv.excluded), kept=len(inv.kept),
                levels=len(stats["levels"]))
    register_conclusions(inv)
    return stats


def _judge_pass(deps: "Deps", triples: set[Any], *, keyer: Any, state: Any,
                inv: Any, stats: dict[str, Any], detail: list[dict[str, Any]], pass_no: int,
                cap_calls: int) -> dict[str, Any]:
    """单轮判定推进：从第 1 级开始，对判为混杂的束逐级细化推进。"""
    started = time.time()
    levels = l2.build_levels(triples, inv.edges, keyer)
    key_of = l2.level_members(levels)
    last = len(levels) - 1
    scale_index = l2.build_scale_index(triples, inv.edges, keyer)
    ref_t = int(inv.poi_t0 or 0)
    parent_map: dict[Any, tuple] = {}
    frontier = _frontier_order(levels[0], inv.edges, ref_t)
    seq = 0
    calls_before = stats["calls"]
    level_stats: list[dict[str, Any]] = []

    def next_id() -> str:
        nonlocal seq
        seq += 1
        return f"B{seq:04d}"

    for level in range(len(levels)):
        if not frontier:
            break
        items = l2.build_items(frontier, level, levels, inv.edges, inv.process_context,
                               samples=settings.bundle_samples(), next_id=next_id,
                               parents=parent_map)
        level_name = l2.level_name(level)

        # 结构前置闸门：空拆检测与单条边扇出跳过
        vacuous = l2.vacuous_ids(items) if settings.vacuous_guard_enabled() else set()
        if vacuous:
            stats["guards"]["vacuous"] += len(vacuous)
            deps.log(f"    [vacuous] 空拆闸门：{len(vacuous)}/{len(items)} 个子束与上一级成员相同，直接归「未排除」")

        skipped: set[str] = set()
        ask_items = items
        if settings.fanout_guard_enabled():
            ask_items, skipped, fanout_edges = l2.fanout_split(items, vacuous, settings.bundle_fanout_min())
            if skipped:
                stats["guards"]["fanout"]["bundles"] += len(skipped)
                stats["guards"]["fanout"]["edges"] += fanout_edges
                deps.log(f"    [fanout] 扇出闸门：跳过 {len(skipped)}/{len(items)} 个拆分产生的单条边子束")

        # 切批与预算配额控制
        batches = [ask_items[i:i + settings.bundle_batch()]
                   for i in range(0, len(ask_items), settings.bundle_batch())]
        kept_by_cap: list[dict[str, Any]] = []
        if stats["calls"] + len(batches) > cap_calls:
            keep = max(0, cap_calls - stats["calls"])
            deps.log(f"    [cap] 调用上限 {cap_calls}；本层只判 {keep}/{len(batches)} 批，其余按保留处理")
            kept_by_cap = [item for batch in batches[keep:] for item in batch]
            batches = batches[:keep]

        deps.log(f"  L{level + 1} {level_name}：{len(items)} 个束 / {len(batches)} 批（第 {pass_no} 轮）")
        verdicts, batch_stats = l2.run_batches(
            deps, items, batches, inv, ref_t, level_name=level_name,
            scale_index=scale_index, aggregate=settings.aggregate_enabled(), state=state
        )
        stats["calls"] += batch_stats["calls"]
        stats["missing_bundles"] += batch_stats["missing"]

        # 结构后置闸门：类一致性约束与误杀凭证校验
        if settings.none_guard() == "hot":
            stats["guards"]["hot"] += l2.hot_guard(items, verdicts)
        warrant_facts: dict[str, dict[str, Any]] = {}
        if settings.warrant_guard_enabled():
            downgraded, warrant_facts = l2.warrant_guard(
                items, verdicts, lambda item: state.facts(item, inv.edges),
                set(settings.warrant_rules())
            )
            stats["guards"]["warrant"] += downgraded

        # 处理条目判定结论与来路沉淀
        counts: dict[str, int] = {}
        children: list[Any] = []
        cap_ids = {item["id"] for item in kept_by_cap}

        for item in items:
            v_info = _resolve_item_verdict(item, verdicts.get(item["id"]), vacuous, skipped, cap_ids,
                                           last == level, settings.bundle_fanout_min())
            verdict, reason, witnesses = v_info["verdict"], v_info["reason"], v_info["witnesses"]
            counts[verdict] = counts.get(verdict, 0) + 1

            note = {"verdict": verdict, "verdict_reason": short(reason)}
            for member in item["members"]:
                inv.edges[member].update(note)

            detail.append({
                "pass": pass_no, "level": level, "level_name": level_name, "id": item["id"],
                "size": item["size"], "verdict": verdict, "tier": l2.tier_of(verdict),
                "reason": short(reason), "witnesses": witnesses,
                "programs": item["programs"], "rels": item["rels"], "syscall": item["syscall"],
                "dirs": item["dirs"], "objects_n": item["objects_n"], "bytes": item["bytes"],
                "parent_bid": (item.get("parent") or {}).get("bid"),
                "sample": [list(t) for t in item["sample"][:4]],
                **({"warrant_facts": warrant_facts[item["id"]]} if item["id"] in warrant_facts else {}),
            })

            if verdict == "all":
                inv.mark(item["members"], "confirmed")
                state.note_confirmed(item, inv.edges)
            elif verdict == "none":
                inv.mark(item["members"], "excluded")
            elif verdict in ("mixed", "unknown", "missing"):
                if last == level:
                    inv.mark(item["members"], "kept")
                else:
                    for member in item["members"]:
                        child_key = key_of[level + 1][member]
                        children.append(child_key)
                        parent_map.setdefault(child_key, (item, verdict, reason))
            else:
                inv.mark(item["members"], "kept")

        level_stats.append({
            "level": level, "name": level_name, "bundles": len(items), "batches": len(batches),
            "verdicts": dict(sorted(counts.items())), "children": len(set(children)),
            "chars_max": batch_stats["chars_max"], "invalid": batch_stats["invalid"],
        })
        stats["levels"].append({"pass": pass_no, **level_stats[-1]})
        deps.log(f"    L{level + 1} 结论：{dict(sorted(counts.items()))}；"
                 f"拆出子束 {len(set(children))} 个；单批最大输入 {batch_stats['chars_max']} 字符")

        frontier = _frontier_order({key: levels[level + 1][key] for key in set(children)
                                    if level + 1 < len(levels)}, inv.edges, ref_t,
                                   risk=False) if children else []

    return {
        "pass": pass_no, "candidates": len(triples), "calls": stats["calls"] - calls_before,
        "levels": len(level_stats), "level_stats": level_stats,
        "seconds": round(time.time() - started, 1),
    }


def _resolve_item_verdict(item: dict[str, Any], row: dict[str, Any] | None,
                          vacuous: set[str], skipped: set[str], cap_ids: set[str],
                          last_level: bool, fanout_min: int) -> dict[str, Any]:
    """解析单束的有效结论、原因及闸门修饰。"""
    witnesses: dict[str, Any] = {}
    if item["id"] in vacuous:
        verdict, reason = "vacuous_kept", "（空拆闸门：与上一级成员相同、没有新信息，不重判）"
    elif item["id"] in skipped:
        verdict, reason = "skipped", "（扇出闸门：拆分产生的单条边子束，不判）"
    elif item["id"] in cap_ids:
        verdict, reason = "cap_kept", "（达到调用上限，按保留处理）"
    elif row is None:
        verdict, reason = "missing", "（模型没给这个束结论）"
    else:
        verdict = str(row.get("verdict") or "").lower()
        reason = str(row.get("reason") or "")
        witnesses = {k: row.get(k) for k in ("witness_relevant", "witness_irrelevant")}

    if (row or {}).get("_guard"):
        reason = f"（类一致性闸门：{row['_guard']}）" + reason
    if (row or {}).get("_warrant"):
        reason = f"（凭证闸门：{row['_warrant']}）" + reason
    if l2.is_leaf(item, verdict, last_level, fanout_min):
        verdict = "leaf_kept"
        reason = "（单条边无可拆，按未排除留）" + reason

    return {"verdict": verdict, "reason": reason, "witnesses": witnesses}


def _confirm_anchor_poi(inv: Any) -> None:
    """强制确认告警事实锚点事件。"""
    for row in inv.poi_rows:
        rel = str(row.get("rel") or "")
        sc = str(row.get("syscall") or "")
        owner = str(row.get("process_content") or "")
        other = str(row.get("other") or "")
        trip = (owner, sc, other) if rel in ("p2f", "p2n") else (other, sc, owner)
        if trip in inv.edges and inv.origin.get(trip) != "confirmed":
            inv.mark([trip], "confirmed")
            if trip in inv.edges:
                inv.edges[trip]["verdict_reason"] = "告警事实锚点（POI）"


def _frontier_order(bundles_at_level: dict[Any, list[Any]], edges: dict[Any, Any], ref_t: int,
                    *, risk: bool = True) -> list[Any]:
    """确定当前层级的待判束队列顺序（第 1 级支持风险分数调度，其余层级采用结构键）。"""
    keys = list(bundles_at_level)
    if risk and settings.risk_schedule_enabled():
        return sorted(keys, key=lambda key: _risk_key(bundles_at_level[key], edges, ref_t))
    return sorted(keys, key=lambda key: l2.bundles.sort_text(key))


def _risk_key(members: list[Any], edges: dict[Any, Any], ref_t: int) -> tuple:
    """计算束的风险排序元组（网络边优先、离锚点近优先、含写边优先）。"""
    records = [edges[t] for t in members]
    has_net = any(str(r.get("src_label") or "") == "Network"
                  or str(r.get("dst_label") or "") == "Network" for r in records)
    has_producer = any(set(r.get("rels") or ()) & set(("p2f", "p2n")) for r in records)
    min_dist = min(int(r.get("dist") or 0) for r in records)
    gap = max(0, int(ref_t) - max(int(r.get("t1") or 0) for r in records))
    return (0 if has_net else 1, min_dist, 0 if has_producer else 1, gap, -len(members))


def _write_detail(inv: Any, detail: list[dict[str, Any]]) -> None:
    """审计旁路写入判定明细日志。"""
    if not detail:
        return
    path = settings.LOG_DIR / f"bundles-{inv.run_id}.jsonl"
    try:
        with _LOG_LOCK:
            with open(path, "a", encoding="utf-8") as handle:
                for row in detail:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - 审计旁路故障不中断主流程
        pass
