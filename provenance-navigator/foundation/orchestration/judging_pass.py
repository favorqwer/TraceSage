"""判定驱动（编排）：单轮束级判定推进（navigator 的慢速通道直接调用它）。

流程：
1. 把送进来的候选三元组打成五级束（`l2_judge.bundles`）；第 1 级按风险优先调度
   （网络边、离锚点近、含写边优先），其余各级按确定性结构键排序（保证可复现）；
2. 逐级推进：每级按参数切批、并发投递模型评审（整批通信、四值判定）；
3. 结构闸门限制删边权限：空拆、扇出、类一致性、结构凭证及叶子规则，未通过者一律保留。

职责边界：本文件只负责「一轮推进」。送哪些三元组进来、判定结论怎么组装成报告，
由调用方决定（navigator 见 `judge/client.py`：只送符号通道未确认的歧义边）。
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ..contracts import short
from ..core import settings
from ..layers import l2_judge as l2

if TYPE_CHECKING:
    from ..deps import Deps


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


