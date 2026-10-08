"""第 1 层：输出期过滤（一次遍历里同时判"实例范围"与"例行活动"）。

两个判据、一个执行时机（闭包之后、折叠之前），因此放在一个模块、一次遍历里：

- **实例范围**：这条候选边，是不是"做出终点事件的那一次执行"里的动作？从终点事件的实例出发，
  沿派生父进程与"谁写了它读取的对象"往上走，再并入会话上下文与只沿绝对路径的指令补段，迭代到不动点。
- **例行活动**：这条边是不是“整类例行活动”？判据是边实例级的：属主类别 + 对象类别 + 方向
  （读 / 写），或系统调用 + 对象类别（条目在 `rules/filters.json` 的 output 段）。另一端是进程的边
  （派生边）不参与：进程不是对象，不按文件路径归类。加条目要能回答“换一个没见过的攻击为什么
  它仍然成立”，并把压缩量与标注流失量分开量。

两者都逐行独立判定、互不依赖，因此合成一次遍历与分两次做结果逐行相同，计数也相同（范围剔掉的
实例不参与例行活动的逐类计数）。两条硬口径：

- **终点事件不受规则约束**：终点事件的实例（按事件编号认定）两步都不判，永远交给模型判定——
  与闭包种子的口径一致（`closure.py` 里种子明确不判规则）。豁免的是**实例**，不是整个内容三元组：
  同一个内容三元组的其它实例照常参与判定。
- **失败即保留**：查不出属主的行不剔除（两步都不判）。

逐类计数进 `stats`（`scope` 与 `routine` 分开放，报告的字段不变）。
"""

from __future__ import annotations

import bisect
import collections
from typing import Any, Callable, Optional

from ...core import edge_rules, graph_facts, vertices
from ...core.vertices import num_prefix


def no_handoff(obj: str) -> bool:
    """这个对象不做"执行实例之间的产物交接"追溯：系统提供的文件、非交付通道。"""
    return vertices.no_handoff(obj)


def _event_id(row: dict[str, Any]) -> int:
    """这一行的事件编号；取不到（缺字段、空值、非整数）返回 -1（绝不会与真实编号相撞）。"""
    try:
        return int(row.get("event_id"))
    except (TypeError, ValueError):
        return -1


def _poi_event_ids(poi_rows: list[dict[str, Any]]) -> set[int]:
    """终点事件的实例编号集合：这些实例不受任何规则约束（与闭包种子同一口径）。"""
    return {eid for eid in (_event_id(row) for row in poi_rows) if eid >= 0}


def _build_maps(rows: list[dict[str, Any]]):
    """从候选边行建：派生关系、读取事件（带时刻）、写入事件（带时刻）、同进程号索引。"""
    parent_of: dict[str, set[str]] = collections.defaultdict(set)
    children_of: dict[str, set[str]] = collections.defaultdict(set)
    reads_by_pid: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    writes_by_obj: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    all_pids: set[str] = set()
    for row in rows:
        pid = str(row.get("process_id") or "")
        rel = str(row.get("rel") or "")
        obj = str(row.get("other") or "")
        st = int(row.get("starttime") or 0)
        et = int(row.get("endtime") or st)
        if pid:
            all_pids.add(pid)
        if graph_facts.is_derivation(rel):
            parent = str(row.get("other_process_id") or "")
            if parent and pid:
                parent_of[pid].add(parent)
                children_of[parent].add(pid)
                all_pids.add(parent)
        elif rel in graph_facts.CONSUMER_RELS:
            if pid and obj:
                reads_by_pid[pid].append((obj, st, et))
        elif rel in graph_facts.PRODUCER_RELS:
            if pid and obj:
                writes_by_obj[obj].append((pid, st, et))
    by_num: dict[str, set[str]] = collections.defaultdict(set)
    for pid in all_pids:
        by_num[num_prefix(pid)].add(pid)
    return parent_of, children_of, reads_by_pid, writes_by_obj, by_num


def _build_scope(rows: list[dict[str, Any]], poi_rows: list[dict[str, Any]]
                 ) -> tuple[set[str], dict[str, int]]:
    """算"做出终点事件的那一次执行"的进程实例集合；返回（集合, 三段新增计数）。"""
    parent_of, children_of, reads_by_pid, writes_by_obj, by_num = _build_maps(rows)
    scope: set[str] = {str(r.get("process_id") or "") for r in poi_rows if r.get("process_id")}
    scope.discard("")
    phase_added = {"phase1": 0, "phase2": 0, "phase3": 0}

    # 每个对象的写入者按（结束时刻, 写入者）排一次序："读取之前最近一次写入"用二分，
    # "全部写入者"用一个集合（不含时间条件的那一段直接用）。
    writes_sorted: dict[str, list[tuple[int, str]]] = {}
    ends_by_obj: dict[str, list[int]] = {}
    writers_all: dict[str, set[str]] = {}
    for obj, items in writes_by_obj.items():
        items = [w for w in items if w[0]]
        writes_sorted[obj] = sorted((w[2], w[0]) for w in items)
        ends_by_obj[obj] = [end for end, _pid in writes_sorted[obj]]
        writers_all[obj] = {pid for _end, pid in writes_sorted[obj]}

    def push(pid: str, frontier: list[str]) -> None:
        """把一个进程放进范围并推进工作清单（已在范围里就不动）。"""
        if pid and pid not in scope:
            scope.add(pid)
            frontier.append(pid)

    def add_ancestors(cur: str, frontier: list[str]) -> None:
        """把派生父进程补进范围（它们同样要被处理）。"""
        for parent in parent_of.get(cur, ()):
            push(parent, frontier)

    def latest_writer(obj: str, st: int, et: int) -> str:
        """读取之前最近一次写入的写入者（先按读取开始时刻，找不到再按结束时刻）；确定性取最大时刻。"""
        ends = ends_by_obj.get(obj)
        if not ends:
            return ""
        index = bisect.bisect_right(ends, st)
        if index == 0:
            index = bisect.bisect_right(ends, et)
        return writes_sorted[obj][index - 1][1] if index else ""

    # 第 1 段：产出链（可交接的对象跟全部写入者）
    frontier = list(scope)
    while frontier:
        cur = frontier.pop()
        add_ancestors(cur, frontier)
        for obj, st, et in reads_by_pid.get(cur, ()):
            if no_handoff(obj):
                continue
            for writer in writers_all.get(obj, ()):
                push(writer, frontier)
    phase_added["phase1"] = len(scope)
    # 第 2 段：会话上下文（不再触发交接，也不加祖先）
    frontier = list(scope)
    while frontier:
        cur = frontier.pop()
        if vertices.process_class(cur) != "resident":
            for child in children_of.get(cur, ()):
                push(child, frontier)
        for same in by_num.get(num_prefix(cur), ()):
            push(same, frontier)
    phase_added["phase2"] = len(scope) - phase_added["phase1"]
    # 第 3 段：只沿绝对路径且可交接的对象补一轮交接（这一轮只跟最近写入者）
    frontier = list(scope)
    while frontier:
        cur = frontier.pop()
        add_ancestors(cur, frontier)
        for obj, st, et in reads_by_pid.get(cur, ()):
            if no_handoff(obj) or not obj.startswith("/"):
                continue
            push(latest_writer(obj, st, et), frontier)
    phase_added["phase3"] = len(scope) - phase_added["phase1"] - phase_added["phase2"]
    return scope, phase_added


def filter_output_rows(rows: list[dict[str, Any]], poi_rows: list[dict[str, Any]], *,
                       enabled: bool = True,
                       log: Optional[Callable[[str], None]] = None,
                       ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """输出期过滤：一次遍历里判实例范围与例行活动；返回（保留的行, 计数）。

    `enabled=False`（对照实验关掉整层）时原样返回，两个统计都只写 `enabled: False`。

    每个统计里 `rows_before` 是这一步的输入、`rows_after` 是这一步之后剩下的、`dropped` 是这一步
    剔掉的（输入 = 剩下 + 剔掉）；`poi_kept`（终点事件的实例数）与 `owner_missing`（查不出属主
    而保留的行数）两步都不判，单独计。
    """
    if not enabled:
        return rows, {"scope": {"enabled": False}, "routine": {"enabled": False}}

    rows_before = len(rows)
    scope_stats: dict[str, Any] = {"enabled": False, "rows_before": rows_before,
                                   "rows_after": rows_before, "dropped": 0, "scope_processes": 0,
                                   "poi_kept": 0, "owner_missing": 0}
    routine_stats: dict[str, Any] = {"enabled": False, "rows_before": 0, "rows_after": 0,
                                     "dropped": 0, "by_label": {},
                                     "poi_kept": 0, "owner_missing": 0}
    if not rows:
        return rows, {"scope": scope_stats, "routine": routine_stats}

    poi_events = _poi_event_ids(poi_rows)
    scope: Optional[set[str]] = None
    if poi_rows:
        scope, phase_added = _build_scope(rows, poi_rows)
        scope_stats = {"enabled": True, "rows_before": rows_before, "rows_after": rows_before,
                       "dropped": 0, "scope_processes": len(scope), "phase_added": phase_added,
                       "poi_kept": 0, "owner_missing": 0}

    kept: list[dict[str, Any]] = []
    scope_dropped = 0
    poi_kept = 0
    owner_missing = 0
    routine_dropped: collections.Counter[str] = collections.Counter()
    for row in rows:
        if _event_id(row) in poi_events:
            # 终点事件不受规则约束（与闭包种子同一口径）：两步都不判，永远交给模型
            poi_kept += 1
            kept.append(row)
            continue
        pid = str(row.get("process_id") or "")
        if not pid:
            # 查不出属主：失败即保留（与实例范围同口径，两步都不判）
            owner_missing += 1
            kept.append(row)
            continue
        if scope is not None and pid not in scope:
            scope_dropped += 1
            continue
        code = edge_rules.output_drop_code(pid, str(row.get("other") or ""),
                                           str(row.get("syscall") or ""),
                                           str(row.get("rel") or ""))
        if code:
            routine_dropped[code] += 1
            continue
        kept.append(row)

    judgeable = rows_before - poi_kept - owner_missing   # 真正进两步判定的行数
    after_scope = judgeable - scope_dropped              # 过实例范围之后、进例行判定的行数
    scope_stats.update({"rows_judged": judgeable, "rows_after": after_scope,
                        "dropped": scope_dropped, "poi_kept": poi_kept,
                        "owner_missing": owner_missing})
    routine_dropped_total = sum(routine_dropped.values())
    routine_stats = {"enabled": after_scope > 0, "rows_before": after_scope,
                     "rows_after": after_scope - routine_dropped_total,
                     "dropped": routine_dropped_total,
                     "by_label": dict(sorted(routine_dropped.items())),
                     "poi_kept": poi_kept, "owner_missing": owner_missing}

    if log:
        if scope is not None:
            phase = scope_stats.get("phase_added") or {}
            log(f"[scope] 实例/会话范围：进程实例 {len(scope)} 个"
                f"（产出链 {phase.get('phase1', 0)} / 会话上下文 +{phase.get('phase2', 0)} / "
                f"指令补段 +{phase.get('phase3', 0)}）；"
                f"进判定的行 {judgeable} → {after_scope}（剔掉 {scope_dropped} 条不在范围内的实例）")
        log(f"[routine] 例行活动剔除：{after_scope} → {routine_stats['rows_after']}"
            f"（剔掉 {routine_dropped_total} 条；逐类：{routine_stats['by_label']}）")
        if poi_kept or owner_missing:
            log(f"[exempt] 两步都不判、直接保留：终点事件实例 {poi_kept} 条 / "
                f"查不出属主 {owner_missing} 条")
    return kept, {"scope": scope_stats, "routine": routine_stats}
