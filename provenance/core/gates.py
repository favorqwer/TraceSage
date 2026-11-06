"""束先验结构闸门与状态机。

包含：
- 锚点事实解析 (anchor_facts)
- 空拆闸门 (vacuous_ids)
- 扇出截断闸门 (fanout_split)
- 类一致性闸门 (hot_guard)
- 凭证闸门 (warrant_guard)
- 叶子规则 (is_leaf)
- 状态滚动累积机 (BundleState)
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from domain.edge import (
    CONSUMER_RELS,
    DERIVATION_REL,
    PRODUCER_RELS,
    content_triple_of,
    labels_of,
)
from core.clustering import dir_class, object_side


def anchor_facts(poi_rows: list[dict[str, Any]]) -> dict[str, set]:
    """提取起点告警锚点事件的客观事实（进程标识、对象及网络主机对）。"""
    out: dict[str, set] = {"procs": set(), "objs": set(), "pairs": set()}
    for row in poi_rows:
        rel = str(row.get("rel") or "")
        src_label, dst_label = labels_of(rel)
        src, _syscall, dst, _src_label = content_triple_of(
            rel, str(row.get("syscall") or ""), str(row.get("process_content") or ""),
            str(row.get("other") or ""))
        out["procs"].add(str(row.get("process_id") or ""))
        for label, content in ((src_label, src), (dst_label, dst)):
            if label == "Process":
                continue
            out["objs"].add((label, str(content)))
            if label == "Network":
                cls = dir_class(str(content), label)
                if cls.startswith("主机对"):
                    out["pairs"].add(cls)
    return out


def vacuous_ids(items: list[dict[str, Any]]) -> set[str]:
    """空拆闸门：筛选与上一级父束成员完全相同的子束编号集合。"""
    return {item["id"] for item in items if item.get("vacuous")}


def fanout_split(items: list[dict[str, Any]], vacuous: set[str], fanout_min: int,
                 ) -> tuple[list[dict[str, Any]], set[str], int]:
    """扇出闸门：分离出拆分产生的成员数不超过下限的单条边子束。"""
    ask: list[dict[str, Any]] = []
    skipped: set[str] = set()
    edges = 0
    for item in items:
        if item["id"] in vacuous:
            continue
        if item.get("parent") and item["size"] <= fanout_min:
            skipped.add(item["id"])
            edges += int(item["size"])
        else:
            ask.append(item)
    return ask, skipped, edges


def hot_guard(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]]) -> int:
    """类一致性闸门：同一对象类别中已有束判为整束相关时，同类的整束无关降级为混杂。"""
    hot: Counter = Counter()
    for item in items:
        row = verdicts.get(item["id"]) or {}
        if str(row.get("verdict", "")).lower() == "all":
            for cls in item.get("all_dirs", []):
                hot[cls] += 1
    if not hot:
        return 0
    downgraded = 0
    for item in items:
        row = verdicts.get(item["id"])
        if row is None or str(row.get("verdict", "")).lower() != "none":
            continue
        shared = [cls for cls in item.get("all_dirs", []) if hot.get(cls)]
        if shared:
            row["verdict"] = "mixed"
            row["_guard"] = "hot:" + "、".join(shared[:2])
            downgraded += 1
    return downgraded


def warrant_guard(items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                  facts_of: Callable[[dict[str, Any]], dict[str, Any]],
                  rules: set[str]) -> tuple[int, dict[str, dict[str, Any]]]:
    """凭证闸门：判整束无关的束若命中已知误杀模式，降级为混杂继续拆分。"""
    downgraded = 0
    facts_by_id: dict[str, dict[str, Any]] = {}
    for item in items:
        row = verdicts.get(item["id"])
        if row is None or str(row.get("verdict", "")).lower() != "none":
            continue
        facts = facts_of(item)
        facts_by_id[item["id"]] = facts
        hits: list[str] = []
        if "deriv" in rules and facts.get("only_derivation"):
            hits.append("束内全是派生边")
        if "proc" in rules and facts.get("proc_confirmed"):
            hits.append("同一进程已出现在已确认相关的束里")
        if hits:
            row["verdict"] = "mixed"
            row["_warrant"] = "、".join(hits)
            downgraded += 1
    return downgraded, facts_by_id


def is_leaf(item: dict[str, Any], verdict: str, last_level: bool, fanout_min: int) -> bool:
    """叶子规则：已是单条边且没有更细级别可拆时，判混杂或判不了直接按未排除保留。"""
    return bool(verdict in ("mixed", "unknown") and not last_level
                and item.get("parent") and item["size"] <= fanout_min)


class BundleState:
    """调查状态机：滚动记录已确认实体并统一评估结构闸门。"""

    def __init__(self, anchor: dict[str, set] | None = None,
                 program_of: dict[str, str] | None = None) -> None:
        self.anchor: dict[str, set] = anchor or {"procs": set(), "objs": set(), "pairs": set()}
        self.program_of: dict[str, str] = program_of or {}
        self.mark_dirs: Counter = Counter()
        self.mark_programs: Counter = Counter()
        self.procs: set[str] = set()
        self.programs: set[str] = set()
        self.objs: set[tuple[str, str]] = set()
        self.pairs: set[str] = set()
        self.window: list[int] | None = None

    def facts(self, item: dict[str, Any], records: dict[Any, Any]) -> dict[str, Any]:
        """提取指定束在当前已知事实下的拓扑与时序特征。"""
        has_producer = has_consumer = has_deriv = False
        written_by_confirmed = is_anchor_object = False
        pairs: set[str] = set()
        procs: set[str] = set()
        programs: set[str] = set()
        for triple in item["members"]:
            record = records[triple]
            for member in record.get("member_processes") or ():
                procs.add(str(member))
                programs.add(str(self.program_of.get(str(member), str(member))))
            rels = set(record.get("rels") or ())
            if rels & set(PRODUCER_RELS):
                has_producer = True
            if rels & set(CONSUMER_RELS):
                has_consumer = True
            if DERIVATION_REL in rels:
                has_deriv = True
            obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                     str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
            if (label, str(obj)) in self.objs:
                written_by_confirmed = True
            if (label, str(obj)) in self.anchor["objs"]:
                is_anchor_object = True
            if label == "Network":
                cls = dir_class(str(obj), label)
                if cls.startswith("主机对"):
                    pairs.add(cls)
        window = self.window
        return {
            "proc_confirmed": bool(procs & self.procs),
            "proc_anchor": bool(procs & self.anchor["procs"]),
            "program_confirmed": bool(programs & self.programs),
            "obj_written_by_confirmed": written_by_confirmed,
            "obj_is_anchor": is_anchor_object,
            "pair_confirmed": bool(pairs & self.pairs),
            "pair_anchor": bool(pairs & self.anchor["pairs"]),
            "only_reader": has_consumer and not has_producer,
            "only_derivation": has_deriv and not has_producer and not has_consumer,
            "touches_producer": has_producer,
            "overlaps_confirmed_window": bool(window) and item["t0"] <= window[1] and item["t1"] >= window[0],
            "before_confirmed_window": bool(window) and item["t1"] < window[0],
        }

    def note_confirmed(self, item: dict[str, Any], records: dict[Any, Any]) -> None:
        """当某束被确认为整束相关时，将其实体、路径与时间窗沉淀到状态记忆中。"""
        for cls in item.get("all_dirs") or ():
            self.mark_dirs[cls] += 1
        for program in item.get("programs") or ():
            self.mark_programs[program] += 1
        for triple in item["members"]:
            record = records[triple]
            for member in record.get("member_processes") or ():
                self.procs.add(str(member))
                self.programs.add(str(self.program_of.get(str(member), str(member))))
            obj, label = object_side(record["src"], record["syscall"], record["dst"],
                                     str(record.get("src_label") or ""), str(record.get("dst_label") or ""))
            if label != "Process" and any(rel in PRODUCER_RELS for rel in record.get("rels") or ()):
                self.objs.add((label, str(obj)))
            if label == "Network":
                cls = dir_class(str(obj), label)
                if cls.startswith("主机对"):
                    self.pairs.add(cls)
        t0, t1 = int(item["t0"]), int(item["t1"])
        self.window = [t0, t1] if self.window is None else [min(self.window[0], t0), max(self.window[1], t1)]
