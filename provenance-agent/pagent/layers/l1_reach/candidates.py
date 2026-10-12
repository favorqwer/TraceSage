"""候选表（第 1 层尾部）：划「同一次执行」的范围 → 折叠成内容三元组 → 条目剔除。

**第一步：实例范围**（`filter_output_rows` + `build_scope`）。这条候选边，是不是"做出终点事件的那
一次执行"里的动作？从终点事件的实例出发，每一轮对清单里的进程做四件事：加它们的父进程；加它们的
子进程（遇到常驻服务就停）；加"进程号相同"的实例；把它们读过的东西的**全部**写入者加进来。
反复做到没有新进程。两条硬口径：**终点事件不受规则约束**（豁免的是实例，同一内容三元组的其它实例
照常参与判定）、**失败即保留**（查不出属主的行不剔除）。

**第二步：折叠**（`fold`）。把同一内容三元组的多个事件实例压成一条记录，是**有损压缩**：实例之间的
相对时序、各自的字节量与时间会丢（只留首末与总和）；同一三元组只有一个判定结论。折叠本身**不做任何
判定、也不删边**：它只把每条实例命中的事件判据记进 `rule_hits`（供条目类判据引用），并给两端各存
一份身份、留下结构上下文。

折叠之后按判据表执行条目类判据的「剔除条目」（`judgments.apply_item_drops`，按表里顺序先命中先剔除）。
三步合起来（实例范围、折叠、条目剔除）才是候选表（交给模型的那一堆内容三元组，也就是召回上限的口径）。
判据不写在这个文件里：范围里用到的 `no_handoff` 与条目剔除的 `drop_item` 都走 `judgments.py` 的
求值入口，表格在 `pagent/rules/l1_judgments.json`。
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from ...core import graph_facts
from . import judgments as J


# --------------------------------------------------------------------------- #
# 第一步：实例范围
# --------------------------------------------------------------------------- #

def _event_id(row: dict[str, Any]) -> int:
    """这一行的事件编号；取不到（缺字段、空值、非整数）返回 -1（绝不会与真实编号相撞）。"""
    try:
        return int(row.get("event_id"))
    except (TypeError, ValueError):
        return -1


def _num_of(pid: str, pids: dict[str, str]) -> str:
    """进程标识 -> 进程号。只用图顶点上的 `pid` 属性（`pids` 表）。

    进程标识是「进程号 + 程序名」拼起来的，靠字符串拆在程序名以数字开头时会拆错（例如
    `00-header`），所以那条路已经删掉。表里没有的（不该发生）按它自己的标识各成一组，不合并。
    """
    return pids.get(str(pid)) or str(pid)


def _no_handoff(key: str) -> bool:
    """划范围时不做「产物交接」追溯的对象：命中 no_handoff 判据的对象。"""
    return "no_handoff" in J.object_ruling(key).effects


def _build_maps(rows: list[dict[str, Any]], pids: dict[str, str]):
    """从候选边行建：派生关系、读取事件（带时刻）、写入事件（带时刻）、同进程号索引。"""
    parent_of: dict[str, set[str]] = collections.defaultdict(set)
    children_of: dict[str, set[str]] = collections.defaultdict(set)
    reads_by_pid: dict[str, list[tuple[str, int, int]]] = collections.defaultdict(list)
    writers_of: dict[str, set[str]] = collections.defaultdict(set)
    all_pids: set[str] = set()
    for row in rows:
        pid = str(row.get("process_id") or "")
        rel = str(row.get("rel") or "")
        obj = str(row.get("other") or "")
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
                st = int(row.get("starttime") or 0)
                reads_by_pid[pid].append((obj, st, int(row.get("endtime") or st)))
        elif rel in graph_facts.PRODUCER_RELS:
            if pid and obj:
                writers_of[obj].add(pid)
    by_num: dict[str, set[str]] = collections.defaultdict(set)
    for pid in all_pids:
        by_num[_num_of(pid, pids)].add(pid)
    return parent_of, children_of, reads_by_pid, writers_of, by_num


def build_scope(rows: list[dict[str, Any]], poi_rows: list[dict[str, Any]],
                pids: dict[str, str], residents: frozenset[str] = frozenset()
                ) -> tuple[set[str], dict[str, int]]:
    """算"做出终点事件的那一次执行"的进程实例集合（一遍循环做到没有新进程）。

    每轮对清单里每个进程做四件事，结果与遍历顺序无关：
    1. 加父进程；
    2. 加子进程（遇到常驻服务就停，不再往下——否则会把整台机器的会话都拉进来）；
    3. 加"进程号相同、程序名不同"的实例（进程号取图顶点的 `pid` 属性）；
    4. 把它读过的东西的全部写入者加进来（不限路径形状、不只看最近一次；命中 no_handoff 的对象除外）。

    `pids` 是「进程标识 → 进程号」表；`residents` 是常驻服务进程集合。两张表都由调用方给
    （不读全局状态）：进程号表由取数来源给出，常驻服务集合由 `judgments.resident_processes` 给出。

    返回（集合, 计数）。
    """
    parent_of, children_of, reads_by_pid, writers_of, by_num = _build_maps(rows, pids)
    scope: set[str] = {str(r.get("process_id") or "") for r in poi_rows if r.get("process_id")}
    scope.discard("")

    frontier = list(scope)
    rounds = 0

    def push(pid: str) -> None:
        """把一个进程放进范围并推进工作清单（已在范围里就不动）。"""
        if pid and pid not in scope:
            scope.add(pid)
            frontier.append(pid)

    while frontier:
        rounds += 1
        cur = frontier.pop()
        for parent in parent_of.get(cur, ()):
            push(parent)
        if cur not in residents:
            for child in children_of.get(cur, ()):
                push(child)
        for same in by_num.get(_num_of(cur, pids), ()):
            push(same)
        for obj, _st, _et in reads_by_pid.get(cur, ()):
            if _no_handoff(obj):
                continue
            for writer in writers_of.get(obj, ()):
                push(writer)
    return scope, {"rounds": rounds, "processes": len(scope)}


def filter_output_rows(rows: list[dict[str, Any]], poi_rows: list[dict[str, Any]], *,
                       enabled: bool = True,
                       log: Optional[Callable[[str], None]] = None,
                       pids: Optional[dict[str, str]] = None,
                       residents: frozenset[str] = frozenset(),
                       ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """输出期过滤：只判实例范围；返回（保留的行, 实例范围计数）。

    `pids` 是「进程标识 → 进程号」表（图顶点的 `pid` 属性，由取数来源给出）；`residents` 是常驻
    服务进程集合（`judgments.resident_processes` 给出）。两张表都由调用方传，不读全局。

    `enabled=False`（对照实验关掉整层）时原样返回。没有终点事件时不做范围过滤（失败即保留）；
    终点事件的实例与查不出属主的行不判、单独计数。
    """
    if not enabled:
        return rows, {"enabled": False}

    rows_before = len(rows)
    poi_events = J.poi_event_ids(poi_rows)
    scope: Optional[set[str]] = None
    scope_rounds = 0
    if poi_rows:
        scope, scope_extra = build_scope(rows, poi_rows, pids or {}, residents)
        scope_rounds = scope_extra.get("rounds", 0)

    kept: list[dict[str, Any]] = []
    scope_dropped = 0
    poi_kept = 0
    owner_missing = 0
    for row in rows:
        if _event_id(row) in poi_events:
            # 终点事件不受规则约束（与闭包种子同一口径）：不判，永远交给模型
            poi_kept += 1
            kept.append(row)
            continue
        pid = str(row.get("process_id") or "")
        if not pid:
            # 查不出属主：失败即保留
            owner_missing += 1
            kept.append(row)
            continue
        if scope is not None and pid not in scope:
            scope_dropped += 1
            continue
        kept.append(row)

    judgeable = rows_before - poi_kept - owner_missing   # 真正进判定的行数
    stats: dict[str, Any] = {
        "enabled": True, "rows_before": rows_before, "rows_judged": judgeable,
        "rows_after": judgeable - scope_dropped, "dropped": scope_dropped,
        "scope_processes": len(scope) if scope is not None else 0,
        "scope_rounds": scope_rounds,
        "poi_kept": poi_kept, "owner_missing": owner_missing,
    }

    if log:
        if scope is not None:
            log(f"[scope] 实例范围：进程实例 {len(scope)} 个"
                f"（一遍循环做完，{scope_rounds} 轮）；"
                f"进判定的行 {judgeable} → {stats['rows_after']}（剔掉 {scope_dropped} 条不在范围内的实例）")
        if poi_kept or owner_missing:
            log(f"[exempt] 不判、直接保留：终点事件实例 {poi_kept} 条 / 查不出属主 {owner_missing} 条")
    return kept, stats


# --------------------------------------------------------------------------- #
# 第二步：折叠
# --------------------------------------------------------------------------- #

@dataclass
class CollapsedEdge:
    src: str
    syscall: str
    dst: str
    src_label: str = "Process"
    dst_label: str = "Process"
    instances: int = 0
    bytes: int = 0
    event_ids: list[int] = field(default_factory=list)
    t0: int = 0
    t1: int = 0
    rels: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)   # 来源进程（同一个内容三元组可能由多个进程产生）
    # 内部计数：每条实例命中的事件判据（判据编号 -> 实例数）。供条目类判据引用（例如
    # 「全部实例都是零字节读」引用零字节读那条事件判据）；不写进记录与报告，to_dict 不含它。
    rule_hits: dict[str, int] = field(default_factory=dict)
    # 两端顶点的**身份**（判定层“按身份找上层已判过的边”用）：进程 → ("Process", 进程标识)、
    # 文件 → ("File", 路径)、网络 → ("Network", 四元组)。内容三元组与报告口径不受影响，
    # 只是多存一份身份，避免“同一个程序跑了 191 次”时把 191 个进程的判定历史混在一起。
    src_identities: set[tuple[str, str]] = field(default_factory=set)
    dst_identities: set[tuple[str, str]] = field(default_factory=set)
    # 结构上下文（判定时渲染给模型看，不进报告）：离终点事件最少几跳、从哪个顶点被回推出来。
    # `via` 是给人读的显示文本（进程显示可执行路径）；`via_kind` / `via_key` 是原始标识
    # （判定层的“上游交接明细”按它定位上一层顶点：进程侧是进程标识，对象侧是路径本身）。
    dist: int = 0
    via: str = ""
    via_kind: str = ""
    via_key: str = ""

    def to_dict(self, *, with_event_ids: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "syscall": self.syscall,
            "dst": self.dst,
            "src_label": self.src_label,
            "dst_label": self.dst_label,
            "instances": self.instances,
            "bytes": self.bytes,
            "t0": self.t0,
            "t1": self.t1,
            "rels": sorted(self.rels),
            "member_processes": sorted(self.members),
            "src_identities": sorted([list(x) for x in self.src_identities]),
            "dst_identities": sorted([list(x) for x in self.dst_identities]),
            "dist": self.dist,
            "via": self.via,
            "via_kind": self.via_kind,
            "via_key": self.via_key,
        }
        if with_event_ids:
            out["event_ids"] = self.event_ids
        return out


@dataclass
class FoldResult:
    edges: list[CollapsedEdge]
    raw_instances: int


def _via_label(row: dict[str, Any]) -> str:
    """这条边从哪个顶点被回推出来（空 = 终点事件本身）。"""
    kind = str(row.get("via_kind") or "")
    return f"{kind} {row.get('via_key') or ''}".strip() if kind else "终点事件"


def _other_identity(row: dict[str, Any]) -> tuple[str, str]:
    """这条边“另一端”（非归属进程那一端）的身份。

    派生边（p2p）的另一端是父进程，取它的进程标识；文件与网络端点取路径 / 四元组。
    取不到标识时返回空串身份，折叠时会被丢弃（宁可这一端没有身份，也不要拿内容冒充身份）。
    """
    label = str(row.get("other_label") or "")
    if label == "Process":
        return label, str(row.get("other_process_id") or "")
    return label, str(row.get("other") or "")


def fold(rows: Iterable[dict[str, Any]]) -> FoldResult:
    """把事件实例折成内容三元组（只合并不删边，也不做任何判定）。"""
    table: dict[tuple[str, str, str], CollapsedEdge] = {}
    raw = 0
    for row in rows:
        raw += 1
        src, syscall, dst, src_label = graph_facts.content_triple_of(
            row["rel"], row["syscall"], row["owner"], row["other"])
        # 两端标签用于消除 `/usr/bin/mv` 这类"既是进程又是文件"的内容歧义（与取边时的判定共用一份）
        _src_label, dst_label = graph_facts.labels_of(row["rel"])
        key = (src, syscall, dst)
        edge = table.get(key)
        if edge is None:
            edge = CollapsedEdge(
                src=src,
                syscall=syscall,
                dst=dst,
                src_label=src_label,
                dst_label=dst_label,
                t0=row["starttime"],
                t1=row["endtime"],
                dist=int(row.get("dist") or 0),
                via=_via_label(row),
                via_kind=str(row.get("via_kind") or ""),
                via_key=str(row.get("via_key") or ""),
            )
            table[key] = edge
        elif int(row.get("dist") or 0) < edge.dist:
            # 同一个三元组可能有多个实例：结构上下文取跳数最小的那一份（确定性：相同则保留先到的）
            edge.dist = int(row.get("dist") or 0)
            edge.via = _via_label(row)
            edge.via_kind = str(row.get("via_kind") or "")
            edge.via_key = str(row.get("via_key") or "")
        edge.instances += 1
        ruling = J.event_ruling(str(row["rel"]), str(row.get("syscall") or ""), row.get("bytes"))
        if ruling.rule_id:
            edge.rule_hits[ruling.rule_id] = edge.rule_hits.get(ruling.rule_id, 0) + 1
        edge.bytes += max(0, int(row.get("bytes") or 0))
        edge.event_ids.append(int(row["event_id"]))
        edge.t0 = min(edge.t0, int(row["starttime"]))
        edge.t1 = max(edge.t1, int(row.get("endtime") or row["starttime"]))
        edge.rels.add(row["rel"])
        if row.get("process_id"):
            edge.members.add(str(row["process_id"]))
        # 两端身份：属主那一端一定是进程（归属规则），另一端按标签取；标识为空就丢这一端
        owner_ident = ("Process", str(row.get("process_id") or ""))
        other_ident = _other_identity(row)
        src_ident, dst_ident = ((owner_ident, other_ident) if graph_facts.owner_is_source(row["rel"])
                                else (other_ident, owner_ident))
        if src_ident[1]:
            edge.src_identities.add(src_ident)
        if dst_ident[1]:
            edge.dst_identities.add(dst_ident)
    edges = sorted(table.values(), key=lambda e: (e.t0, e.src, e.syscall, e.dst))
    return FoldResult(edges=edges, raw_instances=raw)
