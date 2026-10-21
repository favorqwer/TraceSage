"""第 1 层：往回走的**反向闭包**引擎 + 取数来源（本文件是正式流程唯一的取数入口）。

本文件两个部分：上半部分是闭包引擎（`run_closure`）与事件结构（`Event`）；下半部分是取数来源
（`SnapshotReader` / `open_source`）——从本地顶点-时间索引读边（`graph_index.py`），零数据库查询。
生产包只用索引来源；数据库直查的实现只存在单测里（`tests/unit/db_source.py`），作参照实现。

一条**事件**就是图上的一条边：两个端点（进程 / 文件 / 网络）、一个操作名、一个字节数、
一个开始时刻、一个结束时刻。

## 因果规则（本引擎保证的就是这一套，逐条可核）

事件甲**可能影响**事件乙，当且仅当满足下面三条之一：

1. **同进程**：甲、乙都以同一个进程为端点，且甲的开始时刻不晚于乙的开始时刻；
2. **同顶点交付**：甲写入同一个文件或网络顶点、乙从该顶点读取，且甲的开始时刻不晚于乙的
   结束时刻（流式读写允许边写边读；只算写入侧——读不会把内容送回顶点）；
3. **派生**：甲是进程派生事件（父进程到子进程），乙是该子进程在甲之后的事件；同一主体在
   门限之前派生出去的其它子进程也算上游（有意识的超集口径）。

**反向闭包** = 能沿这三条走回终点事件的**全部**事件。

到达一个顶点时带一个**门限**（一个时刻）：进程顶点取“开始不晚于门限”的全部入射事件，
且门限至少抬到终点事件时刻；文件 / 网络顶点只取写入侧，读事件给写入者的门限取读的结束时刻。
门限只增不减（同一顶点只完整展开一次、变高时只补取新增区间），**不设任何条数上限**
（终止条件是“待考察清单耗尽”）。取边时不剔除任何边；会少收上游的只有判据表里声明
`no_expand` 的两处（非交付通道不展开、零字节读不展开），边本身照样收。

## 输出与计数口径

`run_closure` 返回折叠能直接吃的边行（`rows`）与计数（`stats`）；`with_events=True` 时
另有事件集合（`events`）。`stats` 只统计这一次调用；`rows_fetched`
是**进判定**的行数，来源侧扫到的记录数 = `rows_fetched` + 来源的 `skipped_already_included`。
判据、后果与生效阶段见 `foundation/rules/l1_judgments.json`。

每条边还带一个**入闭包通道**位（`support`）：它是从哪一类顶点被收进闭包的（进程 / 文件 /
网络 / 终点事件本身）。判定层按它把「同一程序、同一动作、同一系统调用」的边再细分——从不同
通道进来的边在链条上的位置不同，混在一起判会把两类活动揉成一个束。它同样不参与收边判定。
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

from ...core import graph_facts
from . import graph_index as snap
from . import judgments as J
from .process_info import cache_process_info

# 一轮里处理待考察顶点的顺序（只影响处理顺序，不影响收哪些边）
_KIND_ORDER = ("File", "Network", "Process")

# 索引记录里的关系编号：只取写入侧（读不会把内容送回顶点）
_PRODUCER_CODES = frozenset(code for code, rel in snap.REL_BY_CODE.items()
                            if rel in graph_facts.PRODUCER_RELS)
# 读取侧（对象 -> 进程）：前向补链用（写下的对象后来被谁读走）
_CONSUMER_CODES = frozenset(code for code, rel in snap.REL_BY_CODE.items()
                            if rel in graph_facts.CONSUMER_RELS)
_CHUNK_RECORDS = 4096

# 入闭包通道的位（`Event.support`）：这条边是从哪一类顶点被收进闭包的。
# 终点事件本身算「种子」；同一条边被多类顶点找到时按位或（去重后只留跳数最少的那一份）。
CHANNEL_BITS = {"Process": 1, "File": 2, "Network": 4, "seed": 8}
_SEED_BIT = CHANNEL_BITS["seed"]


class Event:
    """一条图上的边（事件）。`pid` 是按归属规则拥有它的进程。

    用固定槽位的普通类而不是数据类：闭包在大日志上要建上百万个，构造开销直接落在总耗时里。
    规则命中与否不在这里预存：影响往回走的判定在取边时按边的形状现算并缓存（见 `include`）。
    """

    __slots__ = ("event_id", "rel", "syscall", "bytes", "start", "end", "pid", "owner",
                 "other", "other_label", "other_process_id",
                 "dist", "via_kind", "via_key", "support")

    def __init__(self, event_id: int, rel: str, syscall: str, bytes: int, start: int, end: int,
                 pid: str, owner: str, other: str, other_label: str, other_process_id: str = "",
                 dist: int = 0, via_kind: str = "", via_key: str = "", support: int = 0) -> None:
        self.event_id = event_id
        self.rel = rel
        self.syscall = syscall
        self.bytes = bytes
        self.start = start
        self.end = end
        self.pid = pid
        self.owner = owner
        self.other = other
        self.other_label = other_label
        self.other_process_id = other_process_id
        # 结构上下文（只用于判定时的渲染与束的细分，不参与收边判定）：离终点事件最少几跳
        # （种子 = 0）、这条边是从哪个顶点被回推出来的（`via_kind` 为空 = 终点事件本身）、
        # 以及入闭包通道的位掩码（见 `CHANNEL_BITS`）。
        self.dist = dist
        self.via_kind = via_kind
        self.via_key = via_key
        self.support = support


class GraphSource(Protocol):
    """取边的来源：数据库直查，或顶点-时间索引快照（两者必须给出相同结果）。

    `seen` 是"已经收进闭包的边（事件编号）集合"：给了它，来源就可以把这类边直接跳掉、
    不再重造内部表示。它是**只影响快慢的提示**：给了要跳过、不给也不影响收哪些边。
    """

    database: str

    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        """进程顶点：开始时刻落在 (lo, hi] 的全部入射事件（`p2p` 两个方向都取：
        自己是子进程的那条、以及自己派生出去的那些子进程）。"""

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        """文件 / 网络顶点：只取写入侧（开始时刻落在 (lo, hi]）——读不会把内容送回顶点。"""

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """某个文件 / 网络顶点在 (lo, hi] 里被读走的事件（前向补链用）。"""

    def process_info_many(self, pids: list[str]) -> None:
        """把进程静态属性灌进内存缓存（进程身份摘要要用，不算业务查询）。"""

    def network_protocols(self) -> dict[str, str]:
        """网络端点标识 -> 传输层协议。"""

    def close(self) -> None:
        """释放句柄（索引来源为空实现）。"""

    def stats(self) -> dict[str, Any]:
        """来源侧的计数（查询次数、扫到的记录数、非交付通道跳过的顶点展开次数等）。

        `nondelivery_not_expanded` 计的是**被跳过的非交付通道顶点展开次数**，不是被跳过的边数。
        """


@dataclass
class _Pending:
    threshold: int
    key: str
    dist: int = 0                  # 这个顶点离终点事件的最少跳数（只用于上下文渲染）


@dataclass
class _Stats:
    rounds: int = 0
    process_expands: int = 0
    object_expands: int = 0
    reexpands: int = 0
    rows_fetched: int = 0          # 进判定的行数（已被收过、在来源侧跳掉的不算；那是来源的 skipped）
    events_included: int = 0
    empty_reads: int = 0
    frontier_peak: int = 0         # 单轮待考察顶点的峰值（内存诊断）

    def as_dict(self) -> dict[str, Any]:
        return {"rounds": self.rounds, "process_expands": self.process_expands,
                "object_expands": self.object_expands, "reexpands": self.reexpands,
                "rows_fetched": self.rows_fetched, "events_included": self.events_included,
                "empty_reads": self.empty_reads,
                "frontier_peak": self.frontier_peak}


def run_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                log: Optional[Callable[[str], None]] = None,
                with_events: bool = True) -> dict[str, Any]:
    """算反向闭包。返回 `{"rows": [...], "stats": {...}}`，`with_events=True`（默认）时另有 `"events"`。

    `rows` 是折叠（`candidates.py`）能直接吃的边行：`rel / owner / other / other_label /
    syscall / bytes / starttime / endtime / event_id / process_id / dist / via_kind / via_key`
    （`process_id` 是按归属规则拥有这条边的进程的标识）。
    **不设任何条数上限。**（`dist` 是这条边离终点事件最少几跳，`via_*` 是它从哪个顶点被回推出来——
    只用干判定时的上下文渲染，不参与收边判定。）

    `with_events=False` 供"只要边行"的调用方使用：事件集合照样在内部用来生成边行，但不放进返回值。
    """
    included: dict[int, Event] = {}
    # 待考察清单与"已展开到哪一刻"都按顶点类型分开存：省掉每个顶点拼一个带前缀的字符串键，
    # 也省掉每一轮把两边混在一起比对。三类的处理顺序由 `_KIND_ORDER` 固定，结果与顺序无关。
    pending: dict[str, dict[str, _Pending]] = {kind: {} for kind in _KIND_ORDER}
    processed: dict[str, dict[str, int]] = {kind: {} for kind in _KIND_ORDER}
    stats = _Stats()

    def push(kind: str, key: str, threshold: int, dist: int = 0) -> None:
        """把一个顶点按门限放进待考察清单（门限不高于已展开过的就跳过）。

        `dist` 是这个顶点离终点事件的最少跳数：同一个顶点被多次推进时取最小的那个。
        """
        if not key:
            return
        if kind == "Process":
            # 进程状态通道的上界固定取终点事件时刻：同一主体在终点事件之前的活动都算可能影响它
            threshold = int(threshold)
            if threshold < poi_t0:
                threshold = poi_t0
        done = processed[kind]
        if done.get(key, -1) >= threshold:
            return                     # 这个顶点已经按不早于本门限展开过：连清单都不必进
        bucket = pending[kind]
        cur = bucket.get(key)
        if cur is None:
            bucket[key] = _Pending(threshold=int(threshold), key=key, dist=int(dist))
            return
        if dist < cur.dist:
            cur.dist = int(dist)
        if threshold > cur.threshold:
            cur.threshold = int(threshold)

    def include(ev: Event, *, from_dist: int = -1,
                via_kind: str = "", via_key: str = "") -> bool:
        """收一条事件。

        `from_dist` 是展开它的那个顶点离终点几跳（`-1` = 种子，即终点事件本身）：这条边的跳数
        = `from_dist + 1`，种子是 0；`via_kind` / `via_key` 记下是从哪个顶点回推出来的。
        这三个字段只用于上下文渲染，**不参与收边判定**。
        """
        dist = 0 if from_dist < 0 else int(from_dist) + 1
        mask = _SEED_BIT if from_dist < 0 else CHANNEL_BITS.get(via_kind, 0)
        edge_key = (ev.event_id, ev.rel)
        prev = included.get(edge_key)
        if prev is not None:
            # 同一条边可能从多个顶点被找到：留跳数最少的那一份（跳数相同则保留先到的）
            if dist < prev.dist:
                prev.dist = dist
                prev.via_kind, prev.via_key = via_kind, via_key
            prev.support |= mask
            return False
        # 判据在这里第一次生效：命中 no_expand 的读事件（当前只有零字节读）边照收，但不展开对象
        no_expand = "no_expand" in J.event_ruling(ev.rel, ev.syscall, ev.bytes).effects
        ev.dist = dist
        ev.via_kind, ev.via_key = via_kind, via_key
        ev.support = mask
        included[edge_key] = ev
        stats.events_included += 1
        if no_expand:
            stats.empty_reads += 1
            push("Process", ev.pid, ev.start, dist)      # 进程状态这条通道照走
            return True

        if ev.rel in graph_facts.PRODUCER_RELS:
            push("Process", ev.pid, ev.start, dist)
        elif ev.rel in graph_facts.CONSUMER_RELS:
            push("Process", ev.pid, ev.start, dist)
            # 写入者的时间界取读取的结束时刻：流式读写允许边写边读
            push(ev.other_label, ev.other, ev.end, dist)
        elif graph_facts.is_derivation(ev.rel):
            # 派生事件：父进程那一侧往回走；同一主体派生出去的其它子进程也算上游（有意识的超集口径）
            push("Process", ev.other_process_id, ev.start, dist)
            push("Process", ev.pid, ev.start, dist)
        return True

    # --- 种子：终点事件本身 + 它两端顶点的门限 ---
    for seed in seeds:
        include(seed)

    while pending["Process"] or pending["File"] or pending["Network"]:
        # 按门限从高到低、同门限按类型与顶点键排序：只影响处理顺序（可复现），不影响收哪些边。
        # 跳数为什么是最小值：种子先把跳数 0 的顶点推进清单，之后一个顶点的最小跳数只可能由上
        # 一轮里已推进的顶点带来，且推入的顶点最早在下一轮被展开——所以每个顶点第一次被展开时
        # 带的就是最小跳数，与轮内处理顺序无关。
        items: list[tuple[int, int, str, str, int]] = []
        for rank, kind in enumerate(_KIND_ORDER):
            bucket = pending[kind]
            if not bucket:
                continue
            items.extend((item.threshold, rank, kind, item.key, item.dist)
                         for item in bucket.values())
            bucket.clear()
        items.sort(key=lambda it: (-it[0], it[1], it[2]))
        stats.frontier_peak = max(stats.frontier_peak, len(items))

        proc_items: list[tuple[str, int, int, int]] = []
        file_items: list[tuple[str, int, int, int]] = []
        net_items: list[tuple[str, int, int, int]] = []
        for threshold, _rank, kind, key, dist in items:
            done = processed[kind]
            prev = done.get(key)
            if prev is not None and threshold <= prev:
                continue
            lo = prev if prev is not None else -1
            if prev is not None:
                stats.reexpands += 1
            done[key] = threshold
            if kind == "Process":
                proc_items.append((key, lo, threshold, dist))
            elif kind == "Network":
                net_items.append((key, lo, threshold, dist))
            else:
                file_items.append((key, lo, threshold, dist))

        if proc_items:
            stats.process_expands += len(proc_items)
        if file_items or net_items:
            stats.object_expands += len(file_items) + len(net_items)
        # 逐顶点取边（而不是一批一起取）：这样每条边都能记下"是从哪个顶点展开出来的"。
        # 取数来源本身是按顶点逐块读的，逐顶点调用与批量调用的行集合、顺序完全一致。
        # 处理顺序固定为进程 → 文件 → 网络（同一轮里同一条边可能从两个顶点被找到，
        # 保持这个顺序结果才可复现；跳数最小的那一份仍然优先）。
        for kind, items in (("Process", proc_items), ("File", file_items), ("Network", net_items)):
            for key, lo, hi, dist in items:
                if kind == "Process":
                    found_events = source.expand_process([(key, lo, hi)], seen=included)
                else:
                    found_events = source.expand_object([(key, lo, hi)], kind, seen=included)
                for ev in found_events:
                    stats.rows_fetched += 1
                    include(ev, from_dist=dist, via_kind=kind, via_key=key)
        stats.rounds += 1
        if log:
            # 逐轮报进度：闭包在大日志上要跑几十秒，不报进度等于看不见
            log(f"[closure] 第 {stats.rounds} 轮：已收 {stats.events_included} 条事件 / "
                f"展开 {stats.process_expands} 进程 + {stats.object_expands} 文件或端点 / "
                f"待考察 {sum(len(bucket) for bucket in pending.values())} / "
                f"取回 {stats.rows_fetched} 行")

    events = sorted(included.values(), key=lambda e: (e.start, e.event_id))
    rows = _to_rows(events)               # 已经排好序，不再重复排一次
    out: dict[str, Any] = {"rows": rows, "stats": stats.as_dict()}
    if with_events:
        out["events"] = events
    return out


def _to_rows(events: list[Event]) -> list[dict[str, Any]]:
    """把事件转成第 1 层尾部的折叠能直接吃的边行（每行带归属进程的标识 `process_id`）。

    `events` 必须已经按（开始时刻, 事件编号）排好序——闭包引擎排过一次，这里不再排第二遍。

    **不写"另一端的进程标识"**：那个字段只有闭包引擎自己往回走父进程时要用（`Event` 上仍然有），
    折叠、上下文、报告都不读它，所以不进边行。**例外**：判定层的命令表要靠派生边的
    "另一端进程标识"往上找父进程的命令行（非派生边为空串），因此带出来；
    它不参与收边、分组与折叠。

    边行里多带 `dist` / `via_kind` / `via_key` / `support` 四样（结构上下文）：它们是**边上图事实的
    派生值**（这条边离终点最少几跳、展开时是从哪个顶点看到它的、从哪一类顶点被收进闭包的），
    判定时用于渲染给模型看、并作为束的细分键；不参与任何收边判定，也不进报告。
    """
    rows: list[dict[str, Any]] = []
    for ev in events:
        rows.append({
            "rel": ev.rel, "owner": ev.owner, "other": ev.other, "other_label": ev.other_label,
            "event_id": ev.event_id,
            "starttime": ev.start, "endtime": ev.end, "syscall": ev.syscall, "bytes": ev.bytes,
            "dist": ev.dist, "via_kind": ev.via_kind, "via_key": ev.via_key,
            "support": ev.support,
            "other_process_id": ev.other_process_id,
            "process_id": ev.pid,
        })
    return rows


def find_forward_seeds(source: Any, rows: list[dict[str, Any]], closed_processes: set[str],
                       poi_t0: int) -> list[Event]:
    """受限前向补链：闭包内写入的常规数据载体文件在写入后被闭包外进程读取。"""
    written_files: dict[str, int] = {}
    for r in rows:
        if (str(r.get("rel") or "") == "p2f"
                and str(r.get("other_label") or "") == "File"
                and int(r.get("bytes") or 0) > 0):
            path = str(r.get("other") or "")
            if not J.is_forward_carrier(path):
                continue
            start = int(r.get("starttime") or 0)
            if path not in written_files or start < written_files[path]:
                written_files[path] = start

    forward_seeds: list[Event] = []
    for path, t0 in written_files.items():
        reads = source.reads_after(path, "File", t0, poi_t0)
        external = [evt for evt in reads if str(evt.pid) not in closed_processes]
        if not external:
            continue
        pids = {str(evt.pid) for evt in external}
        if len(pids) <= 10:
            forward_seeds.extend(external)
        else:
            for evt in external:
                evts_p = source.expand_process([(evt.pid, evt.start, poi_t0)])
                has_sensitive = any(
                    e.rel in graph_facts.PRODUCER_RELS or graph_facts.is_derivation(e.rel)
                    for e in evts_p
                )
                if has_sensitive:
                    forward_seeds.append(evt)
    return forward_seeds


def run_causal_closure(source: Any, seeds: list[Event], *, poi_t0: int = 0,
                       forward_chain: bool = True, log: Optional[Callable[[str], None]] = None,
                       with_events: bool = False) -> dict[str, Any]:
    """计算因果闭包：反向闭包 +（可选）受限前向补链。

    统一执行：
    1. 沿时序因果规则回溯反向因果闭包；
    2. 基于常规数据载体文件，向前探测外部读者并补充因果种子；
    3. 预热灌入闭包涉及进程的静态身份缓存。
    """
    res = run_closure(source, seeds, poi_t0=poi_t0, log=log, with_events=with_events)
    rows = res["rows"]
    stats = dict(res["stats"])
    closed_processes = {str(r.get("process_id") or "") for r in rows} - {""}
    forward_seeds: list[Event] = []
    all_seeds = list(seeds)

    if forward_chain:
        forward_seeds = find_forward_seeds(source, rows, closed_processes, poi_t0)
        if forward_seeds:
            if log:
                log(f"[causal_closure] 前向补链：常规磁盘文件发现 {len(forward_seeds)} 条外部读取种子，重跑闭包")
            all_seeds = all_seeds + forward_seeds
            res = run_closure(source, all_seeds, poi_t0=poi_t0, log=log, with_events=with_events)
            rows = res["rows"]
            stats = dict(res["stats"])
            closed_processes = {str(r.get("process_id") or "") for r in rows} - {""}

    source.process_info_many(sorted(closed_processes))
    out: dict[str, Any] = {
        "rows": rows,
        "stats": stats,
        "closed_processes": closed_processes,
        "seeds": all_seeds,
        "forward_seeds": forward_seeds,
    }
    if with_events and "events" in res:
        out["events"] = res["events"]
    return out


# --------------------------------------------------------------------------- #
# 顶点-时间索引快照来源（正式流程唯一取数方式）
# --------------------------------------------------------------------------- #

class SnapshotReader:
    """读顶点-时间索引：零数据库查询。

    取数时执行两条判据（都走 `judgments`）：对象类的 `no_expand`（非交付通道不展开）
    与事件类的 `not_delivery`（连接建立类不算交付）。
    """

    def __init__(self, database: str) -> None:
        meta = snap.read_meta(database)
        if meta is None:
            raise RuntimeError(f"索引不存在或格式不符：{snap.meta_path(database)}")
        self.database = database
        self.meta = meta
        self.dir = snap.snapshot_dir(database)
        self.vertices: list[dict[str, Any]] = json.loads(
            (self.dir / "vertices.json").read_text(encoding="utf-8"))
        self._id_of: dict[tuple[str, str], int] = {}
        for vid, item in enumerate(self.vertices):
            self._id_of[(str(item["kind"]), str(item["key"]))] = vid
        raw = json.loads((self.dir / "offsets.json").read_text(encoding="utf-8"))
        self._offsets: dict[int, tuple[int, int]] = {
            int(k): (int(v[0]), int(v[1])) for k, v in raw.items()}
        self._syscalls: list[str] = list(meta.get("syscalls") or [])
        self.queries = 0
        self.rows = 0
        self.skipped = 0            # 因已收进闭包而跳过的记录数（含在 rows 里，只影响快慢）
        self.nondelivery_not_expanded: dict[str, int] = {}   # 被跳过的非交付通道顶点展开次数（不是边数）
        self._adj = (self.dir / "adj.bin").open("rb")

    # --- 内部 ---
    def _block(self, vid: int) -> tuple[int, int]:
        return self._offsets.get(vid, (0, 0))

    def _record(self, index: int) -> tuple:
        self._adj.seek(index * snap.RECORD.size)
        return snap.RECORD.unpack(self._adj.read(snap.RECORD.size))

    def _iter_block(self, vid: int, lo: int, hi: int):
        """块内取 (lo, hi] 的记录：先二分找起点，再按块读，不整块解码。"""
        off, count = self._block(vid)
        if count <= 0:
            return
        # 二分：第一条第 start > lo 的记录
        left, right = 0, count
        while left < right:
            mid = (left + right) // 2
            if self._record(off + mid)[4] <= lo:
                left = mid + 1
            else:
                right = mid
        index = off + left
        remaining = count - left
        while remaining > 0:
            take = min(_CHUNK_RECORDS, remaining)
            self._adj.seek(index * snap.RECORD.size)
            raw = self._adj.read(take * snap.RECORD.size)
            for rec in struct.iter_unpack(snap.RECORD.format, raw):
                if rec[4] > hi:
                    return
                yield rec
            index += take
            remaining -= take

    def _syscall_of(self, rec: tuple) -> str:
        sid = int(rec[3])
        return str(self._syscalls[sid]) if sid < len(self._syscalls) else ""

    def _event(self, rec: tuple) -> Event:
        owner_id, other_id, rel_code, sid, start, end, event_id, nbytes = rec
        owner_vertex = self.vertices[owner_id]
        other_vertex = self.vertices[other_id]
        other_kind = other_vertex["kind"]
        other = other_vertex["key"] if other_kind in ("File", "Network") else other_vertex["content"]
        return Event(event_id=event_id, rel=snap.REL_BY_CODE[rel_code],
                     syscall=self._syscalls[sid] if sid < len(self._syscalls) else "",
                     bytes=nbytes, start=start, end=end,
                     pid=owner_vertex["key"], owner=owner_vertex["content"], other=other,
                     other_label=other_kind,
                     other_process_id=other_vertex["key"] if other_kind == "Process" else "")

    # --- GraphSource ---
    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get(("Process", key))
            if vid is None:
                continue
            for rec in self._iter_block(vid, lo, hi):
                # 派生边在两端顶点的块里各有一条入射记录：子进程侧是"它自己被谁启动"，
                # 父进程侧是"它启动过谁"，两条都要（同一主体子进程算上游，见 `run_closure`）
                self.rows += 1
                rel = snap.REL_BY_CODE[rec[2]]
                if seen is not None and ((rec[6], rel) in seen or rec[6] in seen):
                    self.skipped += 1          # 已经收进闭包：不重造内部表示
                    continue
                out.append(self._event(rec))
        return out

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get((kind, key))
            if vid is None:
                continue
            if kind == "File":
                ruling = J.object_ruling(key)
                if "no_expand" in ruling.effects:
                    # 非交付通道：只收边、不展开（判据现算，索引里不存标记）
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = \
                        self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
            for rec in self._iter_block(vid, lo, hi):
                rel_code = rec[2]
                if rel_code not in _PRODUCER_CODES:  # p2f / p2n
                    continue                # 只回溯写入侧：读不会把内容送回顶点
                rel = snap.REL_BY_CODE[rel_code]
                syscall = self._syscall_of(rec)
                if "not_delivery" in J.event_ruling(rel, syscall, rec[7]).effects:
                    continue                # 连接建立类操作不传递内容
                self.rows += 1
                if seen is not None and ((rec[6], rel) in seen or rec[6] in seen):
                    self.skipped += 1
                    continue
                out.append(self._event(rec))
        return out

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """某个文件 / 网络顶点在 (lo, hi] 里**被读走**的事件（前向补链用：写下的东西后来被谁读走）。

        `lo` 一般是该对象被写入的最早时刻、`hi` 是锚点时刻。只取读取侧（对象 -> 进程）。
        这里不套用对象侧的交付判据：那些判据（非交付通道、不算交付的操作）管的是「往回找写入者」，
        与「往前找读者」是两件事；前向补链展开见 `orchestration/expand_closure.py`。
        """
        out: list[Event] = []
        vid = self._id_of.get((kind, key))
        if vid is None:
            return out
        for rec in self._iter_block(vid, lo, hi):
            if rec[2] not in _CONSUMER_CODES:
                continue
            self.rows += 1
            out.append(self._event(rec))
        return out

    def process_info_many(self, pids: list[str]) -> None:
        for pid in pids:
            vid = self._id_of.get(("Process", pid))
            if vid is None:
                continue
            vertex = self.vertices[vid]
            cache_process_info(self.database, pid, {
                "process_id": pid, "pid": vertex.get("pid"), "name": vertex.get("name"),
                "exepath": vertex.get("exepath"), "args": vertex.get("args"), "cwd": vertex.get("cwd"),
            })

    def network_protocols(self) -> dict[str, str]:
        """网络端点标识 -> 传输层协议（索引顶点表里有的才收录；空值不写）。"""
        out: dict[str, str] = {}
        for vertex in self.vertices:
            if vertex.get("kind") != "Network":
                continue
            protocol = str(vertex.get("protocol") or "").strip()
            if protocol:
                out[str(vertex.get("key") or "")] = protocol
        return out

    def close(self) -> None:
        if self._adj is not None:
            self._adj.close()
            self._adj = None

    def stats(self) -> dict[str, Any]:
        return {"source": "snapshot", "queries": 0, "rows": self.rows,
                "skipped_already_included": self.skipped,
                "nondelivery_not_expanded": dict(sorted(self.nondelivery_not_expanded.items())),
                "index_dir": str(self.dir), "index_edges": self.meta.get("edges")}


def open_source(graph: Any, *, log: Any = print) -> SnapshotReader:
    """打开取边来源：确保索引存在且不过期（否则重建），然后读它。没有别的取数方式。"""
    snap.ensure_snapshot(graph, log=log)
    return SnapshotReader(graph.database)
