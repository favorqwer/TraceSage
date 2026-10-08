"""第 1 层 结构可达：从终点事件往回走的**反向闭包**（事件级、时间门限）。

一条**事件**就是图上的一条边：两个端点（进程 / 文件 / 网络）、一个操作名、一个字节数、
一个开始时刻、一个结束时刻。

## 因果规则（本引擎保证的就是这一套，逐条可核）

事件甲**可能影响**事件乙，当且仅当满足下面三条之一：

1. **同进程**（进程是有记忆的主体）：甲、乙都以同一个进程为端点，
   且甲的开始时刻不晚于乙的开始时刻。
2. **同顶点交付**：甲写入同一个文件或网络顶点，乙从该顶点读取，
   且甲的开始时刻不晚于乙的结束时刻（流式读写允许边写边读）。
   只算写入侧——读不会把内容送回顶点。**交付只发生在能承载内容的通道上**：
   角色是非交付通道的文件顶点（内核现生成的伪文件、设备节点、系统运行目录及其中的套接字，
   判据表 `core/vertices.py` 的文件段）**只收边、不展开**——读取它的那条边照样进闭包，
   但不沿它往回找写入者。
3. **派生**：甲是进程派生事件（父进程到子进程），乙是该子进程在甲之后的事件。
   子进程要不要算上游，由调用方给的把关函数决定（`siblings.py`）：不传把关函数就是全收。

**反向闭包** = 能沿上面的关系走回终点事件的**全部**事件（即这套规则下的最小集合：
收进来的每条边都在一条通往终点的依赖链上，没进来的都不满足条件）。

## 推进方式

到达一个顶点时带着一个**门限**（一个时刻）：进程顶点取"开始时刻不晚于门限"的全部入射事件；
文件 / 网络顶点取"写入该顶点、开始时刻不晚于门限"的全部事件。同一顶点再次被要求时，
若门限不高于已处理过的就跳过；若更高，**只补取新增区间的边**（已经取过的行不会重取）。
因此每个顶点只被完整展开一次、少量顶点会被补取一次，**取回的行数与闭包大小同阶**
（与图的总规模无关）。

**不设任何条数上限**：终止条件是"待考察清单耗尽"。收边时只有三类判定会丢边——
规则的"不进闭包"那一类（`stats.dropped`）、零字节的数据读取（边照收，只是不从它的顶点往回找，
`stats.empty_reads`）、子进程把关（`stats.gate_blocked`）；每一类都逐条计数，互不混装。

## 规则判定（影响往回走的那些，取边时执行，判据唯一来源 `core/edge_rules.traversal_drop_code`）

取边时只删"**不可能通向终点事件**"的边：写非交付通道、读内核按进程号现生成的伪文件（顶点表
文件段，`core/vertices.py`），动态库读取、系统程序自我执行、系统例行文件读取（内容形状，
剔除表的 traversal 段）。
后果只有一档：**命中就不收**这条边，两端也不会被推进待考察清单；逐类计数进 `stats.dropped`
（编号：`r1` / `r2` / `prefilter` / `kernel_pid_file` / `nondelivery_write`）。

**终点事件不受规则约束**：它是唯一绕过这些判定的边（加入闭包时明确不判规则），永远交给模型判定。
（代价：若终点事件本身命中某条规则，它仍会进候选表 —— 它定义了这次调查，不应被规则抹掉。）

## 输出

`run_closure` 返回第 1 层尾部的折叠能直接吃的边行（`rows`）、计数（`stats`），以及
**真正被展开过的进程名单**（`expanded_processes`）——`expanded_processes` 是 `siblings.py`
定主干名单的参照，被把关挡下的子进程不在里面。**`with_events=False` 时不返回事件集合
（`events`）**：正式流程的第二遍只吃边行（第一遍定主干时才需要事件集合）。

## 计数口径（一份日志里不允许混两种口径）

- `stats` 里的每一个数都只统计**这一次调用**（每次 `run_closure` 用一套新计数器）；
- `rows_fetched` 是**进判定**的行数；来源侧扫到的记录数 = `rows_fetched` + 来源的
  `skipped_already_included`（已收进闭包、在来源侧直接跳掉的那些）；
- `dropped` 只装影响往回走的逐类剔除数（`r1` / `r2` / `prefilter` / `kernel_pid_file` /
  `nondelivery_write`）；子进程把关挡下的派生边单独计在 `gate_blocked`；
- 来源自己的计数器由 `take_stats()` 取出并**清零**，因此可以按遍数分开记：正式流程第一遍的数
  落在 `siblings.SiblingGate.stats()` 的 `source_pass1` 里，第二遍的数就是来源的 `stats()`。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from ...core import edge_rules, graph_facts

# 数据读取类操作名（已归一）：只有它们才用"字节数"判断有没有拿到内容。
# `execve` / `accept` / `connect` 这类事件的字节数按设计就是 0，不能用它当"没交付"的判据。
_DATA_READ_SYSCALLS = ("read", "recvfrom")

# 一轮里处理待考察顶点的顺序（只影响处理顺序，不影响收哪些边）
_KIND_ORDER = ("File", "Network", "Process")


class Event:
    """一条图上的边（事件）。`pid` 是按归属规则拥有它的进程。

    用固定槽位的普通类而不是数据类：闭包在大日志上要建上百万个，构造开销直接落在总耗时里。
    规则命中与否不在这里预存：影响往回走的判定在取边时按边的形状现算并缓存（见 `include`）。
    """

    __slots__ = ("event_id", "rel", "syscall", "bytes", "start", "end", "pid", "owner",
                 "other", "other_label", "other_process_id",
                 "dist", "via_kind", "via_key")

    def __init__(self, event_id: int, rel: str, syscall: str, bytes: int, start: int, end: int,
                 pid: str, owner: str, other: str, other_label: str, other_process_id: str = "",
                 dist: int = 0, via_kind: str = "", via_key: str = "") -> None:
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
        # 结构上下文（只用于判定时的渲染，不参与收边判定）：离终点事件最少几跳（种子 = 0），
        # 以及这条边是从哪个顶点被回推出来的（`via_kind` 为空 = 终点事件本身）
        self.dist = dist
        self.via_kind = via_kind
        self.via_key = via_key


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

    def process_info_many(self, pids: list[str]) -> None:
        """把进程静态属性灌进内存缓存（进程身份摘要要用，不算业务查询）。"""

    def iter_object_edges(self, pid: str):
        """把这个进程与文件 / 网络顶点相连的读写边逐个给出：(关系类型, 操作名, 对象键, 对象标签)。

        只用于"这个进程和主干有没有过一次读写来往"这件判定（见 `siblings.py`）：调用方随时
        可以中断（只取到第一个命中即停），因此不会为一个进程建出无上限的中间结构。
        两条来源必须给出相同的集合。
        """

    def close(self) -> None:
        """释放句柄（索引来源为空实现）。"""

    def stats(self) -> dict[str, Any]:
        """来源侧的计数（查询次数、扫到的记录数、非交付通道跳过的顶点展开次数等）。

        `nondelivery_not_expanded` 计的是**被跳过的非交付通道顶点展开次数**，不是被跳过的边数。
        """

    def take_stats(self) -> dict[str, Any]:
        """取出计数并清零：调用方据此把不同遍数（定主干的第 1 遍 / 带把关的第 2 遍）分开记。"""


@dataclass
class _Pending:
    threshold: int
    kind: str
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
    gate_blocked: int = 0          # 子进程把关挡下的派生边（不是规则剔除，见模块头的"计数口径"）
    frontier_peak: int = 0         # 单轮待考察顶点的峰值（内存诊断）
    dropped: dict[str, int] = field(default_factory=dict)   # 只装五条结构式规则的逐类剔除数

    def note_drop(self, code: str) -> None:
        self.dropped[code] = self.dropped.get(code, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {"rounds": self.rounds, "process_expands": self.process_expands,
                "object_expands": self.object_expands, "reexpands": self.reexpands,
                "rows_fetched": self.rows_fetched, "events_included": self.events_included,
                "empty_reads": self.empty_reads, "gate_blocked": self.gate_blocked,
                "frontier_peak": self.frontier_peak,
                "dropped": dict(sorted(self.dropped.items()))}


def run_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                log: Optional[Callable[[str], None]] = None,
                child_allowed: Optional[Callable[[str, str], bool]] = None,
                with_events: bool = True) -> dict[str, Any]:
    """算反向闭包。返回 `{"rows": [...], "stats": {...}, "expanded_processes": [...]}`，
    `with_events=True`（默认）时另有 `"events"`。

    `child_allowed` 是子进程把关函数（父进程标识, 子进程标识）——不传就全收。
    只有"从父进程那一侧看到的派生边"才问它；子进程自己那条派生边照收。

    `rows` 是折叠（第 1 层尾部，`fold.py`）能直接吃的边行：`rel / owner / other / other_label /
    syscall / bytes / starttime / endtime / event_id / process_id / dist / via_kind / via_key`
    （`process_id` 是按归属规则拥有这条边的进程的标识）。
    **不设任何条数上限。**（`dist` 是这条边离终点事件最少几跳，`via_*` 是它从哪个顶点被回推出来——
    只用干判定时的上下文渲染，不参与收边判定。）

    `with_events=False` 供"只要边行"的调用方使用（正式流程的第二遍）：事件集合照样在内部用来
    生成边行，但不放进返回值，因此这一遍的事件对象在这一层返回时就能释放。
    """
    included: dict[int, Event] = {}
    # 待考察清单与"已展开到哪一刻"都按顶点类型分开存：省掉每个顶点拼一个带前缀的字符串键，
    # 也省掉每一轮把两边混在一起比对。三类的处理顺序由 `_KIND_ORDER` 固定，结果与顺序无关。
    pending: dict[str, dict[str, _Pending]] = {kind: {} for kind in _KIND_ORDER}
    processed: dict[str, dict[str, int]] = {kind: {} for kind in _KIND_ORDER}
    stats = _Stats()
    drop_cache: dict[tuple[str, str, str, str, str], str] = {}

    def early_mark(ev: Event) -> str:
        """影响往回走的剔除判定（对象角色 + 剔除表的 traversal 段），按边的形状缓存：同一形状只算一次。"""
        key = (ev.rel, ev.syscall, ev.owner, ev.other)
        mark = drop_cache.get(key)
        if mark is None:
            mark = edge_rules.traversal_drop_code(ev.rel, ev.syscall, ev.owner, ev.other)
            drop_cache[key] = mark
        return mark

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
            bucket[key] = _Pending(threshold=int(threshold), kind=kind, key=key, dist=int(dist))
            return
        if dist < cur.dist:
            cur.dist = int(dist)
        if threshold > cur.threshold:
            cur.threshold = int(threshold)

    def include(ev: Event, *, ctx_threshold: int = 0, apply_rules: bool = True,
                expanded: Optional[str] = None, from_dist: int = -1,
                via_kind: str = "", via_key: str = "") -> bool:
        """收一条事件；被规则剔除的返回 False（计数）。

        `expanded` 是"这条边是从哪个顶点展开出来的"（只有进程展开会传；种子与对象展开传空），
        用来判定派生边上的子进程是不是"被展开的那个进程生出来的"——子进程把关只对这种边生效。

        `from_dist` 是展开它的那个顶点离终点几跳（`-1` = 种子，即终点事件本身）：这条边的跳数
        = `from_dist + 1`，种子是 0；`via_kind` / `via_key` 记下是从哪个顶点回推出来的。
        这三个字段只用于上下文渲染，**不参与收边判定**。
        """
        dist = 0 if from_dist < 0 else int(from_dist) + 1
        prev = included.get(ev.event_id)
        if prev is not None:
            # 同一条边可能从多个顶点被找到：留跳数最少的那一份（跳数相同则保留先到的）
            if dist < prev.dist:
                prev.dist = dist
                prev.via_kind, prev.via_key = via_kind, via_key
            return False
        if apply_rules:
            # 影响往回走的判定：命中就不收这条边（两端也不会被推进待考察清单），按边的形状缓存
            code = early_mark(ev)
            if code:
                stats.note_drop(code)
                return False
        # 零字节的数据读取：什么都没拿到，因此不再从它的顶点往回找（边本身仍然收）
        empty_read = (ev.rel in graph_facts.CONSUMER_RELS and ev.syscall in _DATA_READ_SYSCALLS
                      and int(ev.bytes or 0) <= 0)
        ev.dist = dist
        ev.via_kind, ev.via_key = via_kind, via_key
        included[ev.event_id] = ev
        stats.events_included += 1
        if empty_read:
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
            # 派生事件：往回只走父进程那一侧（子进程是下游，它的活动由文件 / 通道顶点接回来）
            push("Process", ev.other_process_id, ev.start, dist)
            # 同一主体派生出去的其它子进程也算上游（有意识的超集口径），受子进程把关约束
            from_parent_side = expanded is not None and ev.pid != expanded
            if from_parent_side and child_allowed is not None and not child_allowed(expanded, ev.pid):
                stats.gate_blocked += 1
            else:
                push("Process", ev.pid, ctx_threshold or ev.start, dist)
        return True

    # --- 种子：终点事件本身 + 它两端顶点的门限 ---
    for seed in seeds:
        include(seed, apply_rules=False)

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
            threshold_by_pid = {key: hi for key, _lo, hi, _d in proc_items}
            for key, _lo, _hi, dist in proc_items:
                # 逐个顶点取边（而不是一批一起取）：这样才能知道每条派生边是"从哪一个顶点看出去的"
                # （子进程把关要问"是哪个父进程想带走这个子进程"）。取数来源本身是按顶点逐块读的，
                # 逐顶点调用与批量调用的行集合、顺序完全一致。
                for ev in source.expand_process([(key, _lo, _hi)], seen=included):
                    stats.rows_fetched += 1
                    # 门限取"正在展开的那个顶点"的门限：派生边属于父进程那一侧时用它决定子进程收多远
                    ctx = (threshold_by_pid.get(ev.other_process_id)
                           or threshold_by_pid.get(ev.pid) or ev.start)
                    include(ev, ctx_threshold=ctx, expanded=key, from_dist=dist,
                            via_kind="Process", via_key=key)
        if file_items:
            stats.object_expands += len(file_items)
            # 与进程一样逐顶点取边：这样每条边都能记下"是从哪个文件（或端点）回推出来的"
            for key, _lo, _hi, dist in file_items:
                for ev in source.expand_object([(key, _lo, _hi)], "File", seen=included):
                    stats.rows_fetched += 1
                    include(ev, from_dist=dist, via_kind="File", via_key=key)
        if net_items:
            stats.object_expands += len(net_items)
            for key, _lo, _hi, dist in net_items:
                for ev in source.expand_object([(key, _lo, _hi)], "Network", seen=included):
                    stats.rows_fetched += 1
                    include(ev, from_dist=dist, via_kind="Network", via_key=key)
        stats.rounds += 1
        if log:
            # 逐轮报进度：闭包在大日志上要跑几十秒，不报进度等于看不见
            log(f"[closure] 第 {stats.rounds} 轮：已收 {stats.events_included} 条事件 / "
                f"展开 {stats.process_expands} 进程 + {stats.object_expands} 文件或端点 / "
                f"待考察 {sum(len(bucket) for bucket in pending.values())} / "
                f"取回 {stats.rows_fetched} 行 / "
                f"规则剔除 {sum(stats.dropped.values())} / 把关挡下 {stats.gate_blocked}")

    source.process_info_many(sorted({ev.pid for ev in included.values() if ev.pid}))
    events = sorted(included.values(), key=lambda e: (e.start, e.event_id))
    rows = _to_rows(events)               # 已经排好序，不再重复排一次
    out: dict[str, Any] = {
        "rows": rows, "stats": stats.as_dict(),
        # 真正被展开过的进程（不是"在边上出现过的进程"）：子进程把关的参照名单要用它。
        "expanded_processes": sorted(processed["Process"])}
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

    边行里多带 `dist` / `via_kind` / `via_key` 三样（结构上下文）：它们是**边上图事实的派生值**
    （这条边离终点最少几跳、展开时是从哪个顶点看到它的），判定时渲染给模型看，用于让模型知道
    这条边在链条上的位置；不参与任何收边判定，也不进报告。
    """
    rows: list[dict[str, Any]] = []
    for ev in events:
        rows.append({
            "rel": ev.rel, "owner": ev.owner, "other": ev.other, "other_label": ev.other_label,
            "event_id": ev.event_id,
            "starttime": ev.start, "endtime": ev.end, "syscall": ev.syscall, "bytes": ev.bytes,
            "dist": ev.dist, "via_kind": ev.via_kind, "via_key": ev.via_key,
            "other_process_id": ev.other_process_id,
            "process_id": ev.pid,
        })
    return rows
