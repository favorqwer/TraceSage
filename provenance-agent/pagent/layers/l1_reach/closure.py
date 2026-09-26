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
   命中 `core/edge_rules.py` 的 `shared_channel_label` 的文件顶点（内核现生成的伪文件、
   设备节点、系统运行目录及其中的套接字）**只收边、不展开**——读取它的那条边照样进闭包，
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
三条规则本身的方向约束、零字节的数据读取（边照收，只是不从它的顶点往回找）、
子进程把关；每一类都逐条计数，进 `stats.dropped`。

## 输出

`run_closure` 返回闭包的**事件集合**（`events`）、第 2 层折叠能直接吃的边行（`rows`）、
计数（`stats`），以及**真正被展开过的进程名单**（`expanded_processes`）——
`expanded_processes` 是 `siblings.py` 定主干名单的参照，被把关挡下的子进程不在里面。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from ...core import edge_rules
from .steps import make_step_key

_CONSUMER_RELS = ("f2p", "n2p")

# 数据读取类操作名（已归一）：只有它们才用"字节数"判断有没有拿到内容。
# `execve` / `accept` / `connect` 这类事件的字节数按设计就是 0，不能用它当"没交付"的判据。
_DATA_READ_SYSCALLS = ("read", "recvfrom")

# 一轮里处理待考察顶点的顺序（只影响处理顺序，不影响收哪些边）
_KIND_ORDER = ("File", "Network", "Process")


def content_triple_of(rel: str, syscall: str, owner: str, other: str,
                      other_label: str) -> tuple[str, str, str, str]:
    """(源内容, 操作名, 目标内容, 源标签)——与折叠 / 粗筛的口径一致。

    取边来源、闭包引擎与索引构造必须都走这一个函数：规则判定按它下结论，口径一分岔，
    索引里预先算好的规则编码就会与遍历时现算的结果对不上。
    """
    if rel in ("p2f", "p2n"):
        return owner, syscall, other, "Process"
    if rel in _CONSUMER_RELS:
        return other, syscall, owner, other_label
    return other, syscall, owner, "Process"


def rule_code_of(rel: str, syscall: str, owner: str, other: str, other_label: str) -> int:
    """这条边命中哪条结构性伪边规则（`edge_rules.RULE_CODE_OF` 的编码，0 = 不命中）。"""
    name, _label = edge_rules.rule_of(*content_triple_of(rel, syscall, owner, other, other_label))
    return edge_rules.RULE_CODE_OF.get(name, 0)


class Event:
    """一条图上的边（事件）。`pid` 是按归属规则拥有它的进程。

    用固定槽位的普通类而不是数据类：闭包在大日志上要建上百万个，构造开销直接落在总耗时里。

    `rule_code` 是这条边命中哪条结构性伪边规则（`edge_rules.RULE_CODE_OF`）：`-1` 表示来源
    没有预先判定、遍历时现算（手工构造的事件与数据库直查来源走这条路），`0` 表示已判定为不命中。
    """

    __slots__ = ("event_id", "rel", "syscall", "bytes", "start", "end", "pid", "owner",
                 "other", "other_label", "other_process_id", "rule_code")

    def __init__(self, event_id: int, rel: str, syscall: str, bytes: int, start: int, end: int,
                 pid: str, owner: str, other: str, other_label: str, other_process_id: str = "",
                 rule_code: int = -1) -> None:
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
        self.rule_code = rule_code

    def content_triple(self) -> tuple[str, str, str, str]:
        """(源内容, 操作名, 目标内容, 源标签)——与折叠 / 粗筛的口径一致。"""
        return content_triple_of(self.rel, self.syscall, self.owner, self.other, self.other_label)


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
        """把进程静态属性灌进内存缓存（步骤摘要要用，不算业务查询）。"""

    def iter_object_edges(self, pid: str):
        """把这个进程与文件 / 网络顶点相连的读写边逐个给出：(关系类型, 操作名, 对象键, 对象标签)。

        只用于"这个进程和主干有没有过一次读写来往"这件判定（见 `siblings.py`）：调用方随时
        可以中断（只取到第一个命中即停），因此不会为一个进程建出无上限的中间结构。
        两条来源必须给出相同的集合。
        """

    def close(self) -> None:
        """释放句柄（索引来源为空实现）。"""

    def stats(self) -> dict[str, Any]:
        """来源侧的计数（查询次数、取回行数等），供报告与消融表用。"""


@dataclass
class _Pending:
    threshold: int
    kind: str
    key: str


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
    dropped: dict[str, int] = field(default_factory=dict)

    def note_drop(self, code: str) -> None:
        self.dropped[code] = self.dropped.get(code, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {"rounds": self.rounds, "process_expands": self.process_expands,
                "object_expands": self.object_expands, "reexpands": self.reexpands,
                "rows_fetched": self.rows_fetched, "events_included": self.events_included,
                "empty_reads": self.empty_reads, "frontier_peak": self.frontier_peak,
                "dropped": dict(sorted(self.dropped.items()))}


def run_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                log: Optional[Callable[[str], None]] = None,
                child_allowed: Optional[Callable[[str, str], bool]] = None) -> dict[str, Any]:
    """算反向闭包。返回 `{"events": [...], "rows": [...], "stats": {...},
    "expanded_processes": [...]}`。

    `child_allowed` 是子进程把关函数（父进程标识, 子进程标识）——不传就全收。
    只有"从父进程那一侧看到的派生边"才问它；子进程自己那条派生边照收。

    `rows` 是折叠（第 2 层）能直接吃的边行：`rel / owner / other / other_label / syscall /
    bytes / starttime / endtime / event_id / step_key`。**不设任何条数上限。**
    """
    included: dict[int, Event] = {}
    # 待考察清单与"已展开到哪一刻"都按顶点类型分开存：省掉每个顶点拼一个带前缀的字符串键，
    # 也省掉每一轮把两边混在一起比对。三类的处理顺序由 `_KIND_ORDER` 固定，结果与顺序无关。
    pending: dict[str, dict[str, _Pending]] = {kind: {} for kind in _KIND_ORDER}
    processed: dict[str, dict[str, int]] = {kind: {} for kind in _KIND_ORDER}
    stats = _Stats()

    def push(kind: str, key: str, threshold: int) -> None:
        """把一个顶点按门限放进待考察清单（门限不高于已展开过的就跳过）。"""
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
        if cur is None or threshold > cur.threshold:
            bucket[key] = _Pending(threshold=int(threshold), kind=kind, key=key)

    def include(ev: Event, *, ctx_threshold: int = 0, apply_rules: bool = True,
                expanded: Optional[str] = None) -> bool:
        """收一条事件；被规则剔除的返回 False（计数）。

        `expanded` 是"这条边是从哪个顶点展开出来的"（只有进程展开会传；种子与对象展开传空），
        用来判定派生边上的子进程是不是"被展开的那个进程生出来的"——子进程把关只对这种边生效。
        """
        if ev.event_id in included:
            return False
        if apply_rules:
            code = ev.rule_code
            if code < 0:
                # 来源没预先判定（手工构造的事件、数据库直查来源）：现算
                src, syscall, dst, src_label = ev.content_triple()
                name = edge_rules.rule_of(src, syscall, dst, src_label)[0]
                if name:
                    stats.note_drop(name)
                    return False
            elif code:
                # 索引里建的时候就算好了：只查一次名字，不重算
                stats.note_drop(edge_rules.RULE_CODE_NAMES[code])
                return False
        # 零字节的数据读取：什么都没拿到，因此不再从它的顶点往回找（边本身仍然收）
        empty_read = (ev.rel in _CONSUMER_RELS and ev.syscall in _DATA_READ_SYSCALLS
                      and int(ev.bytes or 0) <= 0)
        included[ev.event_id] = ev
        stats.events_included += 1
        if empty_read:
            stats.empty_reads += 1
            push("Process", ev.pid, ev.start)      # 进程状态这条通道照走
            return True

        if ev.rel in ("p2f", "p2n"):
            push("Process", ev.pid, ev.start)
        elif ev.rel in _CONSUMER_RELS:
            push("Process", ev.pid, ev.start)
            # 写入者的时间界取读取的结束时刻：流式读写允许边写边读
            push(ev.other_label, ev.other, ev.end)
        elif ev.rel == "p2p":
            # 派生事件：往回只走父进程那一侧（子进程是下游，它的活动由文件 / 通道顶点接回来）
            push("Process", ev.other_process_id, ev.start)
            # 同一主体派生出去的其它子进程也算上游（有意识的超集口径），受子进程把关约束
            from_parent_side = expanded is not None and ev.pid != expanded
            if from_parent_side and child_allowed is not None and not child_allowed(expanded, ev.pid):
                stats.note_drop("sibling_not_linked")
            else:
                push("Process", ev.pid, ctx_threshold or ev.start)
        return True

    # --- 种子：终点事件本身 + 它两端顶点的门限 ---
    for seed in seeds:
        include(seed, apply_rules=False)

    while pending["Process"] or pending["File"] or pending["Network"]:
        # 按门限从高到低、同门限按类型与顶点键排序：只影响处理顺序（可复现），不影响收哪些边
        items: list[tuple[int, int, str, str]] = []
        for rank, kind in enumerate(_KIND_ORDER):
            bucket = pending[kind]
            if not bucket:
                continue
            items.extend((item.threshold, rank, kind, item.key) for item in bucket.values())
            bucket.clear()
        items.sort(key=lambda it: (-it[0], it[1], it[2]))
        stats.frontier_peak = max(stats.frontier_peak, len(items))

        proc_items: list[tuple[str, int, int]] = []
        file_items: list[tuple[str, int, int]] = []
        net_items: list[tuple[str, int, int]] = []
        for threshold, _rank, kind, key in items:
            done = processed[kind]
            prev = done.get(key)
            if prev is not None and threshold <= prev:
                continue
            lo = prev if prev is not None else -1
            if prev is not None:
                stats.reexpands += 1
            done[key] = threshold
            if kind == "Process":
                proc_items.append((key, lo, threshold))
            elif kind == "Network":
                net_items.append((key, lo, threshold))
            else:
                file_items.append((key, lo, threshold))

        if proc_items:
            stats.process_expands += len(proc_items)
            threshold_by_pid = {key: hi for key, _lo, hi in proc_items}
            for key, _lo, _hi in proc_items:
                # 逐个顶点取边（而不是一批一起取）：这样才能知道每条派生边是"从哪一个顶点看出去的"
                # （子进程把关要问"是哪个父进程想带走这个子进程"）。取数来源本身是按顶点逐块读的，
                # 逐顶点调用与批量调用的行集合、顺序完全一致。
                for ev in source.expand_process([(key, _lo, _hi)], seen=included):
                    stats.rows_fetched += 1
                    # 门限取"正在展开的那个顶点"的门限：派生边属于父进程那一侧时用它决定子进程收多远
                    ctx = (threshold_by_pid.get(ev.other_process_id)
                           or threshold_by_pid.get(ev.pid) or ev.start)
                    include(ev, ctx_threshold=ctx, expanded=key)
        if file_items:
            stats.object_expands += len(file_items)
            for ev in source.expand_object(file_items, "File", seen=included):
                stats.rows_fetched += 1
                include(ev)
        if net_items:
            stats.object_expands += len(net_items)
            for ev in source.expand_object(net_items, "Network", seen=included):
                stats.rows_fetched += 1
                include(ev)
        stats.rounds += 1
        if log:
            # 逐轮报进度：闭包在大日志上要跑几十秒，不报进度等于看不见
            log(f"[closure] 第 {stats.rounds} 轮：已收 {stats.events_included} 条事件 / "
                f"展开 {stats.process_expands} 进程 + {stats.object_expands} 文件或端点 / "
                f"待考察 {sum(len(bucket) for bucket in pending.values())} / "
                f"取回 {stats.rows_fetched} 行 / "
                f"规则剔除 {sum(stats.dropped.values())}")

    source.process_info_many(sorted({ev.pid for ev in included.values() if ev.pid}))
    events = sorted(included.values(), key=lambda e: (e.start, e.event_id))
    rows = _to_rows(events)               # 已经排好序，不再重复排一次
    return {"events": events, "rows": rows, "stats": stats.as_dict(),
            # 真正被展开过的进程（不是"在边上出现过的进程"）：子进程把关的参照名单要用它。
            "expanded_processes": sorted(processed["Process"])}


def _to_rows(events: list[Event]) -> list[dict[str, Any]]:
    """把事件转成第 2 层能直接折叠的边行（步骤键 = 该进程实例最早一条被收进来的边的时刻）。

    `events` 必须已经按（开始时刻, 事件编号）排好序——闭包引擎排过一次，这里不再排第二遍。
    """
    first_start: dict[str, int] = {}
    for ev in events:
        cur = first_start.get(ev.pid)
        if cur is None or ev.start < cur:
            first_start[ev.pid] = ev.start
    rows: list[dict[str, Any]] = []
    for ev in events:
        rows.append({
            "rel": ev.rel, "owner": ev.owner, "other": ev.other, "other_label": ev.other_label,
            "other_process_id": ev.other_process_id, "event_id": ev.event_id,
            "starttime": ev.start, "endtime": ev.end, "syscall": ev.syscall, "bytes": ev.bytes,
            "step_key": make_step_key(ev.pid, first_start[ev.pid]),
        })
    return rows
