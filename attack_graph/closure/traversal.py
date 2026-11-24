"""闭包引擎：反向闭包（时间门限内的因果回溯）与受限前向补链。

本文件只依赖 `domain` 与 `closure.policy`。它不导入 `rules`、`llm`、`routing`，
也不直接接触 Neo4j：取边一律通过 `GraphSource` 协议，正式实现是顶点-时间索引。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

from domain.edge import CHANNEL_BITS, CONSUMER_RELS, PRODUCER_RELS, is_derivation
from domain.taxonomy import is_forward_carrier
from closure.policy import event_ruling

# 待考察清单的排序类别顺序：只决定同一轮里先处理谁，不影响收哪些边。
PENDING_ORDER = ("File", "Network", "Process")
# 同一轮里逐顶点取边的顺序：决定同一条边被两个顶点同时找到时，`via` 取哪一份。
EXPAND_ORDER = ("Process", "File", "Network")
# 前向补链：同一文件的外部读者超过这个数量时，改为逐个进程确认是否有敏感动作再收种子。
# 它只切换探测算法，不丢边。
FORWARD_SEED_EXPAND_LIMIT = 10

_SEED_BIT = CHANNEL_BITS["seed"]


class Event:
    """一条图上的边（事件）。`pid` 是按归属规则拥有它的进程。

    用固定槽位的普通类而不是数据类：闭包在大日志上要建上百万个，构造开销直接落在总耗时里。
    规则命中与否不在这里预存：影响往回走的判定在取边时按边的形状现算并缓存（见 `include`）。
    """

    __slots__ = ("event_id", "rel", "syscall", "bytes", "start", "end", "pid", "owner",
                 "other", "other_label", "other_process_id", "effect",
                 "dist", "via_kind", "via_key", "support")

    def __init__(self, event_id: int, rel: str, syscall: str, bytes: int, start: int, end: int,
                 pid: str, owner: str, other: str, other_label: str, other_process_id: str = "",
                 effect: str = "",
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
        # 成败（图上 result 换算，与评分口径一致）：success / failure / 空 = 未观测
        self.effect = effect
        # 结构上下文（只用于判定时的渲染与束的细分，不参与收边判定）：离终点事件最少几跳
        # （种子 = 0）、这条边是从哪个顶点被回推出来的（`via_kind` 为空 = 终点事件本身）、
        # 以及入闭包通道的位掩码（见 `domain.edge.CHANNEL_BITS`）。
        self.dist = dist
        self.via_kind = via_kind
        self.via_key = via_key
        self.support = support


class GraphSource(Protocol):
    """取边的来源：数据库直查，或顶点-时间索引快照（两者必须给出相同结果）。

    `seen` 是"已经收进闭包的边"的映射，键为 `(event_id, rel)`。给了它，来源可以把这类边
    直接跳掉、不再重造内部表示。它只影响快慢：给了要跳过、不给也不影响收哪些边。
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

    def parent_of_process(self, key: str) -> Optional[str]:
        """按进程节点上记录的 ppid 找父进程（同容器、出生不晚于子进程，取最近的一个）。"""

    def birth_of_process(self, key: str) -> int:
        """进程键里的出生时刻（纳秒）；解析失败返回 0。"""

    def process_info(self, process_id: str) -> dict[str, Any]:
        """进程静态属性（pid / 显示名 / 可执行路径 / 命令行）。"""

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


def _clamp_threshold(kind: str, threshold: int, poi_t0: int) -> int:
    """进程状态通道的上界固定取终点事件时刻：同一主体在终点事件之前的活动都算可能影响它。"""
    if kind == "Process" and threshold < poi_t0:
        return poi_t0
    return threshold


def run_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                log: Optional[Callable[[str], None]] = None,
                with_events: bool = True) -> dict[str, Any]:
    """算反向闭包。返回 `{"rows": [...], "stats": {...}}`，`with_events=True`（默认）时另有 `"events"`。

    `rows` 是折叠（`closure.fold`）能直接吃的边行：`rel / owner / other / other_label /
    syscall / bytes / starttime / endtime / event_id / process_id / dist / via_kind / via_key`
    （`process_id` 是按归属规则拥有这条边的进程的标识）。
    **不设任何条数上限。**（`dist` 是这条边离终点事件最少几跳，`via_*` 是它从哪个顶点被回推出来——
    只用干判定时的上下文渲染，不参与收边判定。）

    `with_events=False` 供"只要边行"的调用方使用：事件集合照样在内部用来生成边行，但不放进返回值。
    """
    included: dict[tuple[int, str], Event] = {}
    # 待考察清单与"已展开到哪一刻"都按顶点类型分开存：省掉每个顶点拼一个带前缀的字符串键，
    # 也省掉每一轮把两边混在一起比对。三类的处理顺序由 `PENDING_ORDER` 固定，结果与顺序无关；
    # 只有同跳数时 `via` 取哪一份受 `EXPAND_ORDER` 影响。
    pending: dict[str, dict[str, _Pending]] = {kind: {} for kind in PENDING_ORDER}
    processed: dict[str, dict[str, int]] = {kind: {} for kind in PENDING_ORDER}
    stats = _Stats()

    def push(kind: str, key: str, threshold: int, dist: int = 0) -> None:
        """把一个顶点按门限放进待考察清单（门限不高于已展开过的就跳过）。

        `dist` 是这个顶点离终点事件的最少跳数：同一个顶点被多次推进时取最小的那个。
        """
        if not key:
            return
        threshold = _clamp_threshold(kind, int(threshold), poi_t0)
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
        no_expand = "no_expand" in event_ruling(ev.rel, ev.syscall, ev.bytes).effects
        ev.dist = dist
        ev.via_kind, ev.via_key = via_kind, via_key
        ev.support = mask
        included[edge_key] = ev
        stats.events_included += 1
        if no_expand:
            stats.empty_reads += 1
            push("Process", ev.pid, ev.start, dist)      # 进程状态这条通道照走
            return True

        if ev.rel in PRODUCER_RELS:
            push("Process", ev.pid, ev.start, dist)
        elif ev.rel in CONSUMER_RELS:
            push("Process", ev.pid, ev.start, dist)
            # 写入者的时间界取读取的结束时刻：流式读写允许边写边读
            push(ev.other_label, ev.other, ev.end, dist)
        elif is_derivation(ev.rel):
            # 派生事件：父进程那一侧往回走；同一主体派生出去的其它子进程也算上游（有意识的超集口径）
            push("Process", ev.other_process_id, ev.start, dist)
            push("Process", ev.pid, ev.start, dist)
        return True

    # --- 种子：终点事件本身 + 它两端顶点的门限 ---
    for seed in seeds:
        include(seed)

    while any(pending[kind] for kind in PENDING_ORDER):
        # 按门限从高到低、同门限按类型与顶点键排序：只影响处理顺序（可复现），不影响收哪些边。
        # 跳数为什么是最小值：种子先把跳数 0 的顶点推进清单，之后一个顶点的最小跳数只可能由上
        # 一轮里已推进的顶点带来，且推入的顶点最早在下一轮被展开——所以每个顶点第一次被展开时
        # 带的就是最小跳数，与轮内处理顺序无关。
        items: list[tuple[int, int, str, str, int]] = []
        for rank, kind in enumerate(PENDING_ORDER):
            bucket = pending[kind]
            if not bucket:
                continue
            items.extend((item.threshold, rank, kind, item.key, item.dist)
                         for item in bucket.values())
            bucket.clear()
        items.sort(key=lambda it: (-it[0], it[1], it[2]))
        stats.frontier_peak = max(stats.frontier_peak, len(items))

        by_kind: dict[str, list[tuple[str, int, int, int]]] = {
            kind: [] for kind in EXPAND_ORDER}
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
                # 记录到的父子关系（ppid）：展开一个进程时，把它记录的父进程一并推进待考察清单。
                # 门限取子进程出生时刻；不新增任何边——父进程的边本来就是图里的真实边。
                # 只在本容器内解析；容器进程的 ppid 属于宿主命名空间，本版不处理。
                parent_key = source.parent_of_process(key)
                if parent_key:
                    push("Process", parent_key, source.birth_of_process(key), dist + 1)
            by_kind[kind].append((key, lo, threshold, dist))

        if by_kind["Process"]:
            stats.process_expands += len(by_kind["Process"])
        stats.object_expands += len(by_kind["File"]) + len(by_kind["Network"])
        # 逐顶点取边（而不是一批一起取）：这样每条边都能记下"是从哪个顶点展开出来的"。
        # 取数来源本身是按顶点逐块读的，逐顶点调用与批量调用的行集合、顺序完全一致。
        for kind in EXPAND_ORDER:
            for key, lo, hi, dist in by_kind[kind]:
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
    """把事件转成折叠能直接吃的边行（每行带归属进程的标识 `process_id`）。

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
            "effect": ev.effect,
            "dist": ev.dist, "via_kind": ev.via_kind, "via_key": ev.via_key,
            "support": ev.support,
            "other_process_id": ev.other_process_id,
            "process_id": ev.pid,
        })
    return rows


def find_forward_seeds(source: GraphSource, rows: list[dict[str, Any]],
                       closed_processes: set[str], poi_t0: int) -> list[Event]:
    """受限前向补链：闭包内写入的常规数据载体文件在写入后被闭包外进程读取。"""
    written_files: dict[str, int] = {}
    for r in rows:
        if (str(r.get("rel") or "") == "p2f"
                and str(r.get("other_label") or "") == "File"
                and int(r.get("bytes") or 0) > 0):
            path = str(r.get("other") or "")
            if not is_forward_carrier(path):
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
        if len(pids) <= FORWARD_SEED_EXPAND_LIMIT:
            forward_seeds.extend(external)
        else:
            for evt in external:
                evts_p = source.expand_process([(evt.pid, evt.start, poi_t0)])
                has_sensitive = any(
                    e.rel in PRODUCER_RELS or is_derivation(e.rel)
                    for e in evts_p
                )
                if has_sensitive:
                    forward_seeds.append(evt)
    return forward_seeds


def run_causal_closure(source: GraphSource, seeds: list[Event], *, poi_t0: int = 0,
                       forward_chain: bool = True,
                       log: Optional[Callable[[str], None]] = None,
                       with_events: bool = False) -> dict[str, Any]:
    """计算因果闭包：反向闭包 +（可选）受限前向补链。

    统一执行：
    1. 沿时序因果规则回溯反向因果闭包；
    2. 基于常规数据载体文件，向前探测外部读者并补充因果种子。
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
