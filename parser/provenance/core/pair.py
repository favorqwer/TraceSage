"""进入行 / 退出行配对（§5.2）。

键：(container, pid, tid, 调用名)；同键内按时间/延迟匹配。

本版是“混合配对”：
- 键带 ``tid``，不会把同进程不同线程的同名调用混在一起；
- 退出行有 ``evt.latency`` 时，精确匹配 ``start_ns == end_ns - latency``，
  再在 ``latency_tolerance_ns`` 内找唯一候选；
- 多个候选且无法唯一确定时**不消费**，记 ``ambiguous``，宁可缺边不配错边；
- 同键出现多个 pending 时不做盲 FIFO（一个线程不可能有两个同名 syscall 在途，
  多个 pending 就是“有退出行丢失”的信号）；
- 只有 latency 缺失、且同键恰好一个 pending 时，才允许单 pending 兜底；
- 阻塞类调用不按 5 秒超时淘汰；流结束时统一计“未配对”。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .events import EventRow

# 这些调用可能长时间阻塞，进入行不能因为"太老"被淘汰
BLOCKING = frozenset(
    {
        "accept", "accept4",
        "read", "readv", "pread", "pread64", "preadv", "preadv2",
        "recvfrom", "recvmsg", "recvmmsg", "recv",
        "wait4", "waitid", "waitpid",
        "poll", "select", "pselect6", "ppoll", "epoll_wait", "epoll_pwait",
        "futex", "nanosleep", "clock_nanosleep",
    }
)


# 单向事件：sysdig 只给一行（dir 恒为 ">"），永远等不到退出行。
# 实测（场景 5 全量）：switch / procexit / exit_group / exit /
# signaldeliver / sigreturn 的退出行数都是 0。把它们塞进配对池会把
# "退出边"整族吞掉，并污染未配对计数。
SINGLE_LINE = frozenset(
    {"switch", "sched_switch", "procexit", "exit", "exit_group",
     "signaldeliver", "sigreturn", "rt_sigtimedwait"}
)


def should_pair(row: EventRow) -> bool:
    return row.call not in SINGLE_LINE


@dataclass(slots=True, eq=False)
class _Pending:
    row: EventRow


class PairingPool:
    def __init__(
        self,
        timeout_ns: int = 5_000_000_000,
        cap: int = 100_000,
        latency_tolerance_ns: int = 1_000,
    ) -> None:
        self.timeout_ns = timeout_ns
        self.cap = cap
        self.latency_tolerance_ns = latency_tolerance_ns
        self._q: dict[tuple[str, int, int, str], deque[_Pending]] = {}
        self._size = 0
        self.counts = {
            "paired": 0,
            "exact": 0,
            "tolerance": 0,
            "single_pending": 0,
            "ambiguous": 0,
            "no_partner": 0,
            "latency_missing": 0,
            "timeout_evicted": 0,
            "cap_evicted": 0,
        }

    @staticmethod
    def _key(row: EventRow) -> tuple[str, int, int, str]:
        return (row.container_id, row.pid, row.tid, row.call)

    def push(self, row: EventRow) -> list[EventRow]:
        key = self._key(row)
        queue = self._q.setdefault(key, deque())
        queue.append(_Pending(row))
        self._size += 1
        evicted: list[EventRow] = []

        # 非阻塞调用：同键里出现更晚的进入行时，淘汰老的非阻塞进入行。
        # 阻塞调用不做时间淘汰：它们可能合法地停留很久；是否可配由
        # take() 的时间校验决定。
        if row.call not in BLOCKING:
            while len(queue) > 1 and row.ns - queue[0].row.ns > self.timeout_ns:
                old = queue.popleft()
                self._size -= 1
                self.counts["timeout_evicted"] += 1
                evicted.append(old.row)

        while self._size > self.cap:
            victim = max(self._q, key=lambda k: len(self._q[k]))
            old = self._q[victim].popleft()
            self._size -= 1
            self.counts["cap_evicted"] += 1
            evicted.append(old.row)
            if not self._q[victim]:
                del self._q[victim]
        return evicted

    def _remove(
        self,
        key: tuple[str, int, int, str],
        queue: deque[_Pending],
        pending: _Pending,
    ) -> bool:
        try:
            queue.remove(pending)
        except ValueError:
            return False
        self._size -= 1
        if not queue:
            del self._q[key]
        return True

    def take(self, row: EventRow) -> EventRow | None:
        key = self._key(row)
        queue = self._q.get(key)
        if not queue:
            self.counts["no_partner"] += 1
            return None

        latency = row.latency_ns
        if latency is not None:
            # 1) 精确：sysdig 的 latency 就是这两条记录算出来的，真实伙伴
            #    一定满足 start_ns == end_ns - latency。
            expected = row.ns - latency
            for pending in queue:
                if pending.row.ns == expected:
                    if self._remove(key, queue, pending):
                        self.counts["paired"] += 1
                        self.counts["exact"] += 1
                        return pending.row
                    break

            # 2) 容差内唯一候选：只有严格优于第二名才配。
            candidates: list[tuple[_Pending, int]] = []
            for pending in queue:
                if pending.row.ns > row.ns:
                    continue
                delta = abs((row.ns - pending.row.ns) - latency)
                if delta <= self.latency_tolerance_ns:
                    candidates.append((pending, delta))
            if len(candidates) == 1:
                pending = candidates[0][0]
                if self._remove(key, queue, pending):
                    self.counts["paired"] += 1
                    self.counts["tolerance"] += 1
                    return pending.row
            if len(candidates) > 1:
                candidates.sort(key=lambda item: item[1])
                if candidates[0][1] < candidates[1][1]:
                    pending = candidates[0][0]
                    if self._remove(key, queue, pending):
                        self.counts["paired"] += 1
                        self.counts["tolerance"] += 1
                        return pending.row
                self.counts["ambiguous"] += 1
                return None

            # latency 已观测但对不上：说明这条退出行不是当前 pending 的。
            # 不消费、不猜；留下 pending 等它真正的退出行。
            if len(queue) > 1:
                self.counts["ambiguous"] += 1
            else:
                self.counts["no_partner"] += 1
            return None

        # 3) latency 缺失：只有“同键恰好一个 pending”才允许兜底。
        self.counts["latency_missing"] += 1
        if len(queue) == 1 and queue[0].row.ns <= row.ns:
            pending = queue[0]
            if self._remove(key, queue, pending):
                self.counts["paired"] += 1
                self.counts["single_pending"] += 1
                return pending.row

        if len(queue) > 1:
            self.counts["ambiguous"] += 1
        else:
            self.counts["no_partner"] += 1
        return None

    def drain(self) -> list[EventRow]:
        rows: list[EventRow] = [p.row for q in self._q.values() for p in q]
        self._q.clear()
        self._size = 0
        return rows

    @property
    def size(self) -> int:
        return self._size
