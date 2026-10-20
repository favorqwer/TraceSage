"""进入行 / 退出行配对（§5.2）。

键：(container, pid, tid, 调用名)，同键先进先出。
阻塞类调用的进入行不按超时淘汰，只在流结束时统一计"未配对"。
"""

from __future__ import annotations

from collections import deque

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


class PairingPool:
    def __init__(self, timeout_ns: int = 5_000_000_000, cap: int = 100_000) -> None:
        self.timeout_ns = timeout_ns
        self.cap = cap
        self._q: dict[tuple[str, int, int, str], deque[EventRow]] = {}
        self._size = 0
        self.counts = {"paired": 0, "timeout_evicted": 0, "cap_evicted": 0}

    @staticmethod
    def _key(row: EventRow) -> tuple[str, int, int, str]:
        return (row.container_id, row.pid, row.tid, row.call)

    def push(self, row: EventRow) -> list[EventRow]:
        key = self._key(row)
        queue = self._q.setdefault(key, deque())
        queue.append(row)
        self._size += 1
        evicted: list[EventRow] = []

        if row.call not in BLOCKING:
            while len(queue) > 1 and row.ns - queue[0].ns > self.timeout_ns:
                evicted.append(queue.popleft())
                self._size -= 1
                self.counts["timeout_evicted"] += 1

        while self._size > self.cap:
            victim = max(self._q, key=lambda k: len(self._q[k]))
            evicted.append(self._q[victim].popleft())
            self._size -= 1
            self.counts["cap_evicted"] += 1
            if not self._q[victim]:
                del self._q[victim]
        return evicted

    def take(self, row: EventRow) -> EventRow | None:
        key = self._key(row)
        queue = self._q.get(key)
        if not queue:
            return None
        enter = queue.popleft()
        self._size -= 1
        self.counts["paired"] += 1
        if not queue:
            del self._q[key]
        return enter

    def drain(self) -> list[EventRow]:
        rows: list[EventRow] = []
        for queue in self._q.values():
            rows.extend(queue)
        self._q.clear()
        self._size = 0
        return rows

    @property
    def size(self) -> int:
        return self._size
