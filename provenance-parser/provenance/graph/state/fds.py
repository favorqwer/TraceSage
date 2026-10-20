"""句柄表：fd -> 客体，键是 (container, pid, fd)。

注意键里**没有 born_ns**：exec 换身份但进程的 fd 集合不变（除非 CLOEXEC），
所以句柄表按 pid 存、按 exec 规则裁剪，与 Process 主键解耦。

设计文档 §5.3 要求的能力逐条实现：clone 整表复制、dup 别名、dup2 覆盖、
close 注销、exec 按 CLOEXEC 裁剪、pipe 的 fd1/fd2 登记。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FdEntry:
    kind: str          # file / directory / ipv4 / ipv6 / unix / pipe / other ...
    name: str          # 路径、元组、pipe:[inode]
    proto: str = ""
    cloexec: bool = False


class FdTable:
    def __init__(self, cap: int = 4096) -> None:
        self.cap = cap
        self._by_pid: dict[tuple[str, int], dict[int, FdEntry]] = {}
        self.counts = {
            "registered": 0,
            "evicted": 0,
            "overwrite": 0,   # 登记时旧映射还在：要么 dup2 覆盖，要么 close 行丢了
            "fork_copies": 0,
            "pipe_registered": 0,
        }

    def _bucket(self, cid: str, pid: int) -> dict[int, FdEntry]:
        return self._by_pid.setdefault((cid, pid), {})

    def get(self, cid: str, pid: int, fd: int) -> FdEntry | None:
        return self._by_pid.get((cid, pid), {}).get(fd)

    def register(self, cid: str, pid: int, fd: int, entry: FdEntry) -> None:
        bucket = self._bucket(cid, pid)
        if fd in bucket:
            # 旧映射还在：正常情况下 close 已被观测到并注销了；这里命中说明
            # fd 被静默复用（close 行丢失）或 dup2 覆盖——后者是正常语义。
            self.counts["overwrite"] += 1
        bucket[fd] = entry
        self.counts["registered"] += 1
        if len(bucket) > self.cap:
            oldest = next(iter(bucket))
            del bucket[oldest]
            self.counts["evicted"] += 1

    def dup(self, cid: str, pid: int, old: int, new: int, cloexec: bool = False) -> None:
        entry = self.get(cid, pid, old)
        if entry is None:
            return
        self.register(cid, pid, new, FdEntry(entry.kind, entry.name, entry.proto, cloexec))

    def close(self, cid: str, pid: int, fd: int) -> None:
        bucket = self._by_pid.get((cid, pid))
        if bucket:
            bucket.pop(fd, None)

    def prune_cloexec(self, cid: str, pid: int) -> int:
        bucket = self._by_pid.get((cid, pid))
        if not bucket:
            return 0
        drop = [fd for fd, entry in bucket.items() if entry.cloexec]
        for fd in drop:
            del bucket[fd]
        return len(drop)

    def fork(self, cid: str, parent_pid: int, child_pid: int) -> None:
        parent = self._by_pid.get((cid, parent_pid))
        if not parent:
            return
        self._by_pid[(cid, child_pid)] = dict(parent)
        self.counts["fork_copies"] += 1

    def dir_path(self, cid: str, pid: int, fd: int) -> str:
        entry = self.get(cid, pid, fd)
        if entry is not None and entry.kind == "directory":
            return entry.name
        return ""

    def stats(self) -> dict[str, int]:
        out = dict(self.counts)
        out["open_fds"] = sum(len(v) for v in self._by_pid.values())
        out["processes"] = len(self._by_pid)
        return out
