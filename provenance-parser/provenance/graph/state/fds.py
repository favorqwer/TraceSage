"""句柄表：fd -> 客体，键是 (container, pid, fd)。

注意键里**没有 start_ns**：exec 换身份但进程的 fd 集合不变（除非 CLOEXEC），
所以句柄表按 pid 存、按 exec 规则裁剪，与 Process 主键解耦。

设计文档 §5.3 要求的能力逐条实现：clone 整表复制、dup 别名、dup2 覆盖、
close 注销、exec 按 CLOEXEC 裁剪、pipe 的 fd1/fd2 登记。

本版补充：
- 只读 open / O_PATH / O_TMPFILE 也登记 fd（不建边，只维护状态）；
- dup/dup2/dup3/fcntl(F_DUPFD) 从退出行返回值取新 fd；
- F_SETFD 更新 CLOEXEC；
- close_range 批量注销；
- 每进程表改为 LRU（get/register 移到队尾，超限淘汰队首）。
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FdEntry:
    kind: str          # file / directory / ipv4 / ipv6 / unix / pipe / memfd / other ...
    name: str          # 路径、元组、pipe:[inode]；O_TMPFILE 等匿名对象为空串
    proto: str = ""
    cloexec: bool = False


class FdTable:
    def __init__(self, cap: int = 4096) -> None:
        self.cap = cap
        self._by_pid: dict[tuple[str, int], OrderedDict[int, FdEntry]] = {}
        self.counts = {
            "registered": 0,
            "evicted": 0,
            "overwrite": 0,   # 登记时旧映射还在：要么 dup2 覆盖，要么 close 行丢了
            "fork_copies": 0,
            "pipe_registered": 0,
            "blind_dup": 0,
            "open_registered": 0,
            "open_fd_missing": 0,
            "dup_alias_miss": 0,
            "dup_alias_fallback": 0,
            "cloexec_set": 0,
            "cloexec_set_miss": 0,
            "cloexec_pruned": 0,
            "close_range_closed": 0,
            "close_range_blind": 0,
            "exit_closed": 0,
            "fd_table_hit": 0,
            "fd_from_token": 0,
            "dirfd_miss": 0,
            "dirfd_from_token": 0,
            "fchdir_miss": 0,
            "fchdir_from_token": 0,
        }

    def _bucket(self, cid: str, pid: int) -> OrderedDict[int, FdEntry]:
        return self._by_pid.setdefault((cid, pid), OrderedDict())

    def get(self, cid: str, pid: int, fd: int) -> FdEntry | None:
        bucket = self._by_pid.get((cid, pid))
        if not bucket:
            return None
        entry = bucket.get(fd)
        if entry is not None:
            # LRU：命中即移到队尾
            bucket.move_to_end(fd)
        return entry

    def register(self, cid: str, pid: int, fd: int, entry: FdEntry) -> None:
        bucket = self._bucket(cid, pid)
        if fd in bucket:
            # 旧映射还在：正常情况下 close 已被观测到并注销了；这里命中说明
            # fd 被静默复用（close 行丢失）或 dup2 覆盖——后者是正常语义。
            self.counts["overwrite"] += 1
            del bucket[fd]
        bucket[fd] = entry
        self.counts["registered"] += 1
        while len(bucket) > self.cap:
            bucket.popitem(last=False)
            self.counts["evicted"] += 1

    def dup(self, cid: str, pid: int, old: int, new: int,
            cloexec: bool = False) -> bool:
        """复制别名；旧 fd 不在表里返回 False，由调用方决定是否用退出行兜底。"""
        entry = self.get(cid, pid, old)
        if entry is None:
            return False
        self.register(cid, pid, new,
                      FdEntry(entry.kind, entry.name, entry.proto, cloexec))
        return True

    def set_cloexec(self, cid: str, pid: int, fd: int, cloexec: bool) -> bool:
        entry = self.get(cid, pid, fd)
        if entry is None:
            return False
        bucket = self._by_pid[(cid, pid)]
        bucket[fd] = FdEntry(entry.kind, entry.name, entry.proto, cloexec)
        return True

    def close(self, cid: str, pid: int, fd: int) -> None:
        bucket = self._by_pid.get((cid, pid))
        if bucket:
            bucket.pop(fd, None)
            if not bucket:
                self._by_pid.pop((cid, pid), None)

    def close_range(self, cid: str, pid: int, first: int, last: int) -> int:
        bucket = self._by_pid.get((cid, pid))
        if not bucket:
            return 0
        drop = [fd for fd in bucket if first <= fd <= last]
        for fd in drop:
            del bucket[fd]
        self.counts["close_range_closed"] += len(drop)
        if not bucket:
            self._by_pid.pop((cid, pid), None)
        return len(drop)

    def close_all(self, cid: str, pid: int) -> int:
        """进程退出时销毁整张表；防止 pid 复用后串到旧客体。"""
        bucket = self._by_pid.pop((cid, pid), None)
        n = len(bucket) if bucket else 0
        self.counts["exit_closed"] += n
        return n

    def prune_cloexec(self, cid: str, pid: int) -> int:
        bucket = self._by_pid.get((cid, pid))
        if not bucket:
            return 0
        drop = [fd for fd, entry in bucket.items() if entry.cloexec]
        for fd in drop:
            del bucket[fd]
        self.counts["cloexec_pruned"] += len(drop)
        if not bucket:
            self._by_pid.pop((cid, pid), None)
        return len(drop)

    def fork(self, cid: str, parent_pid: int, child_pid: int) -> None:
        parent = self._by_pid.get((cid, parent_pid))
        if not parent:
            return
        self._by_pid[(cid, child_pid)] = OrderedDict(parent)
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
