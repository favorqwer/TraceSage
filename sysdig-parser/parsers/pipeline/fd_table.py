"""Per-process fd -> pipe-inode table built from pipe lifecycle events.

sysdig 只在 pipe() 退出记录中给出管道身份（ino=...）；read/write 记录上的
裸 fd=N(<p>) 不含任何身份信息。本表按内核 fd 生命周期维护 (pid, fd) -> ino
映射，供 EntityRegistry 把裸匿名管道解析为真实顶点 pipe:[<ino>]：

    pipe / pipe2 退出      -> fd1/fd2 双端登记同一 ino
    clone / fork / vfork 退出 -> 子进程复制父映射（fd 表随 fork 复制；
                              管道两端的读/写进程正是经 fork 获得管道 fd，
                              不做继承则 cat|nc 这类管道永远解析失败）
    dup                    -> 进入记录暂存 oldfd（fd= 字段）
    dup2 / dup3            -> 同 dup，但源 fd 在 oldfd= 字段（按字段名提取；
                              bash 接线管道也存在 dup2 形态，其他采集兼容）
    fcntl(F_DUPFD*)        -> 同 dup
    close 进入行           -> 立即失效（进入侧钩子，早于配对处理；退出
                              记录丢失时仍能失效。fd 复用会使陈旧映射
                              误指，必须跟踪：实测 close 失效 192 次、
                              登记覆盖 12 次）。close 事件自身的实体抽取
                              因此 miss 而落入哨兵回落——不建边、被无边
                              顶点过滤，无实害，但 resolve_misses 计数
                              含这部分非真缺失
    execve                 -> fd 表跨 exec 存续，无需处理

解析失败（pipe() 早于采集起点、事件丢失）由调用方回落按秒分桶哨兵。键为
记录的 proc.pid：线程事件同样以 proc.pid 归属（本日志实测陈旧误指 0 次）。
进程退出不清理映射——pid 空间有界，泄漏可忽略；fd 被复用为非管道时陈旧
条目不会被读到（解析仅在 fd 提取为 <p> 时发生），被复用为管道时 pipe()
登记自然覆盖，具备自愈性。
"""

import re
from typing import Dict, Optional

from ..jsonl.fields import (
    UNIX_PATH_IN_BIND_ADDR_RE,
    UNIX_PATH_IN_CONNECT_TUPLE_RE,
    UNIX_PATH_IN_FD_NOTE_RE,
)

# pipe() 退出记录：res=0 fd1=16(<p>) fd2=17(<p>) ino=86998
_PIPE_ENDS_PATTERN = re.compile(r"fd1=(\d+)\(<p>\) fd2=(\d+)\(<p>\).*?ino=(\d+)")
# 任意位置出现的 fd 编号：fd=4(<p>) / fd=58 cmd=1(F_DUPFD)
_FD_NUM_PATTERN = re.compile(r"(?<![a-zA-Z0-9_])fd=(\d+)")
# dup2/dup3 进入记录的源 fd：oldfd=3(<f>/path) newfd=1。参数名恰好叫
# oldfd=，_FD_NUM_PATTERN 的负向环视（前面不能是字母/数字/下划线）把它
# 排除，必须按显式字段名提取
_OLDFD_NUM_PATTERN = re.compile(r"(?:^| )oldfd=(\d+)")
# 退出记录的 res 编号（可带类型括号）：res=1(<p>) / res=0
_RES_PATTERN = re.compile(r"res=(-?\d+)")
# 父侧 clone/fork/vfork 退出记录的子 pid：res=21175(cat)；子侧记录为
# res=0 exe=...（0 后无括号），不会被此模式命中
_CHILD_PID_PATTERN = re.compile(r"res=(\d+)\(")

# 进入侧需要观察的事件（close 失效 / dup、fcntl 暂存 oldfd）
_FD_TABLE_START_EVENTS = frozenset({"close", "dup", "dup2", "dup3", "fcntl"})
# 退出侧需要观察的事件（pipe 登记 / clone 继承 / dup、fcntl 完成复制）
_FD_TABLE_END_EVENTS = frozenset(
    {"pipe", "pipe2", "clone", "fork", "vfork", "dup", "dup2", "dup3", "fcntl"}
)

# --- unix socket 文件系统身份（G1，仅类①） ---------------------------------
# 正则统一在 jsonl/fields.py（三处共用避免漂移）：
#   UNIX_PATH_IN_FD_NOTE_RE          fd 注记里的 '/ <u>/path'（含 in_fd=/out_fd=）
#   UNIX_PATH_IN_CONNECT_TUPLE_RE    connect 退出记录 tuple=<addr>-><addr> /path
#   UNIX_PATH_IN_BIND_ADDR_RE        bind 退出记录 addr=/path
# 映射分开存放在 _unix_map，管道口径不受影响。)


class FdTable:
    """(pid, fd) -> pipe inode 的有状态映射，附审计计数。"""

    def __init__(self) -> None:
        self._map: Dict[str, Dict[str, str]] = {}
        # (pid, fd) -> unix socket 文件系统路径（与 _map 分开，避免影响管道口径）
        self._unix_map: Dict[str, Dict[str, str]] = {}
        # dup/fcntl 进入侧暂存：pid -> oldfd（退出侧 res=newfd 完成复制）
        self._pending_dup_src: Dict[str, str] = {}
        # connect/bind 进入侧暂存：pid -> fd（退出侧 tuple=/addr= 才有路径）。
        # 每个 pid 只占一个槽位，后续同族进入记录直接覆盖；退出记录丢失时
        # 遗留一条也只能被同 pid 覆盖（pid 空间有界），不会无界增长。
        self._pending_path_event_fd: Dict[str, str] = {}
        # --- 审计计数 ---
        self.pipes_registered = 0
        self.fork_inherited = 0
        self.dup_copied = 0
        self.fcntl_dupfd = 0
        self.close_invalidated = 0
        self.fd_overwritten = 0
        self.resolve_hits = 0
        self.resolve_misses = 0
        self.unix_registered = 0
        self.unix_learned_from_path_field = 0
        self.unix_dup_copied = 0
        self.unix_invalidated = 0
        self.unix_resolved = 0
        self.unix_resolve_misses = 0

    # ==================================================================
    # Record hooks（由主循环在配对两侧分别调用）
    # ==================================================================
    def observe_start(self, record: Dict[str, str]) -> None:
        """进入 (>) 记录钩子：close 失效、dup/fcntl 暂存 oldfd、unix 身份学习。"""
        event = record.get("event", "")
        pid = record.get("pid", "")
        args = record.get("args", "")
        # unix 身份学习对所有事件生效：sendmsg/recvmsg/sendto/writev/getsockopt/
        # accept/close 等记录的 fd 注记里都可能带 ` /path`，不受事件白名单限制。
        if "<u>" in args:
            self._learn_unix(pid, args)
        if event in ("connect", "bind"):
            # 路径在**退出**记录的 tuple=/addr=，fd 编号只在进入记录里，
            # 这里暂存以便退出侧对齐（与 dup 暂存 oldfd 同模式）。
            m = _FD_NUM_PATTERN.search(args)
            if m is not None:
                self._pending_path_event_fd[pid] = m.group(1)
        if event not in _FD_TABLE_START_EVENTS:
            return

        if event == "close":
            m = _FD_NUM_PATTERN.search(args)
            if m is not None:
                fd = m.group(1)
                entry = self._map.get(pid)
                if entry is not None and fd in entry:
                    del entry[fd]
                    self.close_invalidated += 1
                uentry = self._unix_map.get(pid)
                if uentry is not None and fd in uentry:
                    del uentry[fd]
                    self.unix_invalidated += 1
            return

        # dup / dup2 / dup3 / fcntl：暂存 oldfd（退出侧 res=newfd 完成复制）。
        # dup 的源 fd 在 fd= 字段；dup2/dup3 在 oldfd= 字段（环视会排除它，
        # 必须按字段名提取）；fcntl 仅 F_DUPFD 家族复制 fd 表，其他 cmd
        # 出现时清除陈旧暂存，防止丢失退出记录的 F_DUPFD 污染后续 fcntl。
        if event == "fcntl":
            if "F_DUPFD" not in args:
                self._pending_dup_src.pop(pid, None)
                return
            m = _FD_NUM_PATTERN.search(args)
        elif event in ("dup2", "dup3"):
            m = _OLDFD_NUM_PATTERN.search(args)
        else:  # dup
            m = _FD_NUM_PATTERN.search(args)
        if m is not None:
            self._pending_dup_src[pid] = m.group(1)

    def observe_end(self, record: Dict[str, str]) -> None:
        """退出 (<) 记录钩子：pipe 登记、clone 继承、dup/fcntl 完成复制、
        unix 身份（fd 注记里带路径 / connect 的 tuple= / bind 的 addr=）。"""
        event = record.get("event", "")
        pid = record.get("pid", "")
        args = record.get("args", "")
        if "<u>" in args:
            self._learn_unix(pid, args)
        if event in ("connect", "bind"):
            fd = self._pending_path_event_fd.pop(pid, None)
            if fd is not None:
                m = UNIX_PATH_IN_CONNECT_TUPLE_RE.search(args) or \
                    UNIX_PATH_IN_BIND_ADDR_RE.search(args)
                if m is not None:
                    self._register_unix(pid, fd, m.group("path"))
                    self.unix_learned_from_path_field += 1
        if event not in _FD_TABLE_END_EVENTS:
            return

        if event in ("pipe", "pipe2"):
            m = _PIPE_ENDS_PATTERN.search(args)
            if m is not None:
                fd1, fd2, ino = m.groups()
                self._register(pid, fd1, ino)
                self._register(pid, fd2, ino)
                self.pipes_registered += 1
            return

        if event in ("clone", "fork", "vfork"):
            m = _CHILD_PID_PATTERN.search(args)
            if m is not None:
                child = m.group(1)
                if child != pid:
                    entry = self._map.get(pid)
                    if entry:
                        self._map.setdefault(child, {}).update(entry)
                        self.fork_inherited += 1
                    uentry = self._unix_map.get(pid)
                    if uentry:
                        self._unix_map.setdefault(child, {}).update(uentry)
            return

        # dup / dup2 / dup3 / fcntl 退出侧：res=newfd 完成复制
        src = self._pending_dup_src.pop(pid, None)
        if src is None:
            return
        m = _RES_PATTERN.search(args)
        if m is None or int(m.group(1)) < 0:
            return
        newfd = m.group(1)
        upath = self._unix_map.get(pid, {}).get(src)
        if upath is not None:
            self._register_unix(pid, newfd, upath)
            self.unix_dup_copied += 1
        ino = self._map.get(pid, {}).get(src)
        if ino is not None:
            self._register(pid, newfd, ino)
            if event == "fcntl":
                self.fcntl_dupfd += 1
            else:
                self.dup_copied += 1

    # ==================================================================
    # Resolution（EntityRegistry 调用）
    # ==================================================================
    def resolve(self, pid: str, fd: str) -> Optional[str]:
        """查 (pid, fd) 的管道 ino；未登记返回 None（调用方回落哨兵）。"""
        if not pid or not fd:
            return None
        ino = self._map.get(pid, {}).get(fd)
        if ino is not None:
            self.resolve_hits += 1
        else:
            self.resolve_misses += 1
        return ino

    def resolve_unix_path(self, pid: str, fd: str) -> Optional[str]:
        """查 (pid, fd) 的 unix socket 文件系统路径；未登记返回 None。

        与 resolve()（管道）共用同一套 fd 生命周期，但映射分开存放，
        管道口径不受影响。"""
        if not pid or not fd:
            return None
        path = self._unix_map.get(pid, {}).get(fd)
        if path is None:
            self.unix_resolve_misses += 1
        else:
            self.unix_resolved += 1
        return path

    # ==================================================================
    # 内部与审计
    # ==================================================================
    def _learn_unix(self, pid: str, args: str) -> None:
        for m in UNIX_PATH_IN_FD_NOTE_RE.finditer(args):
            self._register_unix(pid, m.group(1), m.group("path"))

    def _register_unix(self, pid: str, fd: str, path: str) -> None:
        entry = self._unix_map.setdefault(pid, {})
        entry[fd] = path
        self.unix_registered += 1

    def _register(self, pid: str, fd: str, ino: str) -> None:
        entry = self._map.setdefault(pid, {})
        if entry.get(fd, ino) != ino:
            self.fd_overwritten += 1
        entry[fd] = ino

    def stats(self) -> Dict[str, int]:
        return {
            "pipes_registered": self.pipes_registered,
            "fork_inherited": self.fork_inherited,
            "dup_copied": self.dup_copied,
            "fcntl_dupfd": self.fcntl_dupfd,
            "close_invalidated": self.close_invalidated,
            "fd_overwritten": self.fd_overwritten,
            "resolve_hits": self.resolve_hits,
            "resolve_misses": self.resolve_misses,
            "unix_registered": self.unix_registered,
            "unix_learned_from_path_field": self.unix_learned_from_path_field,
            "unix_dup_copied": self.unix_dup_copied,
            "unix_invalidated": self.unix_invalidated,
            "unix_resolved": self.unix_resolved,
            "unix_resolve_misses": self.unix_resolve_misses,
        }
