"""跨动词的判定策略：成功门、匿名 fd、/proc 派生边、失败证据。"""

from __future__ import annotations

import re

from ..core import args as A
from ..core.events import Call
from ..core.graph import Outcome
from ..core.kinds import Bucket, EdgeClass, FileKey, ProcKey

_PROC_PATH = re.compile(r"^/proc/(\d+)/(mem|maps|environ|cmdline|fd)(?:/|$)")
_READ_ACTIONS = {"read", "mmap", "probe", "load_image"}


class Policies:
    ANON_KINDS = frozenset(
        {"event", "timerfd", "signalfd", "inotify", "eventpoll", "pipe",
         "unix", "memfd", "bpf", "netlink"}
    )

    def __init__(self, state, graph) -> None:
        self.st = state
        self.graph = graph
        self.counts = {"gate_missing_res": 0, "proc_derived_edges": 0}

    # -- 成功门 --------------------------------------------------------
    def gate(self, ctx, call: Call, gate: str) -> tuple[bool, int | None]:
        res = ctx.res(call)
        if gate == "always":
            return True, res
        if res is None:
            self.counts["gate_missing_res"] += 1
            return False, None
        return res >= 0, res

    # -- 无客体 --------------------------------------------------------
    def no_object_bucket(self, fd: A.Fd | None) -> Bucket:
        if fd is not None and fd.kind in self.ANON_KINDS:
            return Bucket.NO_OBJECT
        return Bucket.UNKNOWN_FD

    def no_object(self, ctx, out: Outcome, call: Call, fd: A.Fd | None) -> Outcome:
        """fd 存在但客体天生不可标识（匿名 IPC / 无路径 unix）-> 无客体桶；
        真正是映射丢了（找不到 fd）才计未知句柄。"""
        if fd is not None and fd.kind in self.ANON_KINDS:
            name = f"anon:{fd.code or fd.kind}"
            ctx.ops(out, call, name)
            return out.settle(call, Bucket.NO_OBJECT, name)
        code = fd.code if fd else "-"
        return out.settle(call, Bucket.UNKNOWN_FD, f"{call.call}:{code}")

    # -- /proc/<pid> 派生边（§5.6）-------------------------------------
    def derive_proc(
        self,
        ctx,
        out: Outcome,
        call: Call,
        file_key: FileKey,
        action: str,
        subject: ProcKey,
    ) -> None:
        m = _PROC_PATH.match(file_key.path)
        if not m:
            return
        target_pid = int(m.group(1))
        if target_pid == subject.pid:
            return
        target = self.st.proc.resolve_or_none(
            file_key.container_id, target_pid, call.ts_ns
        )
        if target is None:
            return
        derived = action if action in ("mem_read", "mem_write") else (
            "mem_write" if action in ("write", "create", "chmod") else "mem_read"
        )
        edge = self.graph.edge(EdgeClass.P2P, derived, subject, target, call)
        if self.graph.add(out, edge):
            self.counts["proc_derived_edges"] += 1

    # -- 失败证据 ------------------------------------------------------
    def note_attempt(
        self,
        ctx,
        out: Outcome,
        call: Call,
        verb: str,
        target: str,
        res: int | None,
    ) -> None:
        """只记录“目标 + 错误码”，不改变这一行的桶归属。

        ``res`` 必须是被观测到的值：未知结果不能写成 0，因为 0 在整套口径里
        是“成功 / 零字节”，会把“没有证据”读成“没有报错”。调用方遇到 res=None
        时应自己落 OTHER 桶（reason ``result_unobserved:<verb>``）。
        """
        if res is None:
            return
        key = ctx.key(call)
        errno = -res if res < 0 else 0
        out.attempts.append((key, verb, target or "-", errno, call.ts_ns))
