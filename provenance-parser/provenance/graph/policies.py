"""跨动词的判定策略：成功门、匿名 fd、/proc 派生边、失败证据。"""

from __future__ import annotations

import re

from ..core import args as A
from ..core.events import Call
from ..core.graph import Outcome
from ..core.kinds import Bucket, EdgeClass, FileKey, ProcKey

_PROC_MEM_PATH = re.compile(r"^/proc/(\d+)/mem(?:/|$)")


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
        result = ctx.result(call)
        if gate == "always":
            return True, result
        if result is None:
            self.counts["gate_missing_res"] += 1
            return False, None
        return result >= 0, result

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

    # -- /proc/<pid>/mem 派生边（只认真正的内存文件）-------------------
    def derive_proc(
        self,
        ctx,
        out: Outcome,
        call: Call,
        file_key: FileKey,
        action: str,
        subject: ProcKey,
    ) -> None:
        m = _PROC_MEM_PATH.match(file_key.path)
        if not m:
            # maps/cmdline/environ/status/fd/* 是进程元数据，不是内存；
            # 不再派生 mem_read 的 ProcessToProcess 边（File 边仍由 flow 保留）。
            return
        target_pid = int(m.group(1))
        if target_pid == subject.pid:
            return
        target = self.st.proc.resolve_or_none(
            file_key.container_id, target_pid, call.start_ns
        )
        if target is None:
            return

        # 读：目标内存/元数据 -> 读取者；写：写入者 -> 目标。
        if action in ("read", "mmap_read", "mmap_exec"):
            derived, src, dst = "mem_read", target, subject
        elif action in ("write", "mmap_write"):
            derived, src, dst = "mem_write", subject, target
        else:
            # stat/create/chmod 等不是实际内存读写，不派生。
            return
        edge = self.graph.edge(EdgeClass.P2P, derived, src, dst, call)
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
        result: int | None,
    ) -> None:
        """只记录“目标 + 错误码”，不改变这一行的桶归属。

        ``result`` 必须是被观测到的值：未知结果不能写成 0，因为 0 在整套口径里
        是“成功 / 零字节”，会把“没有证据”读成“没有报错”。调用方遇到 result=None
        时应自己落 OTHER 桶（reason ``result_unobserved:<verb>``）。
        """
        if result is None:
            return
        key = ctx.key(call)
        errno = -result if result < 0 else 0
        out.attempts.append((key, verb, target or "-", errno, call.start_ns))
