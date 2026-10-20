"""纯句柄表维护：close / dup / pipe。"""

from __future__ import annotations

from ...core import args as A
from ...core.graph import Outcome
from ...core.kinds import Bucket
from ..state.fds import FdEntry


def apply_handle(ctx, call) -> Outcome:
    out = Outcome()
    name = call.call
    cid, pid = call.container_id, call.pid
    fds = ctx.st.fds

    if name in ("close",):
        fd = A.fd_of(call.args.get("fd"))
        if fd is not None:
            fds.close(cid, pid, fd.num)
    elif name in ("dup", "dup2", "dup3"):
        old = A.fd_of(call.args.get("fd"))
        new = A.int_of(call.args.get("newfd") or call.args.get("fd2") or call.args.get("ret"))
        if old is not None and new is not None:
            fds.dup(cid, pid, old.num, new)
    elif name in ("pipe", "pipe2"):
        ino = call.text("ino")
        if ino:
            for key in ("fd1", "fd2"):
                fd = A.fd_of(call.args.get(key))
                if fd is not None:
                    fds.register(cid, pid, fd.num,
                                 FdEntry(kind="pipe", name=f"pipe:[{ino}]"))
                    fds.counts["pipe_registered"] += 1

    key = ctx.st.proc.observe(call.head_row).key
    out.ops.append((key, name, call.ts_ns))
    return out.settle(call, Bucket.HANDLE, name)
