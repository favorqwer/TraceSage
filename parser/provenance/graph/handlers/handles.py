"""纯句柄表维护：open 家族 / close / dup / fcntl / pipe / close_range。

这里只改状态，不建边。所有函数都返回 Outcome（桶是 HANDLE），
由 dispatch 统一结算。
"""

from __future__ import annotations

from ...core import args as A
from ...core.syscalls import OPEN_FAMILY
from ...core.graph import Outcome
from ...core.kinds import Bucket
from ..state.fds import FdEntry


def _flag(raw: str, flags: set[str], name: str) -> bool:
    """同时看注解解码后的集合和原始串：sysdig 有些字段只给数字。"""
    return name in flags or name in (raw or "")


def _open_handle(ctx, out: Outcome, call, fds, reason: str) -> Outcome | None:
    """open/openat 只读、只写、O_PATH、O_TMPFILE：只登记 fd，不建边。

    成功返回 None（由调用方统一收尾）；失败/不可登记返回已结算的 Outcome。
    """
    raw_flags = call.args.get("flags", "")
    flags = A.flags_of(raw_flags)
    cloexec = _flag(raw_flags, flags, "O_CLOEXEC")
    # 优先进入/退出行的 fd=...；没有时回退退出行 evt.args 的 res=N(<f>/path)。
    fd = A.fd_of(call.args.get("fd")) or A.fd_of(call.args.get("res"))
    result = call.result

    # 失败：不登记；目标串 + errno 进 attempts（没有对象，绝不能建节点）。
    if result is not None and result < 0:
        target = ctx.path_arg(
            call, "name", "path", "filename", dirfd_key="dirfd"
        ) or call.text("name")
        return ctx.attempt(out, call, "open", target, result)

    if fd is None or fd.num < 0:
        fds.counts["open_fd_missing"] += 1
        if result is None:
            return out.settle(call, Bucket.OTHER, "result_unobserved:open")
        return out.settle(call, Bucket.OTHER, "open_fd_missing")

    kind = fd.kind or "file"
    if _flag(raw_flags, flags, "O_DIRECTORY") and kind in ("", "file", "unknown"):
        kind = "directory"
    if _flag(raw_flags, flags, "O_TMPFILE"):
        # O_TMPFILE 没有名字；linkat 之前不能当 File 节点身份。
        # 但 fd 状态（CLOEXEC/别名/close）必须维护。
        kind = "directory" if kind == "directory" else "file"
        target = None
    else:
        name = "" if A.is_unknown_name(fd.name) else fd.name
        target = ctx.objects.target_from_token(call, fd, kind=kind, name=name) if name else None

    fds.register(
        call.container_id, call.pid, fd.num,
        FdEntry(target, fd.proto, cloexec),
    )
    fds.counts["open_registered"] += 1
    return None  # 调用方统一收尾


def _dup_handle(ctx, out: Outcome, call, fds, name: str) -> Outcome:
    old = A.fd_of(call.args.get("fd") or call.args.get("oldfd"))
    new = call.result
    raw_flags = call.args.get("flags", "")
    flags = A.flags_of(raw_flags)
    cloexec = name == "dup3" and _flag(raw_flags, flags, "O_CLOEXEC")

    if old is not None and new is not None and new >= 0:
        if not fds.dup(call.container_id, call.pid, old.num, new,
                       cloexec=cloexec):
            # 旧 fd 不在表里：退出行 evt.args 的 res=N(<f>/path) 仍带着新 fd 的客体，
            # 用它补登记（不假装知道旧 fd 的别名历史）。
            new_fd = A.fd_of(call.args.get("res"))
            target = (ctx.objects.target_from_token(call, new_fd)
                      if new_fd is not None and new_fd.num == new else None)
            if target is not None:
                fds.register(call.container_id, call.pid, new,
                             FdEntry(target, new_fd.proto, cloexec))
                fds.counts["dup_alias_fallback"] += 1
            else:
                fds.counts["dup_alias_miss"] += 1
        return out

    fds.counts["dup_alias_miss"] += 1
    return out


def _fcntl_handle(ctx, out: Outcome, call, fds) -> Outcome:
    cmd = A.int_of(call.args.get("cmd"))
    old = A.fd_of(call.args.get("fd"))
    result = call.result

    if cmd in (0, 1030):  # F_DUPFD / F_DUPFD_CLOEXEC
        if old is not None and result is not None and result >= 0:
            if not fds.dup(call.container_id, call.pid, old.num, result,
                           cloexec=(cmd == 1030)):
                new_fd = A.fd_of(call.args.get("res"))
                target = (ctx.objects.target_from_token(call, new_fd)
                          if new_fd is not None and new_fd.num == result else None)
                if target is not None:
                    fds.register(call.container_id, call.pid, result,
                                 FdEntry(target, new_fd.proto, cloexec=(cmd == 1030)))
                    fds.counts["dup_alias_fallback"] += 1
                else:
                    fds.counts["blind_dup"] += 1
        else:
            fds.counts["blind_dup"] += 1
    elif cmd == 2:  # F_SETFD
        arg = A.int_of(call.args.get("arg"))
        if (old is not None and arg is not None
                and (result is None or result >= 0)):
            if fds.set_cloexec(call.container_id, call.pid, old.num,
                               bool(arg & 1)):
                fds.counts["cloexec_set"] += 1
            else:
                fds.counts["cloexec_set_miss"] += 1
        else:
            fds.counts["cloexec_set_miss"] += 1
    return out


def apply_handle(ctx, call, decision=None) -> Outcome:
    out = Outcome()
    name = call.call
    cid, pid = call.container_id, call.pid
    fds = ctx.st.fds
    reason = decision.reason if decision is not None else ""

    if name in OPEN_FAMILY:
        early = _open_handle(ctx, out, call, fds, reason)
        if early is not None:
            return early
        op_name = f"{name}:{reason or 'open'}"
    elif name == "close":
        fd = A.fd_of(call.args.get("fd"))
        if fd is not None:
            fds.close(cid, pid, fd.num)
        op_name = name
    elif name in ("dup", "dup2", "dup3"):
        _dup_handle(ctx, out, call, fds, name)
        op_name = name
    elif name in ("pipe", "pipe2"):
        ino = call.text("ino")
        raw_flags = call.args.get("flags", "")
        flags = A.flags_of(raw_flags)
        cloexec = name == "pipe2" and _flag(raw_flags, flags, "O_CLOEXEC")
        if ino:
            for key in ("fd1", "fd2"):
                fd = A.fd_of(call.args.get(key))
                if fd is not None:
                    fds.register(cid, pid, fd.num,
                                 FdEntry.synthetic(f"pipe:[{ino}]", "pipe",
                                                   cloexec=cloexec))
                    fds.counts["pipe_registered"] += 1
        op_name = name
    elif name in ("fcntl", "fcntl64"):
        _fcntl_handle(ctx, out, call, fds)
        op_name = name
    elif name == "close_range":
        first = A.int_of(call.args.get("first") or call.args.get("fd"))
        last = A.int_of(call.args.get("last"))
        result = call.result
        if first is not None and last is not None and (result is None or result >= 0):
            fds.close_range(cid, pid, first, last)
        else:
            fds.counts["close_range_blind"] += 1
        op_name = name
    else:
        op_name = name

    key = ctx.st.proc.observe(call.head_row).key
    out.ops.append((key, op_name, call.start_ns))
    return out.settle(call, Bucket.HANDLE, op_name)
