"""文件生命周期：create / link / rename / unlink / truncate。"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext
from ..state.fds import FdEntry


def create(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    flags = A.flags_of(call.args.get("flags"))
    fd = A.fd_of(call.args.get("fd"))
    if fd is not None and fd.kind == "memfd":
        # memfd 没有文件系统路径。名字是调用者给的（<m>payload），是 fileless
        # 载荷唯一的身份线索；用 memfd:<name> 作合成身份，不拼 cwd。
        path = f"memfd:{fd.name}" if fd.name else "memfd:"
    else:
        raw_path = fd.name if fd and not A.is_unknown_name(fd.name) else ""
        path = ctx.norm_path(raw_path, call, "dirfd") or ctx.path_arg(
            call, "name", "path", "filename", "file", dirfd_key="dirfd")
    ok, result = ctx.gate(call, "success")
    if not ok and result is None and fd is not None:
        ok = True
    if not ok:
        if result is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:create")
        return ctx.attempt(out, call, "create", path or raw_path, result)

    if fd is not None:
        target = ctx.objects.target_from_token(call, fd, kind=fd.kind, name=path or fd.name)
        ctx.st.fds.register(
            call.container_id, call.pid, fd.num,
            FdEntry(target, fd.proto, "O_CLOEXEC" in flags),
        )
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")

    node = ctx.file_node(call.container_id, path, fd.kind if fd else "")
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "create", ctx.key(call), node.key,
                          call, result=result))
    return ctx.covered(out, call)


def link(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    new_path = ctx.path_arg(
        call, "linkpath", "newpath", "path", "name", dirfd_key="dirfd"
    )
    target = call.text("target") or call.text("oldpath")
    to_path = ctx.norm_path(target, call, "olddirfd") if target else ""
    ok, result = ctx.gate(call, "success")
    if not ok:
        if result is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:link")
        return ctx.attempt(out, call, "link", new_path or to_path, result)
    if not new_path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, new_path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "link", ctx.key(call), node.key,
                          call, result=result, to_path=to_path or target))
    return ctx.covered(out, call)


def rename(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    old_path = ctx.path_arg(call, "oldpath", dirfd_key="olddirfd")
    new_path = ctx.path_arg(call, "newpath", dirfd_key="newdirfd")
    ok, result = ctx.gate(call, "success")
    if not ok:
        if result is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:rename")
        if old_path:
            ctx.ops(out, call, f"oldpath:{old_path}")
        return ctx.attempt(out, call, "rename", new_path or old_path, result)
    if not new_path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    # 源路径 -> 进程：rename 的内容来源边。旧路径解析不到就不建，不猜。
    if old_path:
        old_node = ctx.file_node(call.container_id, old_path)
        if old_node is not None:
            ctx.attach(out, old_node)
            ctx.add(out, ctx.edge(EdgeClass.F2P, "rename", old_node.key,
                                  ctx.key(call), call, result=result))
    new_node = ctx.file_node(call.container_id, new_path)
    ctx.attach(out, new_node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "rename", ctx.key(call), new_node.key,
                          call, result=result))
    return ctx.covered(out, call)


def unlink(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "name", "filename", dirfd_key="dirfd")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "unlink", ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    return ctx.covered(out, call)


def truncate(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "filename", "name")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "truncate", ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    return ctx.covered(out, call)
