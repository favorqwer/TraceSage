"""文件元数据/控制：chmod / ioctl / stat。"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext


def chmod(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    mode = (call.text("mode").split("(", 1)[0] or "").strip()
    path = ctx.path_arg(call, "filename", "path", "name", dirfd_key="dirfd")
    subject = ctx.key(call)
    if path:
        node = ctx.file_node(call.container_id, path)
    else:
        fd, entry = ctx.fd_entry(call)
        if fd is None or entry is None:
            return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
        obj = ctx.objects.from_entry(call, fd, entry)
        if obj.kind != "file" or obj.key is None:
            return ctx.give_up(out, call,
                               obj.bucket if obj.kind == "none" else Bucket.NO_OBJECT,
                               obj.reason or "not_file")
        node = ctx.file_node(call.container_id, obj.key.path, obj.node_kind)
        if node is None:
            return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "chmod", subject, node.key,
                          call, result=ctx.result(call), mode=mode))
    return ctx.covered(out, call)


def ioctl(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    request = call.text("request")
    if request:
        ctx.ops(out, call, f"ioctl:{A.int_of(request)}")
    fd, entry = ctx.fd_entry(call)
    if fd is None or entry is None:
        return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
    obj = ctx.objects.from_entry(call, fd, entry)
    if obj.kind != "file" or obj.key is None:
        return ctx.give_up(out, call,
                           obj.bucket if obj.kind == "none" else Bucket.NO_OBJECT,
                           obj.reason or "not_file")
    node = ctx.file_node(call.container_id, obj.key.path, obj.node_kind)
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "ioctl", ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    return ctx.covered(out, call)


def stat_(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "name", "path", "filename", dirfd_key="dirfd")
    if path:
        node = ctx.file_node(call.container_id, path)
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "stat", node.key, ctx.key(call),
                              call, result=ctx.result(call)))
        return ctx.covered(out, call)
    fd, entry = ctx.fd_entry(call)
    if fd is not None and entry is not None:
        obj = ctx.objects.from_entry(call, fd, entry)
        if obj.kind != "file" or obj.key is None:
            return ctx.give_up(out, call,
                               obj.bucket if obj.kind == "none" else Bucket.NO_OBJECT,
                               obj.reason or "not_file")
        node = ctx.file_node(call.container_id, obj.key.path, obj.node_kind)
        if node is None:
            return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "stat", node.key, ctx.key(call),
                              call, result=ctx.result(call)))
        return ctx.covered(out, call)
    return ctx.give_up(out, call, Bucket.NO_OBJECT, "no_object_arg")
