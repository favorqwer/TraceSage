"""网络动词：connect / bind / listen / send / accept / recv。"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext
from ..state.fds import FdEntry


def _register(ctx: EmitContext, call: Call, fd: A.Fd | None, name: str, proto: str) -> None:
    if fd is None or fd.num < 0:
        return
    ctx.st.fds.register(call.container_id, call.pid, fd.num,
                        FdEntry(kind=fd.kind or "ipv4", name=name, proto=proto))


def connect(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd = A.fd_of(call.args.get("fd"))
    raw = call.text("tuple") or (fd.name if fd else "")
    res = ctx.res(call)
    proto = fd.proto if fd else ""

    if fd is not None and fd.kind == "unix":
        path = A.unix_path(raw) or A.unix_path(fd.name)
        if not path:
            ctx.ops(out, call, f"connect:{raw or '-'}")
            return ctx.give_up(out, call, Bucket.OTHER, "unix_unusable")
        ctx.st.fds.register(call.container_id, call.pid, fd.num,
                            FdEntry(kind="unix", name=path))
        node = ctx.file_node(call.container_id, path, "unix")
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.P2F, "connect", ctx.key(call), node.key,
                              call, res=res))
        return ctx.covered(out, call)

    if not raw or not A.tuple_usable(raw, session=True):
        ctx.ops(out, call, f"connect:{raw or '-'}")
        return ctx.give_up(out, call, Bucket.OTHER, "tuple_unusable")

    _register(ctx, call, fd, raw, proto)
    node = ctx.net_node(raw, proto)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2N, "connect", ctx.key(call), node.key,
                          call, res=res))
    return ctx.covered(out, call)


def _endpoint(ctx: EmitContext, call: Call) -> tuple[str, str, A.Fd | None]:
    fd = A.fd_of(call.args.get("fd"))
    raw = call.text("addr")
    if not raw or raw == "NULL":
        raw = fd.name if fd else ""
    proto = fd.proto if fd else ""
    return raw, proto, fd


def bind(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    raw, proto, fd = _endpoint(ctx, call)
    ok, res = ctx.gate(call, "success")
    if not ok:
        return ctx.attempt(out, call, "bind", raw, res)
    if not raw or not A.endpoint_usable(raw):
        ctx.ops(out, call, f"bind:{raw or '-'}")
        return ctx.give_up(out, call, Bucket.OTHER, "tuple_unusable")
    _register(ctx, call, fd, raw, proto)
    node = ctx.net_node(raw, proto)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2N, "bind", ctx.key(call), node.key,
                          call, res=res))
    return ctx.covered(out, call)


def listen(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    raw, proto, fd = _endpoint(ctx, call)
    ok, res = ctx.gate(call, "success")
    if not ok:
        return ctx.attempt(out, call, "listen", raw, res)
    if not raw or not A.endpoint_usable(raw):
        ctx.ops(out, call, f"listen:{raw or '-'}")
        return ctx.give_up(out, call, Bucket.OTHER, "tuple_unusable")
    _register(ctx, call, fd, raw, proto)
    node = ctx.net_node(raw, proto)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2N, "listen", ctx.key(call), node.key,
                          call, res=res))
    return ctx.covered(out, call)


def accept(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd = A.fd_of(call.args.get("fd"))
    raw = call.text("tuple") or (fd.name if fd else "")
    ok, res = ctx.gate(call, "success")
    if not ok and res is None and fd is not None:
        ok = True
    if not ok:
        return ctx.attempt(out, call, "accept", raw, res)
    if fd is not None and fd.kind == "unix":
        path = A.unix_path(fd.name) or A.unix_path(raw)
        if not path:
            ctx.ops(out, call, f"accept:{raw or '-'}")
            return ctx.give_up(out, call, Bucket.OTHER, "unix_unusable")
        ctx.st.fds.register(call.container_id, call.pid, fd.num,
                            FdEntry(kind="unix", name=path))
        node = ctx.file_node(call.container_id, path, "unix")
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "accept", node.key, ctx.key(call),
                              call, res=res))
        return ctx.covered(out, call)

    if not raw or not A.tuple_usable(raw, session=True):
        ctx.ops(out, call, f"accept:{raw or '-'}")
        return ctx.give_up(out, call, Bucket.OTHER, "tuple_unusable")

    proto = fd.proto if fd else ""
    _register(ctx, call, fd, raw, proto)
    node = ctx.net_node(raw, proto)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.N2P, "accept", node.key, ctx.key(call),
                          call, res=res))
    return ctx.covered(out, call)


def _data(ctx: EmitContext, call: Call, action: str) -> Outcome:
    """send/recv：客体类型决定边类（§3.1）。"""
    out = Outcome()
    fd, entry = ctx.fd_entry(call)
    subject = ctx.key(call)

    if entry is None:
        raw = call.text("tuple")
        if not raw or raw == "NULL" or not A.tuple_usable(raw, session=True):
            return ctx.no_object(out, call, fd)
        node = ctx.net_node(raw, fd.proto if fd else "")
        ctx.attach(out, node)
        if action == "recv":
            ctx.add(out, ctx.edge(EdgeClass.N2P, "recv", node.key, subject,
                                  call, res=ctx.res(call), head=True))
        else:
            ctx.add(out, ctx.edge(EdgeClass.P2N, "send", subject, node.key,
                                  call, res=ctx.res(call), head=True))
        return ctx.covered(out, call)

    obj = ctx.objects.from_entry(call, fd, entry, unix_bucket=Bucket.NO_OBJECT)
    if obj.kind == "none":
        if obj.reason == "unix_unusable":
            return out.settle(call, Bucket.NO_OBJECT, "unix_unusable")
        reason = "tuple_unusable" if obj.reason == "tuple_unusable" else "unusable_object"
        return ctx.give_up(out, call, obj.bucket, reason)

    bucket = ctx.objects.flow(
        ctx, out, call, obj, action, head=True, res=ctx.res(call)
    )
    if bucket is Bucket.COVERED:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, bucket, "unusable_object")


def send(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    return _data(ctx, call, "send")


def recv(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    return _data(ctx, call, "recv")
