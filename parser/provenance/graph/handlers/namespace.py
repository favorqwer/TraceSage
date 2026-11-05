"""命名空间/挂载：mount / unmount / chroot / ns。"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext


def mount(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    kind = call.text("type")
    if kind:
        ctx.ops(out, call, f"mount:{kind}")
    path = ctx.path_arg(call, "dir")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "mount", ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    return ctx.covered(out, call)


def umount(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    """umount：只对成功建边。

    卸载失败时挂载点可能根本不存在（ENOENT），建节点等于宣告一个不存在的
    目录；所以失败走 attempts.csv（目标 + errno），保留“尝试”证据。
    """
    out = Outcome()
    path = ctx.path_arg(call, "name", "dir", "target")
    flags = A.int_of(call.args.get("flags"))
    if flags:
        ctx.ops(out, call, f"umount2:{flags}")
    ok, result = ctx.gate(call, "success")
    if not ok:
        if result is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:umount")
        return ctx.attempt(out, call, "umount", path or "-", result)
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path, "directory")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "umount", ctx.key(call), node.key,
                          call, result=result))
    return ctx.covered(out, call)


def chroot(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "newroot", "new_root")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path, "directory")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "chroot", ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    result = ctx.result(call)
    if result is not None and result >= 0:
        # 同一路径只解析一次：状态更新消费这里的结果（见 ObjectResolver.observe_fs）
        ctx.st.proc.note_root_target(call.head_row.num, path)
    return ctx.covered(out, call)


def setns(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    return chroot_like(ctx, call, "setns")


def chroot_like(ctx: EmitContext, call: Call, action: str) -> Outcome:
    out = Outcome()
    fd, entry = ctx.fd_entry(call)
    if fd is None or entry is None:
        return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
    obj = ctx.objects.from_entry(call, fd, entry)
    if obj.kind != "file" or obj.key is None:
        return ctx.give_up(out, call, obj.bucket if obj.kind == "none" else Bucket.NO_OBJECT,
                           obj.reason or "not_file")
    node = ctx.file_node(call.container_id, obj.key.path, obj.node_kind)
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, action, ctx.key(call), node.key,
                          call, result=ctx.result(call)))
    return ctx.covered(out, call)
