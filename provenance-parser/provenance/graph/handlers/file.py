"""文件类动词：create / link / rename / unlink / truncate / write / chmod /
mount / chroot / ns / ioctl / read / load_image / mmap / probe。
"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext
from ..state.fds import FdEntry
from .process import exec_


def _fd_pairs(call: Call) -> list[tuple[str, str]]:
    """sendfile/splice/tee/copy_file_range 的双 fd 形态 -> [(动作, fd 值)]。"""
    pairs: list[tuple[str, str]] = []
    for in_key, out_key in (("in_fd", "out_fd"), ("fd_in", "fd_out"), ("fd1", "fd2")):
        if call.args.get(in_key) and call.args.get(out_key):
            pairs.append(("read", call.args[in_key]))
            pairs.append(("write", call.args[out_key]))
            break
    return pairs


def _flow(ctx: EmitContext, out: Outcome, call: Call, fd_value: str, action: str,
          res: int | None, head: bool) -> Bucket:
    obj = ctx.objects.by_fd_value(call, fd_value)
    return ctx.objects.flow(ctx, out, call, obj, action, head, res)


def create(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    flags = A.flags_of(call.args.get("flags"))
    fd = A.fd_of(call.args.get("fd"))
    raw_path = fd.name if fd and not A.is_unknown_name(fd.name) else ""
    path = ctx.norm_path(raw_path, call, "dirfd") or ctx.path_arg(
        call, "name", "path", "filename", "file", dirfd_key="dirfd")
    ok, res = ctx.gate(call, "success")
    if not ok and res is None and fd is not None:
        ok = True
    if not ok:
        if res is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:create")
        return ctx.attempt(out, call, "create", path or raw_path, res)

    if fd is not None:
        ctx.st.fds.register(
            call.container_id, call.pid, fd.num,
            FdEntry(kind=fd.kind, name=path or fd.name, proto=fd.proto,
                    cloexec="O_CLOEXEC" in flags),
        )
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")

    node = ctx.file_node(call.container_id, path, fd.kind if fd else "")
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "create", ctx.key(call), node.key,
                          call, res=res))
    return ctx.covered(out, call)


def link(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    new_path = ctx.path_arg(
        call, "linkpath", "newpath", "path", "name", dirfd_key="dirfd"
    )
    target = call.text("target") or call.text("oldpath")
    target_path = ctx.norm_path(target, call, "olddirfd") if target else ""
    ok, res = ctx.gate(call, "success")
    if not ok:
        if res is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:link")
        return ctx.attempt(out, call, "link", new_path or target_path, res)
    if not new_path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, new_path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "link", ctx.key(call), node.key,
                          call, res=res, target_path=target_path or target))
    return ctx.covered(out, call)


def rename(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    old_path = ctx.path_arg(call, "oldpath", dirfd_key="olddirfd")
    new_path = ctx.path_arg(call, "newpath", dirfd_key="newdirfd")
    ok, res = ctx.gate(call, "success")
    if not ok:
        if res is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:rename")
        if old_path:
            ctx.ops(out, call, f"oldpath:{old_path}")
        return ctx.attempt(out, call, "rename", new_path or old_path, res)
    if not new_path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, new_path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "rename", ctx.key(call), node.key,
                          call, res=res, old_path=old_path))
    return ctx.covered(out, call)


def unlink(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "name", "filename", dirfd_key="dirfd")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "unlink", ctx.key(call), node.key,
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def truncate(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "filename", "name")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path)
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "truncate", ctx.key(call), node.key,
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def read(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd, entry = ctx.fd_entry(call)
    if entry is None:
        return ctx.no_object(out, call, fd)
    bucket = _flow(ctx, out, call, call.text("fd"), "read", ctx.res(call), head=True)
    if bucket is Bucket.COVERED:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, bucket, "unusable_object")


def write(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    pairs = _fd_pairs(call)
    if not pairs:
        fd0, entry = ctx.fd_entry(call)
        if entry is None:
            return ctx.no_object(out, call, fd0)
        pairs = [("write", call.text("fd"))]

    covered = False
    last = Bucket.OTHER
    for action, fd_value in pairs:
        last = _flow(ctx, out, call, fd_value, action, ctx.res(call), head=True)
        covered = covered or last is Bucket.COVERED
    if covered:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, last, "unusable_object")


def mmap(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd = A.fd_of(call.args.get("fd"))
    prot = A.flags_of(call.args.get("prot"))
    if fd is None or fd.num < 0 or (not fd.name and not fd.kind):
        reason = "exec_mem" if "PROT_EXEC" in prot else "anon_mmap"
        ctx.ops(out, call, f"mmap:{reason}")
        return ctx.give_up(out, call, Bucket.NO_OBJECT, reason)
    bucket = _flow(ctx, out, call, call.text("fd"), "mmap", ctx.res(call), head=False)
    if bucket is Bucket.COVERED:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, bucket, "unusable_object")


def chmod(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    mode = (call.text("mode").split("(", 1)[0] or "").strip()
    path = ctx.path_arg(call, "filename", "path", "name", dirfd_key="dirfd")
    subject = ctx.key(call)
    if path:
        node = ctx.file_node(call.container_id, path)
    else:
        fd, entry = ctx.fd_entry(call)
        if entry is None or A.is_unknown_name(entry.name):
            return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
        node = ctx.file_node(call.container_id, entry.name, entry.kind)
        if node is None:
            return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "chmod", subject, node.key,
                          call, res=ctx.res(call), mode=mode))
    return ctx.covered(out, call)


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
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def unmount(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    """umount：只对成功建边。

    卸载失败时挂载点可能根本不存在（ENOENT），建节点等于宣告一个不存在的
    目录；所以失败走 attempts.csv（目标 + errno），保留“尝试”证据。
    """
    out = Outcome()
    path = ctx.path_arg(call, "name", "dir", "target")
    flags = A.int_of(call.args.get("flags"))
    if flags:
        ctx.ops(out, call, f"umount2:{flags}")
    ok, res = ctx.gate(call, "success")
    if not ok:
        if res is None:
            return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:unmount")
        return ctx.attempt(out, call, "unmount", path or "-", res)
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path, "directory")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "unmount", ctx.key(call), node.key,
                          call, res=res))
    return ctx.covered(out, call)


def chroot(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "path", "newroot", "new_root")
    if not path:
        return ctx.give_up(out, call, Bucket.OTHER, "path_unresolved")
    node = ctx.file_node(call.container_id, path, "directory")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "chroot", ctx.key(call), node.key,
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def ns(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    return chroot_like(ctx, call, "ns")


def chroot_like(ctx: EmitContext, call: Call, action: str) -> Outcome:
    out = Outcome()
    fd, entry = ctx.fd_entry(call)
    if entry is None or A.is_unknown_name(entry.name):
        return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
    node = ctx.file_node(call.container_id, entry.name, entry.kind)
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, action, ctx.key(call), node.key,
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def ioctl(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    request = call.text("request")
    if request:
        ctx.ops(out, call, f"ioctl:{A.int_of(request)}")
    fd, entry = ctx.fd_entry(call)
    if entry is None or A.is_unknown_name(entry.name):
        return ctx.give_up(out, call, Bucket.UNKNOWN_FD, "fd")
    node = ctx.file_node(call.container_id, entry.name, entry.kind)
    if node is None:
        return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
    ctx.attach(out, node)
    ctx.add(out, ctx.edge(EdgeClass.P2F, "ioctl", ctx.key(call), node.key,
                          call, res=ctx.res(call)))
    return ctx.covered(out, call)


def probe(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    path = ctx.path_arg(call, "name", "path", "filename", dirfd_key="dirfd")
    if path:
        node = ctx.file_node(call.container_id, path)
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "probe", node.key, ctx.key(call),
                              call, res=ctx.res(call)))
        return ctx.covered(out, call)
    fd, entry = ctx.fd_entry(call)
    if entry is not None and not A.is_unknown_name(entry.name):
        node = ctx.file_node(call.container_id, entry.name, entry.kind)
        if node is None:
            return ctx.give_up(out, call, Bucket.NO_OBJECT, "not_file")
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "probe", node.key, ctx.key(call),
                              call, res=ctx.res(call)))
        return ctx.covered(out, call)
    return ctx.give_up(out, call, Bucket.NO_OBJECT, "no_object_arg")


def load_image(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    return exec_(ctx, call, decision)
