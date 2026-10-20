"""产出层门面：一个 verb 一个函数，外加四种非建边结论。"""

from __future__ import annotations

from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, Verdict
from ..context import EmitContext
from . import file, network, process
from .handles import apply_handle

HANDLERS = {
    # p2p
    "clone": process.clone,
    "exec": process.exec_,
    "exit": process.exit_,
    "signal": process.signal,
    "wait": process.wait,
    "ptrace": process.ptrace,
    "mem_read": process.mem_read,
    "mem_write": process.mem_write,
    "pidfd_getfd": process.pidfd_getfd,
    # p2f / f2p
    "create": file.create,
    "link": file.link,
    "rename": file.rename,
    "unlink": file.unlink,
    "truncate": file.truncate,
    "write": file.write,
    "chmod": file.chmod,
    "mount": file.mount,
    "unmount": file.unmount,
    "chroot": file.chroot,
    "ns": file.ns,
    "ioctl": file.ioctl,
    "read": file.read,
    "load_image": file.load_image,
    "mmap": file.mmap,
    "probe": file.probe,
    # p2n / n2p
    "connect": network.connect,
    "bind": network.bind,
    "listen": network.listen,
    "send": network.send,
    "accept": network.accept,
    "recv": network.recv,
}


def _attr(call: Call, ctx: EmitContext) -> Outcome:
    out = Outcome()
    meta = {
        "id": call.args.get("id") or call.container_id,
        "name": call.args.get("name", ""),
        "image": call.args.get("image", ""),
        "privileged": call.args.get("privileged", ""),
        "mounts": call.args.get("mounts", ""),
    }
    if meta["id"] and meta["id"] != "host":
        ctx.st.containers.observe(meta)
    return out.settle(call, Bucket.ATTR, "container_meta")


def _ops(call: Call, ctx: EmitContext, reason: str) -> Outcome:
    out = Outcome()
    ctx.ops(out, call, call.call)
    return out.settle(call, Bucket.NO_OBJECT, reason or call.call)


def _drop(call: Call, ctx: EmitContext, reason: str) -> Outcome:
    out = Outcome()
    ctx.ops(out, call, call.call)
    return out.settle(call, Bucket.DROP, reason or call.call)


def _unmapped(call: Call, ctx: EmitContext) -> Outcome:
    return Outcome().settle(call, Bucket.UNMAPPED, call.call)


def dispatch(call: Call, decision: Decision, ctx: EmitContext) -> Outcome:
    ctx.graph.reset_seq()
    verdict = decision.verdict
    if verdict is Verdict.HANDLE:
        return apply_handle(ctx, call)
    if verdict is Verdict.ATTR:
        return _attr(call, ctx)
    if verdict is Verdict.DROP:
        return _drop(call, ctx, decision.reason)
    if verdict is Verdict.OPS:
        return _ops(call, ctx, decision.reason)
    if verdict is Verdict.UNMAPPED:
        return _unmapped(call, ctx)

    handler = HANDLERS.get(decision.verb)
    if handler is None:
        return _unmapped(call, ctx)
    return handler(ctx, call, decision)
