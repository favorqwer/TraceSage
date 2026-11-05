"""产出层门面：一个 verb 一个函数，外加四种非建边结论。"""

from __future__ import annotations

from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket, Verdict
from ..context import EmitContext
from . import file_io, file_lifecycle, file_meta, namespace, network, process
from . import mmap as mmap_handler
from .handles import apply_handle

HANDLERS = {
    # ProcessToProcess
    "clone": process.clone,
    "exec": process.exec_,
    "exit": process.exit_,
    "signal": process.signal,
    "wait": process.wait,
    "ptrace": process.ptrace,
    "mem_read": process.mem_read,
    "mem_write": process.mem_write,
    "pidfd_getfd": process.pidfd_getfd,
    # ProcessToFile / FileToProcess
    "create": file_lifecycle.create,
    "link": file_lifecycle.link,
    "rename": file_lifecycle.rename,
    "unlink": file_lifecycle.unlink,
    "truncate": file_lifecycle.truncate,
    "write": file_io.write,
    "chmod": file_meta.chmod,
    "mount": namespace.mount,
    "umount": namespace.umount,
    "chroot": namespace.chroot,
    "setns": namespace.setns,
    "ioctl": file_meta.ioctl,
    "read": file_io.read,
    "mmap": mmap_handler.mmap,
    "stat": file_meta.stat_,
    # ProcessToNetwork / NetworkToProcess
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
    verdict = decision.verdict
    if verdict is Verdict.HANDLE:
        return apply_handle(ctx, call, decision)
    if verdict is Verdict.ATTR:
        return _attr(call, ctx)
    if verdict is Verdict.DROP:
        return _drop(call, ctx, decision.reason)
    if verdict is Verdict.OPS:
        return _ops(call, ctx, decision.reason)
    if verdict is Verdict.UNMAPPED:
        return _unmapped(call, ctx)
    if verdict is Verdict.BLIND:
        return Outcome().settle(
            call, Bucket.COLLECTOR_BLIND, decision.reason or "collector_unknown"
        )

    handler = HANDLERS.get(decision.verb)
    if handler is None:
        return _unmapped(call, ctx)
    return handler(ctx, call, decision)
