"""文件数据流：read / write。"""

from __future__ import annotations

from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket
from ..context import EmitContext
from .file_common import fd_pairs, flow


def read(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd, entry = ctx.fd_entry(call)
    if entry is None:
        return ctx.no_object(out, call, fd)
    bucket = flow(ctx, out, call, call.text("fd"), "read", ctx.result(call), payload=True)
    if bucket is Bucket.COVERED:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, bucket, "unusable_object")


def write(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    pairs = fd_pairs(call)
    if not pairs:
        fd0, entry = ctx.fd_entry(call)
        if entry is None:
            return ctx.no_object(out, call, fd0)
        pairs = [("write", call.text("fd"))]

    covered = False
    last = Bucket.OTHER
    for action, fd_value in pairs:
        last = flow(ctx, out, call, fd_value, action, ctx.result(call), payload=True)
        covered = covered or last is Bucket.COVERED
    if covered:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, last, "unusable_object")
