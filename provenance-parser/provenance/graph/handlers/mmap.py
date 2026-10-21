"""mmap：建边时读 prot/flags，只决定 action；flags 不落图。

action 三态对称：mmap_read（只读/私有写/未观测）/ mmap_write（MAP_SHARED|PROT_WRITE）/ mmap_exec（PROT_EXEC）。
"""

from __future__ import annotations

from ...core import args as A
from ...core.classify import Decision
from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket
from ..context import EmitContext


def _has_flag(raw: str, flags: set[str], name: str) -> bool:
    return name in flags or name in (raw or "")


def mmap_actions(call: Call) -> list[str]:
    prot_raw = call.text("prot")
    flags_raw = call.text("flags")
    prot = A.flags_of(prot_raw)
    flags = A.flags_of(flags_raw)
    write = _has_flag(prot_raw, prot, "PROT_WRITE")
    read = _has_flag(prot_raw, prot, "PROT_READ")
    execute = _has_flag(prot_raw, prot, "PROT_EXEC")
    shared = (_has_flag(flags_raw, flags, "MAP_SHARED")
              or _has_flag(flags_raw, flags, "MAP_SHARED_VALIDATE"))
    shared_write = shared and write

    actions: list[str] = []
    if shared_write:
        actions.append("mmap_write")
    if execute:
        actions.append("mmap_exec")
    elif read or not shared_write:
        # 只读、私有写、或 flags 未观测：保守地只建读边。
        actions.append("mmap_read")
    return actions or ["mmap_read"]


def mmap(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    fd = A.fd_of(call.args.get("fd"))
    prot = A.flags_of(call.args.get("prot"))
    if fd is None or fd.num < 0 or (not fd.name and not fd.kind):
        reason = "exec_mem" if "PROT_EXEC" in prot else "anon_mmap"
        ctx.ops(out, call, f"mmap:{reason}")
        return ctx.give_up(out, call, Bucket.NO_OBJECT, reason)

    obj = ctx.objects.by_fd_value(call, call.text("fd"))
    if obj.kind != "file":
        return ctx.give_up(out, call, obj.bucket or Bucket.OTHER,
                           obj.reason or "unusable_object")

    result = ctx.result(call)
    # 失败只保留一条 mmap 边作为"尝试"，不要因为共享写拆出两条失败边。
    actions = mmap_actions(call) if (result is None or result >= 0) else ["mmap_read"]
    covered = False
    last = Bucket.OTHER
    for action in actions:
        last = ctx.flow(out, call, obj, action, False, result)
        covered = covered or last is Bucket.COVERED
    if covered:
        return ctx.covered(out, call)
    return ctx.give_up(out, call, last, "unusable_object")
