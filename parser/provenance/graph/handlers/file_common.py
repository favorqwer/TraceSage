"""文件处理共享小工具：双 fd 解析、fd -> 流向路由。"""

from __future__ import annotations

from ...core.events import Call
from ...core.graph import Outcome
from ...core.kinds import Bucket
from ..context import EmitContext


def fd_pairs(call: Call) -> list[tuple[str, str]]:
    """sendfile/splice/tee/copy_file_range 的双 fd 形态 -> [(动作, fd 值)]。"""
    pairs: list[tuple[str, str]] = []
    for in_key, out_key in (("in_fd", "out_fd"), ("fd_in", "fd_out"), ("fd1", "fd2")):
        if call.args.get(in_key) and call.args.get(out_key):
            pairs.append(("read", call.args[in_key]))
            pairs.append(("write", call.args[out_key]))
            break
    return pairs


def flow(ctx: EmitContext, out: Outcome, call: Call, fd_value: str, action: str,
         result: int | None, payload: bool) -> Bucket:
    obj = ctx.objects.by_fd_value(call, fd_value)
    return ctx.flow(out, call, obj, action, payload, result)
