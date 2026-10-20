"""p2p 动词：clone / exec / exit / signal / wait / ptrace / mem_* / pidfd_getfd。"""

from __future__ import annotations

from ...core import args as A
from ...core.events import Call
from ...core.graph import Outcome
from ...core.classify import Decision
from ...core.kinds import Bucket, EdgeClass
from ..context import EmitContext


def clone(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    flags = A.flags_of(call.args.get("flags"))
    if "CLONE_THREAD" in flags:
        return ctx.give_up(out, call, Bucket.DROP, "thread_clone")

    res = ctx.res(call)
    parent = ctx.seg(call)
    if res == 0:
        return ctx.give_up(out, call, Bucket.DROP, "clone_child_view")
    if res is None or res < 0:
        return ctx.attempt(out, call, "clone", "-", res)

    child_pid = res
    child = ctx.st.proc.on_clone(
        parent, child_pid, call.ts_ns,
        call.exit.exe if call.exit else parent.exe,
        call.exit.cmdline if call.exit else parent.cmdline,
    )
    if call.exit is not None:
        child.ruid = call.exit.ruid or parent.ruid
        child.ppid = child.ppid or (call.exit.ppid or parent.key.pid)
    ctx.st.fds.fork(call.container_id, parent.key.pid, child_pid)
    ctx.attach(out, ctx.proc_node(parent))
    ctx.attach(out, ctx.proc_node(child))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "clone", parent.key, child.key, call, res=child_pid))
    return ctx.covered(out, call)


def exec_(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    res = ctx.res(call)
    old = ctx.seg(call)
    target = ctx.norm_path(call.text("filename"), call)

    if res is None or res < 0:
        return ctx.attempt(out, call, "exec", target or call.text("filename"), res)

    exe = (call.exit.exe if call.exit else "") or old.exe
    cmdline = (call.exit.cmdline if call.exit else "") or ""
    new = ctx.st.proc.on_exec(old, call.ts_ns, exe, cmdline)
    ctx.st.fds.prune_cloexec(call.container_id, call.pid)

    ctx.attach(out, ctx.proc_node(old))
    ctx.attach(out, ctx.proc_node(new))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "exec", old.key, new.key, call, res=res))

    image = target or ctx.norm_path(exe, call)
    if image:
        node = ctx.file_node(call.container_id, image)
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "load_image", image and node.key, new.key,
                              call, res=res))
    return ctx.covered(out, call)


def exit_(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    seg = ctx.seg(call)
    parent = ctx.st.proc.parent_of(seg, call.te_ns)
    ctx.st.proc.on_exit(seg, call.ts_ns)
    if parent is None or parent == seg.key:
        return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
    ctx.attach(out, ctx.proc_node(seg))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "exit", parent, seg.key, call))
    return ctx.covered(out, call)


def _target_pid(call: Call) -> int:
    for key in ("pid", "tgid", "tid"):
        value = call.number(key)
        if value:
            return value
    return 0


def signal(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    subject = ctx.key(call)
    pid = _target_pid(call)
    sig = call.text("sig")
    if sig:
        ctx.ops(out, call, f"signal:{A.int_of(sig) or sig}")

    if pid <= 0:
        return ctx.give_up(out, call, Bucket.DROP, "pid_group")
    target = ctx.st.proc.resolve_or_none(call.container_id, pid, call.ts_ns)
    if target is None:
        return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
    if target == subject:
        return ctx.give_up(out, call, Bucket.DROP, "self_signal")
    ctx.attach(out, ctx.proc_node(ctx.st.proc.resolve(call.container_id, pid, call.ts_ns)))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "signal", subject, target, call, res=ctx.res(call)))
    return ctx.covered(out, call)


def _pid_verb(action: str):
    def handler(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
        out = Outcome()
        subject = ctx.key(call)
        pid = _target_pid(call)
        if pid <= 0:
            return ctx.give_up(out, call, Bucket.OTHER, "no_target_arg")
        target = ctx.st.proc.resolve_or_none(call.container_id, pid, call.ts_ns)
        if target is None:
            return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
        if target == subject:
            return ctx.give_up(out, call, Bucket.DROP, "self_target")
        ctx.add(out, ctx.edge(EdgeClass.P2P, action, subject, target, call, res=ctx.res(call)))
        return ctx.covered(out, call)

    return handler


wait = _pid_verb("wait")
ptrace = _pid_verb("ptrace")
mem_read = _pid_verb("mem_read")
mem_write = _pid_verb("mem_write")
pidfd_getfd = _pid_verb("pidfd_getfd")
