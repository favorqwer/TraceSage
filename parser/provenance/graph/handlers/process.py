"""ProcessToProcess 动词：clone / exec / exit / signal / wait / ptrace / mem_* / pidfd_getfd。"""

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
    result = ctx.result(call)
    if "CLONE_THREAD" in flags:
        if result is not None and result > 0:
            parent = ctx.seg(call)
            ctx.st.proc.on_thread_clone(parent, result)
            return ctx.give_up(out, call, Bucket.DROP, "thread_clone")
        return ctx.give_up(out, call, Bucket.DROP, "thread_clone_unobserved")

    parent = ctx.seg(call)
    if result == 0:
        return ctx.give_up(out, call, Bucket.DROP, "clone_child_view")
    if result is None:
        return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:clone")
    if result < 0:
        return ctx.attempt(out, call, "clone", "-", result)

    child_pid = result
    child = ctx.st.proc.on_clone(
        parent, child_pid, call.start_ns,
        call.exit.exe if call.exit else parent.exe_path,
        call.exit.proc_args if call.exit else parent.cmdline,
    )
    if call.exit is not None:
        child.uid = call.exit.ruid or parent.uid
        child.ppid = child.ppid or (call.exit.ppid or parent.key.pid)
    ctx.st.fds.fork(call.container_id, parent.key.pid, child_pid)
    ctx.attach(out, ctx.proc_node(parent))
    ctx.attach(out, ctx.proc_node(child))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "clone", parent.key, child.key, call, result=child_pid))
    return ctx.covered(out, call)


def exec_(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()
    result = ctx.result(call)
    old = ctx.seg(call)
    target = ctx.norm_path(call.text("filename"), call, "dirfd")

    if result is None:
        return ctx.give_up(out, call, Bucket.OTHER, "result_unobserved:exec")
    if result < 0:
        return ctx.attempt(out, call, "exec", target or call.text("filename"), result)

    exe = (call.exit.exe if call.exit else "") or old.exe_path
    proc_args = (call.exit.proc_args if call.exit else "") or ""
    new = ctx.st.proc.on_exec(old, call.start_ns, exe, proc_args)
    ctx.st.fds.prune_cloexec(call.container_id, call.pid)

    ctx.attach(out, ctx.proc_node(old))
    ctx.attach(out, ctx.proc_node(new))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "exec", old.key, new.key, call, result=result))

    # 同一次 execve 的第二条边：可执行文件 -> 新进程。动作名与 ProcessToProcess 那条相同
    # （都是 execve 的产物），靠关系类型区分角色，不再造 load_image 这种自造词。
    image = target or ctx.norm_path(exe, call)
    if image:
        node = ctx.file_node(call.container_id, image)
        ctx.attach(out, node)
        ctx.add(out, ctx.edge(EdgeClass.F2P, "exec", image and node.key, new.key,
                              call, result=result))
    return ctx.covered(out, call)


def exit_(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
    out = Outcome()

    # 退出路径只允许使用活段，绝不在这里新建身份段。
    live = ctx.st.proc.live(call.container_id, call.pid)
    if live is None:
        ctx.st.proc.counts["exit_no_segment"] += 1
        # 没有身份段也要清掉可能残留的 fd 状态，防止 pid 复用时串线。
        ctx.st.fds.close_all(call.container_id, call.pid)
        return ctx.give_up(out, call, Bucket.OTHER, "exit_no_segment")

    tid = call.tid
    if tid <= 0:
        ctx.st.proc.counts["exit_tid_missing"] += 1
        tid = call.pid

    if call.call == "exit_group":
        # 整组退出，一定是进程退出。
        ctx.st.proc.on_exit(live, call.start_ns)
        ctx.st.fds.close_all(call.container_id, call.pid)
    else:
        # procexit / exit：可能是线程退出。
        if tid != call.pid and tid not in live.threads:
            ctx.st.proc.counts["thread_untracked"] += 1
            return ctx.give_up(out, call, Bucket.OTHER, "thread_untracked")
        last_thread = ctx.st.proc.on_thread_exit(live, tid, call.start_ns)
        if not last_thread:
            return ctx.give_up(out, call, Bucket.OTHER, "thread_exit")
        ctx.st.fds.close_all(call.container_id, call.pid)

    parent = ctx.st.proc.parent_of(live, call.end_ns)
    if parent is None or parent == live.key:
        return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
    ctx.attach(out, ctx.proc_node(live))
    # 退出通知：子 -> 父；不是“父导致子退出”。
    ctx.add(out, ctx.edge(EdgeClass.P2P, "exit", live.key, parent, call))
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
    target = ctx.st.proc.resolve_or_none(call.container_id, pid, call.start_ns)
    if target is None:
        return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
    if target == subject:
        return ctx.give_up(out, call, Bucket.DROP, "self_signal")
    ctx.attach(out, ctx.proc_node(ctx.st.proc.resolve(call.container_id, pid, call.start_ns)))
    ctx.add(out, ctx.edge(EdgeClass.P2P, "signal", subject, target, call, result=ctx.result(call)))
    return ctx.covered(out, call)


def _ptrace_read(call: Call) -> bool:
    """ptrace 请求是不是“从目标读”：PEEK/GET 类 -> 目标 -> tracer。"""
    text = call.text("request")
    upper = text.upper()
    if ("PEEK" in upper or "GETREGS" in upper or "GETFPREGS" in upper
            or "GETSIGINFO" in upper or "GETEVENTMSG" in upper
            or "GET_SYSCALL_INFO" in upper):
        return True
    num = A.int_of(text)
    return num in {1, 2, 3, 12, 14, 0x4201, 0x4202, 0x4204, 0x420E}


def _pid_verb(action: str):
    def handler(ctx: EmitContext, call: Call, decision: Decision) -> Outcome:
        out = Outcome()
        subject = ctx.key(call)
        pid = _target_pid(call)
        if pid <= 0:
            return ctx.give_up(out, call, Bucket.OTHER, "no_target_arg")
        target = ctx.st.proc.resolve_or_none(call.container_id, pid, call.start_ns)
        if target is None:
            return ctx.give_up(out, call, Bucket.OTHER, "target_unresolved")
        if target == subject:
            return ctx.give_up(out, call, Bucket.DROP, "self_target")

        # 数据流方向：读类 target -> subject；写类 subject -> target。
        src, dst = subject, target
        if action in ("mem_read", "pidfd_getfd", "wait"):
            src, dst = target, subject
        elif action == "ptrace" and _ptrace_read(call):
            src, dst = target, subject
        ctx.add(out, ctx.edge(EdgeClass.P2P, action, src, dst, call,
                              result=ctx.result(call)))
        return ctx.covered(out, call)

    return handler


wait = _pid_verb("wait")
ptrace = _pid_verb("ptrace")
mem_read = _pid_verb("mem_read")
mem_write = _pid_verb("mem_write")
pidfd_getfd = _pid_verb("pidfd_getfd")
