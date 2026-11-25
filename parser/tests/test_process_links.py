"""验证 parser 三类进程派生断链根治修复：
1. clone3 采集盲区（NoCloneExec）：通过 execve 退出行的客观 ppid (>1) 在存活窗口内补连父进程，同时严格排除 ppid=1；
2. vfork/慢 clone 晚于 execve 到达（LateVforkExec）：直接挂回前置段不造重复空壳分身；
3. 迟到 clone 到达前子进程已落图边（LateCloneOrph）：保留原 pid|0 键不遗弃已落图边。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core.classify import Decision  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.kinds import Bucket, EdgeClass  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.handlers.process import clone, exec_  # noqa: E402
from provenance.graph.state import State  # noqa: E402


def _row(
    num: int,
    ns: int,
    direction: str,
    call: str,
    pid: int,
    *,
    ppid: int = 0,
    exe: str = "",
    proc_args: str = "",
    args: dict | None = None,
    rawres: int | None = None,
) -> EventRow:
    return EventRow(
        num=num,
        ns=ns,
        direction=direction,
        call=call,
        pid=pid,
        tid=pid,
        container_id="host",
        exe=exe,
        cwd="/",
        ppid=ppid,
        ruid="33",
        proc_args=proc_args,
        args=args or {},
        rawres=rawres,
    )


class ProcessLinksFixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.state = State.build("h1")
        self.ctx = EmitContext(self.state, EmitOptions())

    def test_exec_infers_clone_from_live_ppid_for_clone3_blindspot(self) -> None:
        # 复现场景 8：php-fpm(1147) 经 clone3(<unknown>) 派生 sh(14962)
        parent_row = _row(1, 100, "<", "read", 1147, ppid=980, exe="/usr/sbin/php-fpm8.1")
        parent_seg = self.state.proc.observe(parent_row)

        enter = _row(2, 200, ">", "execve", 14962, args={"filename": "/bin/sh"})
        exit_r = _row(
            3, 210, "<", "execve", 14962, ppid=1147, exe="/bin/sh",
            proc_args="-c id", args={"res": "0"}, rawres=0,
        )
        call = Call.build(enter, exit_r)
        self.state.proc.observe(call.head_row)
        out = exec_(self.ctx, call, Decision("verb", "exec", EdgeClass.P2P, "success"))

        p2p_edges = [e for e in out.edges if e.cls == EdgeClass.P2P]
        clone_edges = [e for e in p2p_edges if e.action == "clone"]
        exec_edges = [e for e in p2p_edges if e.action == "exec"]
        self.assertEqual(len(clone_edges), 1)
        self.assertEqual(len(exec_edges), 1)
        self.assertEqual(clone_edges[0].src, parent_seg.key)
        self.assertEqual(clone_edges[0].dst, exec_edges[0].src)
        self.assertEqual(clone_edges[0].syscall, "clone")
        self.assertEqual(self.state.proc.counts["clone_inferred_from_exec_ppid"], 1)
        # 子进程在 execve 前的前置段必须继承父进程可执行路径，不得退化为空/主键
        pre_exec_nodes = [n for n in out.nodes if n.key == clone_edges[0].dst]
        self.assertTrue(pre_exec_nodes)
        self.assertEqual(pre_exec_nodes[-1].props.get("exe_path"), "/usr/sbin/php-fpm8.1")

    def test_exec_never_infers_clone_for_ppid_1_orphan(self) -> None:
        self.state.proc.observe(_row(1, 100, "<", "read", 1, ppid=0, exe="/sbin/init"))
        enter = _row(2, 200, ">", "execve", 500, args={"filename": "/bin/sh"})
        exit_r = _row(3, 210, "<", "execve", 500, ppid=1, exe="/bin/sh", args={"res": "0"}, rawres=0)
        call = Call.build(enter, exit_r)
        self.state.proc.observe(call.head_row)
        out = exec_(self.ctx, call, Decision("verb", "exec", EdgeClass.P2P, "success"))

        clone_edges = [e for e in out.edges if e.action == "clone"]
        self.assertEqual(len(clone_edges), 0)
        self.assertEqual(self.state.proc.counts["clone_inferred_from_exec_ppid"], 0)

    def test_late_vfork_after_exec_reconciles_without_ghost_segment(self) -> None:
        # 复现 LateVforkExec：父进程 t=150 进入 vfork，子进程 t=200 先完成 execve，父进程 t=250 才退出 vfork
        parent_seg = self.state.proc.observe(_row(1, 100, "<", "read", 2000, ppid=1, exe="/bin/bash"))
        # 子进程先 execve（故意设 ppid=0 检验纯 vfork 迟到场景也能接上）
        ex_enter = _row(2, 200, ">", "execve", 2001, args={"filename": "/usr/bin/curl"})
        ex_exit = _row(3, 210, "<", "execve", 2001, ppid=0, exe="/usr/bin/curl", args={"res": "0"}, rawres=0)
        ex_call = Call.build(ex_enter, ex_exit)
        self.state.proc.observe(ex_call.head_row)
        ex_out = exec_(self.ctx, ex_call, Decision("verb", "exec", EdgeClass.P2P, "success"))
        exec_edge = next(e for e in ex_out.edges if e.cls == EdgeClass.P2P and e.action == "exec")

        # 父进程晚到的 vfork 退出行
        vf_enter = _row(4, 150, ">", "vfork", 2000, exe="/bin/bash")
        vf_exit = _row(5, 250, "<", "vfork", 2000, exe="/bin/bash", args={"res": "2001"}, rawres=2001)
        vf_call = Call.build(vf_enter, vf_exit)
        vf_out = clone(self.ctx, vf_call, Decision("verb", "clone", EdgeClass.P2P, "success"))

        clone_edge = next(e for e in vf_out.edges if e.action == "clone")
        # clone 目标必须精确连到 exec 的前驱段，而不是新建的幽灵分身
        self.assertEqual(clone_edge.src, parent_seg.key)
        self.assertEqual(clone_edge.dst, exec_edge.src)
        self.assertEqual(self.state.proc.counts["late_vfork_reconciled"], 1)
        # pid=2001 全程只有 2 个段（前置段 + exec 段），没有第 3 个幽灵段
        segs_2001 = [s for s in self.state.proc.segments() if s.key.pid == 2001]
        self.assertEqual(len(segs_2001), 2)
        self.assertEqual(segs_2001[0].exe_path, "/bin/bash")
        self.assertEqual(segs_2001[1].parent, parent_seg.key)

    def test_late_clone_keeps_key_when_child_already_emitted_edge(self) -> None:
        # 复现 LateCloneOrph：子进程先落了一条边（标记 emitted_to_graph=True），随后迟到 clone 到达
        parent_seg = self.state.proc.observe(_row(1, 100, "<", "read", 3000, ppid=1, exe="/bin/bash"))
        early_child = self.state.proc.observe(_row(2, 120, "<", "read", 3001, ppid=3000, exe="/bin/bash"))
        old_key = early_child.key
        self.state.proc.mark_emitted(old_key)

        cl_enter = _row(3, 110, ">", "clone", 3000, exe="/bin/bash")
        cl_exit = _row(4, 130, "<", "clone", 3000, exe="/bin/bash", args={"res": "3001"}, rawres=3001)
        cl_call = Call.build(cl_enter, cl_exit)
        cl_out = clone(self.ctx, cl_call, Decision("verb", "clone", EdgeClass.P2P, "success"))

        clone_edge = next(e for e in cl_out.edges if e.action == "clone")
        # 必须保留原 pid|0 键，保证 clone 边与早先已落图边在同一个顶点上连通
        self.assertEqual(clone_edge.dst, old_key)
        self.assertEqual(early_child.key, old_key)
        self.assertEqual(self.state.proc.counts["late_clone_kept_key"], 1)

    def test_late_vfork_after_ppid_inferred_exec_does_not_emit_duplicate_clone_edge(self) -> None:
        parent_seg = self.state.proc.observe(_row(1, 100, "<", "read", 4000, ppid=1, exe="/bin/bash"))
        ex_enter = _row(2, 200, ">", "execve", 4001, args={"filename": "/usr/bin/id"})
        ex_exit = _row(3, 210, "<", "execve", 4001, ppid=4000, exe="/usr/bin/id", args={"res": "0"}, rawres=0)
        ex_call = Call.build(ex_enter, ex_exit)
        self.state.proc.observe(ex_call.head_row)
        ex_out = exec_(self.ctx, ex_call, Decision("verb", "exec", EdgeClass.P2P, "success"))
        inferred_clones = [e for e in ex_out.edges if e.action == "clone"]
        self.assertEqual(len(inferred_clones), 1)
        self.assertEqual(inferred_clones[0].src, parent_seg.key)

        vf_enter = _row(4, 150, ">", "vfork", 4000, exe="/bin/bash")
        vf_exit = _row(5, 250, "<", "vfork", 4000, exe="/bin/bash", args={"res": "4001"}, rawres=4001)
        vf_call = Call.build(vf_enter, vf_exit)
        vf_out = clone(self.ctx, vf_call, Decision("verb", "clone", EdgeClass.P2P, "success"))
        self.assertEqual([e for e in vf_out.edges if e.action == "clone"], [])
        self.assertEqual(self.state.proc.counts["late_vfork_reconciled"], 1)


if __name__ == "__main__":
    unittest.main()
