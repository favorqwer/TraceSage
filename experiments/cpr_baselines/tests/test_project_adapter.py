"""TraceSage_Current 项目适配器单元测试。"""

import unittest
from experiments.cpr_baselines.event import ActionKind, EntityKind, TraceEvent
from experiments.cpr_baselines.reducers.project_adapter import ProjectCurrentReducer


class TestProjectCurrentReducer(unittest.TestCase):

    def setUp(self):
        self.reducer = ProjectCurrentReducer()

    def test_execve_dual_edge_and_process_evolution(self):
        """测试主干 execve 映像替换生成 ProcessToProcess 与 FileToProcess 双边。"""
        e_exec = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="proc:100:bash", src_kind=EntityKind.PROCESS,
            syscall="execve", dst_id="file:/bin/ls", dst_kind=EntityKind.FILE, result=0
        )
        self.reducer.process_event(e_exec)
        nodes, edges = self.reducer.export_graph()

        # 应产生旧进程->新进程 与 镜像文件->新进程 两条边
        self.assertEqual(len(edges), 2)
        p2p = [e for e in edges if e.src_kind == EntityKind.PROCESS and e.dst_kind == EntityKind.PROCESS]
        f2p = [e for e in edges if e.src_kind == EntityKind.FILE and e.dst_kind == EntityKind.PROCESS]
        self.assertEqual(len(p2p), 1)
        self.assertEqual(len(f2p), 1)
        self.assertEqual(p2p[0].action, ActionKind.EXEC)
        self.assertEqual(f2p[0].action, ActionKind.EXEC)

    def test_dual_track_effect_isolation(self):
        """测试主干双轨因果：同一三元组的成功与失败调用不混叠。"""
        e_succ = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="proc:100:bash", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="file:/etc/passwd", dst_kind=EntityKind.FILE, result=3
        )
        e_fail = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="proc:100:bash", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="file:/etc/passwd", dst_kind=EntityKind.FILE, result=-2
        )
        self.reducer.process_event(e_succ)
        self.reducer.process_event(e_fail)
        nodes, edges = self.reducer.export_graph()

        # 成功与失败各出一条独立边
        self.assertEqual(len(edges), 2)
        succ_edge = [e for e in edges if e.success_count > 0]
        fail_edge = [e for e in edges if e.fail_count > 0]
        self.assertEqual(len(succ_edge), 1)
        self.assertEqual(len(fail_edge), 1)


if __name__ == "__main__":
    unittest.main()
