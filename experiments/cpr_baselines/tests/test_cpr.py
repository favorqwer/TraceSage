"""CPR (CCS 2016 完整内核) 单元测试。"""

import unittest
from experiments.cpr_baselines.event import ActionKind, EntityKind, TraceEvent
from experiments.cpr_baselines.reducers.cpr_reducer import CPRReducer


class TestCPRReducer(unittest.TestCase):

    def setUp(self):
        self.reducer = CPRReducer(default_syscall_duration_ns=1000)

    def test_consecutive_reads_compression(self):
        """测试同一打开会话内的连续读取被正确折叠。"""
        # P1 读 F1 三次
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=100, bytes_count=100
        )
        e2 = TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=100, bytes_count=100
        )
        e3 = TraceEvent(
            host_id="h1", ts_ns=5000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=100, bytes_count=100
        )

        r1 = self.reducer.process_event(e1)
        r2 = self.reducer.process_event(e2)
        r3 = self.reducer.process_event(e3)

        self.assertIsNotNone(r1)
        self.assertIsNone(r2)
        self.assertIsNone(r3)

        nodes, edges = self.reducer.export_graph()
        # 读边因果源为 f1，目标为 p1
        f1_edges = [e for e in edges if e.src_id == "f1" and e.dst_id == "p1"]
        self.assertEqual(len(f1_edges), 1)
        self.assertEqual(f1_edges[0].instances, 3)
        self.assertEqual(f1_edges[0].total_bytes, 300)

    def test_close_file_breaks_aggregation_session(self):
        """测试 Section 3.1.3：进程 close 文件后再次 open 读取，会话切断，严格禁止跨会话合并。"""
        # 1. 第一次打开会话读取
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=50, bytes_count=50
        )
        self.reducer.process_event(e1)

        # 2. 进程调用 close 关闭该文件
        e_close = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="close", dst_id="f1", dst_kind=EntityKind.FILE, result=0, bytes_count=0
        )
        self.reducer.process_event(e_close)

        # 3. 第二次打开后再次读取同一文件
        e2 = TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=50, bytes_count=50
        )
        r2 = self.reducer.process_event(e2)

        # 因为会话已被 close 切断，e2 不能与 e1 合并，必须作为新的独立边保留！
        self.assertIsNotNone(r2)

        nodes, edges = self.reducer.export_graph()
        f1_read_edges = [e for e in edges if e.src_id == "f1" and e.dst_id == "p1" and e.action == ActionKind.READ]
        self.assertEqual(len(f1_read_edges), 2)


if __name__ == "__main__":
    unittest.main()
