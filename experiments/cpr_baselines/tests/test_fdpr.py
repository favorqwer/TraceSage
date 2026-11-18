"""FDPR (USENIX Security 2018 完整内核) 单元测试。"""

import unittest
from experiments.cpr_baselines.event import ActionKind, EntityKind, TraceEvent
from experiments.cpr_baselines.reducers.fdpr_reducer import FDPRReducer


class TestFDPRReducer(unittest.TestCase):

    def setUp(self):
        self.reducer = FDPRReducer(enable_rno=True, enable_reo_star=True, enable_cco=True)

    def test_reo_omits_duplicate_direct_edge(self):
        """测试 REO (Section 4.2.1)：同一版本状态下的直接重复边被省略。"""
        # P1 写 F1 两次 (未被消费，F1 版本原地复用)
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="write", dst_id="f1", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        e2 = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="write", dst_id="f1", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )

        r1 = self.reducer.process_event(e1)
        r2 = self.reducer.process_event(e2)

        self.assertIsNotNone(r1)
        self.assertIsNone(r2)

    def test_reo_star_omits_transitive_ancestor_edge(self):
        """测试 REO* (Section 4.2.2)：已存在传递因果链时，直接边被 REO* 全局省略。"""
        # 1. P1 写 F1 (p1 -> f1)
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="write", dst_id="f1", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        # 2. P2 读 F1 (f1 -> p2，使得 p1 成为 p2 的传递前驱祖先)
        e2 = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f1", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        self.reducer.process_event(e1)
        self.reducer.process_event(e2)

        # 3. 此时 p1 已经是 p2 的祖先。现在发生直接事件 p1 衍生 p2 (clone)
        e3 = TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="clone", dst_id="p2", dst_kind=EntityKind.PROCESS, result=0, bytes_count=0
        )
        r3 = self.reducer.process_event(e3)

        # REO* 算子生效：因为 p1 已经在 p2 的祖先闭包中，直接边被全局判定为冗余省略！
        self.assertIsNone(r3)

    def test_execve_truncates_ancestor_dependencies(self):
        """测试 Section 6.1：execve 物理重写内存并截断祖先依赖链。"""
        # 1. P1 读 /tmp/malware.sh (建立祖先关系)
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="/tmp/malware.sh", dst_kind=EntityKind.FILE, result=50, bytes_count=50
        )
        self.reducer.process_event(e1)

        # 2. P1 执行 execve 重置映像为 /bin/ls
        e_exec = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="execve", dst_id="/bin/ls", dst_kind=EntityKind.FILE, result=0, bytes_count=0
        )
        self.reducer.process_event(e_exec)

        # 验证此时 p1 的活跃版本的祖先闭包已被清空截断
        curr_p1_ver = self.reducer._active_versions["p1"]
        self.assertEqual(len(self.reducer._ancestors[curr_p1_ver.node_key]), 0)

    def test_rno_splits_version_when_intervening_read_occurs(self):
        """测试 RNO 语义：写操作在客体被读取消费后，后续写操作必须分裂新版本，严禁合并。"""
        # 1. 进程 P 写文件 F (F 活跃版本为 F#v0)
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p", src_kind=EntityKind.PROCESS,
            syscall="write", dst_id="f", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        r1 = self.reducer.process_event(e1)
        self.assertIsNotNone(r1)
        self.assertEqual(r1.dst_id, "f#v0")

        # 2. 进程 Q 读文件 F (F#v0 被消费，has_descendants 变为 True)
        e2 = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="q", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="f", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        r2 = self.reducer.process_event(e2)
        self.assertIsNotNone(r2)
        self.assertEqual(r2.src_id, "f#v0")

        # 3. 进程 P 再次写文件 F (F 必须分裂出 F#v1，严禁合并回 F#v0)
        e3 = TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p", src_kind=EntityKind.PROCESS,
            syscall="write", dst_id="f", dst_kind=EntityKind.FILE, result=10, bytes_count=10
        )
        r3 = self.reducer.process_event(e3)
        self.assertIsNotNone(r3, "第三步写入由于客体已被读取消费，必须生成新因果边而非被省略合并")
        self.assertEqual(r3.dst_id, "f#v1")



if __name__ == "__main__":
    unittest.main()
