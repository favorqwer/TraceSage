"""NodeMerge (CCS 2018 完整内核) 单元测试。"""

import unittest
from experiments.cpr_baselines.event import ActionKind, EntityKind, TraceEvent
from experiments.cpr_baselines.reducers.nodemerge_reducer import FPTreeNode, NodeMergeReducer, merge_weakly_dominated_paths


class TestNodeMergeReducer(unittest.TestCase):

    def setUp(self):
        self.reducer = NodeMergeReducer(min_support_k=2, min_pattern_length=2, wdp_epsilon=0.05)

    def test_wdp_formula_3_compression(self):
        """测试 Section 7.2.1 公式 (3)：弱支配单分支路径在 (1-eps) < ratio < (1+eps) 时被合并。"""
        # 手工构建单分支 FP-Tree：Root -> NodeA (count=100) -> NodeB (count=99)
        # ratio = 100/99 = 1.0101，在 1-0.05 与 1+0.05 之间，属于弱支配路径
        root = FPTreeNode(file_id="<ROOT>", counter=0)
        node_a = FPTreeNode(file_id="lib_a.so", counter=100, parent=root)
        node_b = FPTreeNode(file_id="lib_b.so", counter=99, parent=node_a)
        root.children["lib_a.so"] = node_a
        node_a.children["lib_b.so"] = node_b

        merge_weakly_dominated_paths(root, epsilon=0.05)

        # 验证 node_b 是否被收缩进 node_a 的 wdp_files
        self.assertIn("lib_a.so", node_a.wdp_files)
        self.assertIn("lib_b.so", node_a.wdp_files)
        self.assertEqual(len(node_a.children), 0)

    def test_template_clustering_with_real_syscalls(self):
        """测试只读库聚类合并且保留底层真实系统调用语义 (mmap/read)。"""
        # P1 启动读取两个库
        e1 = TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="mmap", dst_id="lib_a.so", dst_kind=EntityKind.FILE, result=0, bytes_count=4096
        )
        e2 = TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="mmap", dst_id="lib_b.so", dst_kind=EntityKind.FILE, result=0, bytes_count=4096
        )
        # P2 启动读取两个库
        e3 = TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="mmap", dst_id="lib_a.so", dst_kind=EntityKind.FILE, result=0, bytes_count=4096
        )
        e4 = TraceEvent(
            host_id="h1", ts_ns=4000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="mmap", dst_id="lib_b.so", dst_kind=EntityKind.FILE, result=0, bytes_count=4096
        )

        self.reducer.process_event(e1)
        self.reducer.process_event(e2)
        self.reducer.process_event(e3)
        self.reducer.process_event(e4)

        nodes, edges = self.reducer.export_graph()

        # 验证虚拟模板节点产生
        template_nodes = [n for n in nodes if n.startswith("VirtualTemplate:")]
        self.assertEqual(len(template_nodes), 1)
        tpl_id = template_nodes[0]

        # 验证合并边保留了底层真实的 mmap 系统调用，而不是粗暴替换为 template_read
        tpl_edges = [e for e in edges if e.src_id == tpl_id]
        self.assertEqual(len(tpl_edges), 2)
        self.assertEqual(tpl_edges[0].syscall, "mmap")

    def test_fsa_line_8_noise_tolerance(self):
        """测试 Algorithm 2 Line 8：遇到非模板噪声文件时状态机自环维持，不打断模板匹配。"""
        # P1 依次读取 lib_a.so, lib_b.so
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="lib_a.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="lib_b.so", dst_kind=EntityKind.FILE, result=0
        ))
        # P2 依次读取 lib_a.so, 中间穿插噪声 random_noise.txt, 然后读取 lib_b.so
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="lib_a.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=3500, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="random_noise.txt", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=4000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="openat", dst_id="lib_b.so", dst_kind=EntityKind.FILE, result=0
        ))

        nodes, edges = self.reducer.export_graph()
        template_nodes = [n for n in nodes if n.startswith("VirtualTemplate:")]
        self.assertEqual(len(template_nodes), 1)
        tpl_id = template_nodes[0]

        # P2 的 lib_a 和 lib_b 依然被成功吸收到模板中，噪声文件单独保留
        tpl_edges_p2 = [e for e in edges if e.src_id == tpl_id and e.dst_id == "p2"]
        self.assertEqual(len(tpl_edges_p2), 1)
        self.assertEqual(tpl_edges_p2[0].instances, 2)
        noise_edges = [e for e in edges if e.src_id == "random_noise.txt" and e.dst_id == "p2"]
        self.assertEqual(len(noise_edges), 1)

    def test_conditional_fpgrowth_cross_branch_mining(self):
        """测试条件模式基跨分支频繁项集挖掘。"""
        # P1 访问 [head_x.so, lib_m.so, lib_n.so]
        # P2 访问 [head_y.so, lib_m.so, lib_n.so]
        # 虽然 head_x 和 head_y 使得根部分支分化，但条件模式基能成功挖掘出频繁项集 {lib_m.so, lib_n.so}
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=1000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="head_x.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=2000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="lib_m.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=3000, src_id="p1", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="lib_n.so", dst_kind=EntityKind.FILE, result=0
        ))

        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=4000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="head_y.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=5000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="lib_m.so", dst_kind=EntityKind.FILE, result=0
        ))
        self.reducer.process_event(TraceEvent(
            host_id="h1", ts_ns=6000, src_id="p2", src_kind=EntityKind.PROCESS,
            syscall="read", dst_id="lib_n.so", dst_kind=EntityKind.FILE, result=0
        ))

        nodes, edges = self.reducer.export_graph()
        template_nodes = [n for n in nodes if n.startswith("VirtualTemplate:")]
        self.assertTrue(len(template_nodes) >= 1)
        # 验证挖掘出的模板包含 lib_m.so 和 lib_n.so
        found = False
        for tpl_id, files in self.reducer.cfaps.items():
            if "lib_m.so" in files and "lib_n.so" in files:
                found = True
                break
        self.assertTrue(found, "条件模式基必须成功跨分支挖掘出共享的频繁项集")


if __name__ == "__main__":
    unittest.main()
