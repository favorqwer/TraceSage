"""第 2 层：切批规则（不丢边、装得满、同一步骤的边在批内连续）。"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pagent.layers.l2_prepare import make_batches


class BatchingTest(unittest.TestCase):
    def test_batching_rules(self) -> None:
        edges = ([{"src": f"f{i}", "syscall": "read", "dst": "p", "step_key": "s1", "t0": i} for i in range(3)]
                 + [{"src": f"g{i}", "syscall": "read", "dst": "p", "step_key": "s2", "t0": i} for i in range(2)]
                 + [{"src": f"h{i}", "syscall": "read", "dst": "p", "step_key": "s3", "t0": i} for i in range(30)])
        batches = make_batches(edges, 10)
        sizes = [sum(len(e) for _, e in b) for b in batches]
        self.assertTrue(all(s <= 10 for s in sizes), f"每批不超过批大小：{sizes}")
        self.assertEqual(sum(len(e) for b in batches for _, e in b), len(edges), "切批不丢边")
        self.assertEqual(len(batches), 4, f"切批数量符合预期（{len(batches)} 批）")
        self.assertGreaterEqual(min(sizes[:-1]), 9, f"批次填得满（{sizes}）")
        self.assertTrue(any(len(b) > 1 for b in batches), "小步骤被合并进同一批")
        for batch in batches:
            seen: list[str] = []
            for key, _ in batch:
                if not seen or seen[-1] != key:
                    seen.append(key)
            self.assertEqual(len(seen), len(set(seen)), "同一步骤的边在批内连续（不被其它步骤插队）")


if __name__ == "__main__":
    unittest.main()
