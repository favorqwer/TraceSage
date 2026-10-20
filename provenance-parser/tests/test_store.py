import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.neo4j import _NODE_QUERIES, _edge_query  # noqa: E402
from provenance.core.kinds import EdgeClass  # noqa: E402


class StoreQueryTest(unittest.TestCase):
    """写库查询的参数名必须与 write_edges 传的行键一致。

    曾经把 `x.s` 拼成 `x.sk`，MERGE 静默不建边、API 不报错；这个测试锁住它。
    """

    def test_edge_query_uses_same_keys_as_rows(self):
        for cls in EdgeClass:
            q = _edge_query(cls)
            self.assertIn("x.s[0]", q)
            self.assertIn("x.d[0]", q)
            self.assertNotIn("x.sk", q)
            self.assertNotIn("x.dk", q)
            self.assertIn(f"[r:{cls.value} ", q)   # 与既有图同名的 lowercase 关系类型
            self.assertNotIn(f"[r:{cls.name} ", q)

    def test_node_queries_use_k_and_p(self):
        for label, q in _NODE_QUERIES.items():
            self.assertIn("x.k[0]", q, label)
            self.assertIn("x.p", q, label)

    def test_page_shape_matches_node_keys(self):
        # Process 4 段、File 3 段、Network 2 段
        self.assertIn("born_ns: x.k[3]", _NODE_QUERIES["Process"])
        self.assertIn("path: x.k[2]", _NODE_QUERIES["File"])
        self.assertIn("tuple: x.k[1]", _NODE_QUERIES["Network"])


if __name__ == "__main__":
    unittest.main()
