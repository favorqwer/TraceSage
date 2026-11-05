"""取数层格式与查询文本的单测（不需要数据库、不需要模型）。

钉住三件事：
1. 索引记录的字节布局与关系码顺序（改动会让旧索引失效，必须显式升 FORMAT_VERSION）；
2. 顶点 / 边 / POI 查询共用同一套顶点键表达式；
3. result -> 成败码 -> 成败名的换算。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from domain.edge import ALL_RELS, RELATION_LABELS
from closure import storage as S


class StorageFormatTest(unittest.TestCase):
    def test_record_sizes_and_format_version(self) -> None:
        self.assertEqual(S.RECORD.size, 44)
        self.assertEqual(S.BUCKET_RECORD.size, 48)
        self.assertEqual(S.FORMAT_VERSION, 9)

    def test_relation_codes_follow_domain_order(self) -> None:
        self.assertEqual(tuple(S.REL_CODES), ALL_RELS)
        for rel, code in S.REL_CODES.items():
            self.assertEqual(S.REL_BY_CODE[code], rel)

    def test_edge_queries_cover_all_relations(self) -> None:
        self.assertEqual(set(S.EDGE_QUERIES), set(ALL_RELS))
        for rel in ALL_RELS:
            kind_a, kind_b = RELATION_LABELS[rel]
            query = S.EDGE_QUERIES[rel]
            self.assertIn(f"MATCH (a:{kind_a})-[e:", query, rel)
            self.assertIn(f"|{rel}]->(b:{kind_b})", query, rel)
            self.assertIn(S.key_expr("a", kind_a), query, rel)
            self.assertIn(S.key_expr("b", kind_b), query, rel)

    def test_poi_query_reuses_process_key(self) -> None:
        query = S.poi_query("p2f", "file")
        self.assertIn(S.key_expr("p", "Process"), query)
        self.assertIn(S.name_expr("p"), query)
        self.assertIn("o.file_id", query)
        self.assertIn("o.path", query)

    def test_effect_code_round_trip(self) -> None:
        self.assertEqual(S.effect_code(None), 0)
        self.assertEqual(S.effect_code(0), 1)
        self.assertEqual(S.effect_code(17), 1)
        self.assertEqual(S.effect_code(-13), 2)
        self.assertEqual([S.effect_name(code) for code in range(3)], ["", "success", "failure"])
        self.assertEqual(S.effect_name(9), "")


if __name__ == "__main__":
    unittest.main()
