"""边方向表的单测（不需要数据库、不需要模型）：五种关系类型的方向、两端类别与归属端。

口径：方向与两端类别只写 `core/graph_facts.py` 这一份，闭包、折叠、索引构建、判定层渲染都查它；
"归属进程"（按归属规则拥有这条边的进程：写文件/网络归源进程，文件/网络被读写归目标进程，
进程派生归子进程）在内容三元素里是源端还是目标端也由关系类型唯一决定。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from domain import edge as G

# 关系类型 -> （源端类别, 目标端类别）
EXPECTED_LABELS = {
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
    "p2p": ("Process", "Process"),
}

OWNER = "OWNER"          # 归属进程的内容（进程用可执行路径口径）
OTHER = "OTHER"          # 另一端的内容（文件是路径，网络是四元组标识）


class RelationShapeTest(unittest.TestCase):
    def test_relation_set_and_order(self) -> None:
        self.assertEqual(G.ALL_RELS, ("p2f", "f2p", "p2n", "n2p", "p2p"))
        self.assertEqual(set(G.RELATION_LABELS), set(G.ALL_RELS))

    def test_labels_and_owner_side(self) -> None:
        for rel, labels in EXPECTED_LABELS.items():
            self.assertEqual(G.labels_of(rel), labels, rel)
            self.assertEqual(G.owner_is_source(rel), rel in G.PRODUCER_RELS, rel)

    def test_content_triple_direction(self) -> None:
        for rel, (src_label, _dst_label) in EXPECTED_LABELS.items():
            src, syscall, dst, triple_src_label = G.content_triple_of(rel, "read", OWNER, OTHER)
            if rel in G.PRODUCER_RELS:
                self.assertEqual((src, dst), (OWNER, OTHER), rel)
            else:
                self.assertEqual((src, dst), (OTHER, OWNER), rel)
            self.assertEqual(syscall, "read", rel)
            self.assertEqual(triple_src_label, src_label, rel)

    def test_endpoints_round_trip_with_content_triple(self) -> None:
        """内容三元素与"归属进程 / 另一端"两个视角可以互相反推（索引与闭包共用同一口径）。"""
        for rel in G.ALL_RELS:
            src, _syscall, dst, _src_label = G.content_triple_of(rel, "read", OWNER, OTHER)
            owner, other, other_label = G.endpoints_of(rel, src, dst)
            self.assertEqual(owner, OWNER, rel)
            self.assertEqual(other, OTHER, rel)
            expected_other = EXPECTED_LABELS[rel][1] if rel in G.PRODUCER_RELS \
                else EXPECTED_LABELS[rel][0]
            self.assertEqual(other_label, expected_other, rel)

    def test_groupings(self) -> None:
        self.assertEqual(G.PRODUCER_RELS, ("p2f", "p2n"))
        self.assertEqual(G.CONSUMER_RELS, ("f2p", "n2p"))
        self.assertEqual(G.DERIVATION_REL, "p2p")
        self.assertTrue(G.is_derivation("p2p"))
        for rel in ("p2f", "f2p", "p2n", "n2p"):
            self.assertFalse(G.is_derivation(rel), rel)
        self.assertEqual(set(G.PRODUCER_RELS) | set(G.CONSUMER_RELS) | {G.DERIVATION_REL},
                         set(G.ALL_RELS))

    def test_vertex_kinds_and_channels(self) -> None:
        self.assertEqual(G.VERTEX_KINDS, ("Process", "File", "Network"))
        self.assertEqual(G.CHANNEL_BITS, {"Process": 1, "File": 2, "Network": 4, "seed": 8})
        self.assertEqual(G.SCENARIO_KIND_LABELS, {"file": "File", "network": "Network"})

    def test_full_relation_names_are_derived_from_labels(self) -> None:
        for rel in G.ALL_RELS:
            full = next(k for k, v in G.REL_NORM.items() if v == rel and k != rel)
            self.assertEqual(G.normalize_rel(full), rel)
            self.assertTrue(G.cypher_rel_match(full).endswith(f"|{rel}"))

    def test_unknown_relation_falls_back_to_process(self) -> None:
        """未知关系类型按"进程到进程"处理（数据模型里不该出现，但查询分支要稳）。"""
        self.assertEqual(G.labels_of("nope"), ("Process", "Process"))
        self.assertFalse(G.owner_is_source("nope"))
        self.assertFalse(G.is_derivation("nope"))
        self.assertEqual(G.content_triple_of("nope", "read", OWNER, OTHER),
                         (OTHER, "read", OWNER, "Process"))


if __name__ == "__main__":
    unittest.main()
