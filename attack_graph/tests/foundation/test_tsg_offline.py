"""验证 TSGSource 离线闭包、离线 POI 定位与本地规则知识库零 Neo4j 检索。"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from closure import traversal as C  # noqa: E402
from closure.snapshot import TSGSource  # noqa: E402
from rag.graph_retrieve import RuleGraphRetriever  # noqa: E402
from rag.motif_likelihood import MotifLikelihoodIndex  # noqa: E402
import settings as cfg  # noqa: E402

if str(cfg.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(cfg.REPO_ROOT))
from tsg.format import TSGWriter  # noqa: E402


class TSGOfflineTests(unittest.TestCase):
    def test_tsg_source_closure_and_poi_zero_neo4j(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsg_path = Path(tmp) / "unit.tsg"
            w = TSGWriter(tsg_path, scenario="unit", database="unit-v2")
            w.add_vertex("Process", "h1|host|1|10", {
                "content": "/p1", "host_id": "h1", "container_id": "host",
                "pid": 1, "ppid": 0, "exepath": "/p1", "args": "/p1 -x",
            })
            w.add_vertex("Process", "h1|host|2|20", {
                "content": "/p2", "host_id": "h1", "container_id": "host",
                "pid": 2, "ppid": 1, "exepath": "/p2", "args": "/p2",
            })
            w.add_vertex("File", "/f", {"content": "/f", "host_id": "h1", "container_id": "host", "file_type": "file"})
            w.add_vertex("File", "/proc/1/limits", {"content": "/proc/1/limits", "host_id": "h1", "file_type": "file"})
            w.add_vertex("File", "/out", {"content": "/out", "host_id": "h1", "container_id": "host", "file_type": "file"})
            w.add_vertex("Network", "10.0.0.1:1->10.0.0.2:2", {
                "content": "10.0.0.1:1->10.0.0.2:2", "host_id": "h1", "protocol": "tcp",
            })

            w.add_edge(rel="p2p", src_kind="Process", src_key="h1|host|1|10",
                       dst_kind="Process", dst_key="h1|host|2|20",
                       event_id=1, start_ns=20, end_ns=21, syscall="clone", action="clone", result=0)
            w.add_edge(rel="p2f", src_kind="Process", src_key="h1|host|2|20",
                       dst_kind="File", dst_key="/f",
                       event_id=2, start_ns=40, end_ns=40, syscall="write", action="write", result=10)
            w.add_edge(rel="f2p", src_kind="File", src_key="/f",
                       dst_kind="Process", dst_key="h1|host|1|10",
                       event_id=3, start_ns=100, end_ns=105, syscall="read", action="read", result=7)
            w.add_edge(rel="p2f", src_kind="Process", src_key="h1|host|1|10",
                       dst_kind="File", dst_key="/out",
                       event_id=4, start_ns=120, end_ns=122, syscall="write", action="write", result=5)
            w.add_edge(rel="f2p", src_kind="File", src_key="/proc/1/limits",
                       dst_kind="Process", dst_key="h1|host|1|10",
                       event_id=5, start_ns=110, end_ns=111, syscall="read", action="read", result=4)
            w.finish()

            src = TSGSource(tsg_path)
            try:
                pois = src.find_poi(kind="file", rel="p2f", syscall="write", key="/out")
                self.assertEqual([r["event_id"] for r in pois], [4])
                self.assertEqual(src.parent_of_process("h1|host|2|20"), "h1|host|1|10")
                self.assertEqual(src.network_protocols(), {"10.0.0.1:1->10.0.0.2:2": "tcp"})
                self.assertEqual(src.process_info("h1|host|1|10")["args"], "/p1 -x")

                seed = C.Event(
                    event_id=4, rel="p2f", syscall="write", bytes=5, start=120, end=122,
                    pid="h1|host|1|10", owner="/p1", other="/out", other_label="File",
                    effect="success", action="write", result=5, src_host="h1", dst_host="h1",
                )
                res = C.run_closure(src, [seed], poi_t0=120)
                eids = {e.event_id for e in res["events"]}
                self.assertEqual(eids, {1, 2, 3, 4, 5})
                self.assertGreaterEqual(sum(src.nondelivery_not_expanded.values()), 1)
            finally:
                src.close()

    def test_local_rule_retriever_and_likelihood_zero_neo4j(self) -> None:
        fold = "1_Web_Exploit_Ransomware"
        retriever = RuleGraphRetriever(fold=fold)
        try:
            motifs = retriever.all_motifs()
            self.assertGreater(len(motifs), 0)
            first_m = motifs[0]["motif"]
            first_h = motifs[0]["hops"][0]
            res = retriever.retrieve_rules(first_h["src_role"], first_h["syscall"], first_h["dst_role"], limit=5)
            self.assertTrue(len(res["exact"]) >= 1)
            self.assertEqual(res["motifs"][0]["entry_source"], "exact")
            sub = retriever.expand_motif(first_m["motif_id"])
            self.assertIsNotNone(sub)
            self.assertEqual(sub["motif"]["motif_id"], first_m["motif_id"])
        finally:
            retriever.close()

        lr_idx = MotifLikelihoodIndex(fold)
        lr_idx.load()
        val = lr_idx.get_weighted_lr(first_m["motif_id"])
        self.assertIsInstance(val, float)


if __name__ == "__main__":
    unittest.main()
