import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "experiments" / "plain_llm"))
from plainllm.checkpoint import load_checkpoint, request_identity, write_checkpoint
from plainllm.chunking import format_edge, load_triples
from plainllm.export_graph import export_graph
from plainllm.poi import find_anchor_triple
import score_and_summarize as scoring


class PlainTripletsTest(unittest.TestCase):
    def test_export_merges_outcomes_and_model_uses_the_same_relation_id(self):
        rows = [{"sa": "/p", "ka": "P", "sb": "/f", "kb": "F", "rel": "p2f",
                  "call": "write", "action": "write", "pay": None,
                  "result": result, "t0": timestamp, "t1": timestamp + 1}
                for result, timestamp in ((0, 9), (-1, 4), (None, 15))]
        rows.append({**rows[0], "ka": "F", "t0": 18, "t1": 19})
        session = MagicMock()
        session.__enter__.return_value = session
        counts = MagicMock()
        counts.single.return_value = {"c": 1}
        session.run.side_effect = [rows, counts, counts, counts]
        driver = MagicMock()
        driver.session.return_value = session
        with tempfile.TemporaryDirectory() as directory, patch(
                "plainllm.export_graph.GraphDatabase.driver", return_value=driver):
            path = Path(directory) / "edges.jsonl"
            stats = export_graph("bolt://unused", "u", "p", "attack-test-v2", path)
            triples = load_triples(path)
            self.assertEqual((stats["triples"], stats["instances"]), (2, 4))
            self.assertEqual((triples[0]["first_ns"], triples[0]["last_ns"]), (4, 16))
            self.assertNotIn("effect", triples[0])
            self.assertEqual(find_anchor_triple({"src": "/p", "src_kind": "P", "call": "write",
                                                 "dst": "/f", "dst_kind": "F"}, triples)["id"],
                             triples[0]["id"])
            self.assertNotIn("eff=", format_edge(triples[0]))
            self.assertEqual(find_anchor_triple({"src": "/p", "src_kind": "F", "call": "write",
                                                 "dst": "/f", "dst_kind": "F"}, triples)["id"],
                             triples[1]["id"])

    def test_score_cache_rechecks_report_and_groundtruth(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "graphs").mkdir()
            (folder / "graphs/unit.tsg").write_bytes(b"test")
            gt = folder / "unit.groundtruth.json"
            gt.write_text("{}", encoding="utf-8")
            report = folder / "report.json"
            metadata = {"input_protocol": "triplet-v1", "endpoint_identity": "typed-endpoints-v1"}
            report.write_text(json.dumps(metadata), encoding="utf-8")
            cache = folder / "metrics.json"

            def score(command, **kwargs):
                Path(command[-1]).write_text(json.dumps({"scoring_protocol": "triplet-v1",
                                                        "totals": {"steps_hit": 1}}), encoding="utf-8")
                return SimpleNamespace(returncode=0)

            with patch.object(scoring, "ROOT", folder), patch.object(scoring, "GT_DIR", folder), patch.object(
                    scoring.subprocess, "run", side_effect=score) as scorer:
                scoring.score_scenario("unit", report, cache, False)
                scoring.score_scenario("unit", report, cache, False)
                self.assertEqual(scorer.call_count, 1)
                report.write_text(json.dumps({**metadata, "edges": []}), encoding="utf-8")
                scoring.score_scenario("unit", report, cache, False)
                gt.write_text('{"attack_path":[]}', encoding="utf-8")
                scoring.score_scenario("unit", report, cache, False)
                self.assertEqual(scorer.call_count, 3)

    def test_request_cache_rejects_legacy_and_changed_input(self):
        config = SimpleNamespace(model="unit", base_url="unit", temperature=0, max_tokens=None,
                                 response_format_json=True, extra_body={})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chunk.json"
            path.write_text(json.dumps({"ids": ["E000001"]}), encoding="utf-8")
            identity = request_identity(config, "one", "system", "body")
            self.assertIsNone(load_checkpoint(path, identity))
            write_checkpoint(path, {**identity, "ids": ["E000001"]})
            self.assertEqual(load_checkpoint(path, identity)["ids"], ["E000001"])
            self.assertIsNone(load_checkpoint(path, request_identity(config, "two", "system", "body")))
            self.assertIsNone(load_checkpoint(path, request_identity(config, "one", "system", "changed")))
