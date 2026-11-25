import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rules_match as rm
import score_graph_product as engine
import score_report_product as reports
from triplet_report import merge_report_edges, refresh_event_totals


class TripletScoringTest(unittest.TestCase):
    def test_totals_and_numeric_rule_use_distinct_events(self):
        triple = ("p", "write", "f")
        relation = dict(zip(("src", "syscall", "dst"), triple))
        edges = merge_report_edges([
            {**relation, "instances": 1, "event_ids": [1], "bytes": 6},
            {**relation, "instances": 2, "event_ids": [1, 2], "bytes": 12},
        ])
        memberships = [{"agg_edge_index": 0, "bundle_triple": triple}]
        first = {"event_id": 1, "bytes": 6, "start_ns": 10, "end_ns": 11,
                 "src_host": "host", "memberships": memberships}
        second = {**first, "event_id": 2, "start_ns": 15, "end_ns": 17}
        events = [first, first, second]
        refresh_event_totals(edges, events)
        self.assertEqual([edges[0][k] for k in ("instances", "bytes", "t0", "t1")], [2, 12, 10, 17])
        rule = {"rule_id": "r", "action": ["write"], "source": {}, "target": {},
                "edge": {"bytes": {"op": ">=", "value": 10}}}
        with tempfile.TemporaryDirectory() as folder, patch.object(rm.VertexKinds, "for_gt", return_value=None):
            report = Path(folder) / "report.json"
            gt = Path(folder) / "gt.json"
            report.write_text(json.dumps({"edges": edges}), encoding="utf-8")
            gt.write_text(json.dumps({"attack_path": [{"rules": [rule]}]}), encoding="utf-8")
            self.assertEqual(reports.evaluate(report, gt)["rule_hits"], [])
            for size, hits in ((6, []), (11, ["r"])):
                second["bytes"] = size
                with gzip.open(report.with_suffix(".events.json.gz"), "wt", encoding="utf-8") as stream:
                    json.dump({"events": events}, stream)
                self.assertEqual(reports.evaluate(report, gt)["rule_hits"], hits)

    def test_step_and_relation_counts_and_engine_agreement(self):
        relation = {"src": "/p", "syscall": "write", "dst": "/f"}
        reverse = {"src": "/f", "syscall": "write", "dst": "/p"}
        rule = {"rule_id": "r", "action": ["write"], "effect": "success",
                "source": {"match": "exact", "value": "/p"}, "target": {},
                "edge": {"bytes": {"op": ">=", "value": 8}}}
        gt = {"scenario": "sample", "attack_path": [
            {"phase": "first", "edges": [{**relation, "effect": "success"}], "rules": [rule]},
            {"phase": "second", "edges": [{**relation, "effect": "failure"}]},
        ]}
        edges = [{**relation, "effect": "failure", "bytes": 1},
                 {**relation, "effect": "success", "bytes": 8},
                 {**relation, "bytes": 2}, {**reverse, "bytes": 8}]
        with tempfile.TemporaryDirectory() as folder:
            gt_path = Path(folder) / "gt.json"
            gt_path.write_text(json.dumps(gt), encoding="utf-8")
            report_path = Path(folder) / "sample.json.gz"
            with patch.object(rm.VertexKinds, "for_gt", return_value=None):
                for rows in (edges, list(reversed(edges)), merge_report_edges(edges)):
                    with gzip.open(report_path, "wt", encoding="utf-8") as handle:
                        json.dump({"edges": rows}, handle)
                    metrics = reports.evaluate(report_path, gt_path)
                    self.assertEqual(metrics["scoring_protocol"], "triplet-v1")
                    self.assertEqual((metrics["steps_hit"], metrics["steps_total"]), (3, 3))
                    self.assertEqual((metrics["correct_edges"], metrics["reported_triples"]), (1, 2))
                    self.assertEqual(metrics["extra_list"], [reverse])
            _, required = engine.load_gt(gt_path)
            instances = [{**row, "start": index, "end": index} for index, row in enumerate(edges)]
            triples, _ = engine.to_triples(instances)
            result = rm.evaluate_report(required, [("first", rule)], triples)
            self.assertEqual((result["steps_hit"], result["correct_edges"], result["reported_triples"]), (3, 1, 2))
            triples, _ = engine.to_triples(instances, window=0.1, poi={"start_time": 1, "end_time": 1})
            result = rm.evaluate_report(required, [("first", rule)], triples)
            self.assertEqual((result["steps_hit"], result["reported_triples"]), (3, 1))

    def test_unknown_numeric_attribute_and_empty_result(self):
        rule = {"rule_id": "r", "effect": "failure", "action": ["write"], "source": {}, "target": {},
                "edge": {"bytes": {"op": ">", "value": 2}}}
        result = rm.evaluate_report([], [("one", rule)], [("a", "write", "b", {})])
        self.assertEqual(result["rule_hits"], [])
        self.assertEqual(result["edge_attrs_skipped"], ["r"])
        empty = rm.evaluate_report([], [], [])
        self.assertEqual((empty["reported_triples"], empty["precision_edges"], empty["recall_steps"]), (0, 0, 0))

    def test_merged_report_without_companion_preserves_bytes_rels_and_numeric_rules(self) -> None:
        first_attrs = [{"bytes": 4}]
        e1 = {"src": "/p", "syscall": "write", "dst": "/f", "instances": 1, "event_ids": [1],
              "bytes": 4, "rels": ["p2f"], "record_attributes": first_attrs}
        e2 = {"src": "/p", "syscall": "write", "dst": "/f", "instances": 1, "event_ids": [2],
              "bytes": 12, "rels": ["f2p"]}
        merged = merge_report_edges([e1, e2])
        self.assertEqual(len(first_attrs), 1)
        self.assertEqual(merged[0]["bytes"], 16)
        self.assertEqual(merged[0]["rels"], ["p2f", "f2p"])
        rule = {"rule_id": "r", "action": ["write"], "source": {}, "target": {},
                "edge": {"bytes": {"op": ">=", "value": 10}}}
        with tempfile.TemporaryDirectory() as folder, patch.object(rm.VertexKinds, "for_gt", return_value=None):
            report = Path(folder) / "report.json"
            gt = Path(folder) / "gt.json"
            report.write_text(json.dumps({"edges": merged}), encoding="utf-8")
            gt.write_text(json.dumps({"attack_path": [{"rules": [rule]}]}), encoding="utf-8")
            self.assertEqual(reports.evaluate(report, gt)["rule_hits"], ["r"])
