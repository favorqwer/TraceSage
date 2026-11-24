"""验证索引格式 v10、阶段 6.5 零查库内存复用与阶段 7 双层伴生导出。"""
from __future__ import annotations

from contextlib import redirect_stdout
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import settings as cfg  # noqa: E402
from closure.snapshot import TSGSource  # noqa: E402
from core.context import PipelineContext  # noqa: E402
from core.reporting import build_events_export, default_events_path  # noqa: E402
from core.stages import s7_reporting, temporal_pruning  # noqa: E402
from domain.edge import edge_key  # noqa: E402

if str(cfg.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(cfg.REPO_ROOT))
from tsg.format import TSGWriter  # noqa: E402


class EventExportV10Tests(unittest.TestCase):
    def test_tsg_preserves_action_result_null_flags_and_vertex_attrs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsg_path = Path(tmp) / "unit.tsg"
            w = TSGWriter(tsg_path, scenario="unit", database="unit-v2")
            w.add_vertex("Process", "h1|host|100|1000", {
                "content": "/bin/sh", "host_id": "h1", "container_id": "host",
                "pid": 100, "name": "sh", "exepath": "/bin/sh", "args": "/bin/sh -c run",
                "ppid": 1, "uid": 0, "euid": 0,
            })
            w.add_vertex("Process", "h1|host|200|2000", {
                "content": "/usr/bin/cat", "host_id": "h1", "container_id": "host",
                "pid": 200, "name": "cat", "exepath": "/usr/bin/cat", "args": "/usr/bin/cat /tmp/a",
                "ppid": 100, "uid": 1000, "euid": 1000,
                "container_privileged": False, "container_host_root_rw": True,
            })
            w.add_vertex("File", "/tmp/a", {"content": "/tmp/a", "host_id": "h1", "container_id": "host", "file_type": "pipe"})
            w.add_edge(rel="p2p", src_kind="Process", src_key="h1|host|100|1000",
                       dst_kind="Process", dst_key="h1|host|200|2000",
                       event_id=10, start_ns=2000, end_ns=2001, syscall="execve", action="exec", result=0)
            w.add_edge(rel="f2p", src_kind="File", src_key="/tmp/a",
                       dst_kind="Process", dst_key="h1|host|200|2000",
                       event_id=20, start_ns=None, end_ns=None, syscall="read", action="read", result=-11)
            w.add_edge(rel="p2f", src_kind="Process", src_key="h1|host|200|2000",
                       dst_kind="File", dst_key="/tmp/a",
                       event_id=30, start_ns=3000, end_ns=3005, syscall="write", action="write", result=None)
            w.finish()

            reader = TSGSource(tsg_path)
            try:
                evts = reader.expand_process([("h1|host|200|2000", -1, 10_000)])
                by_eid = {e.event_id: e for e in evts}
                self.assertEqual(set(by_eid), {10, 20, 30})
                self.assertEqual(by_eid[10].action, "exec")
                self.assertEqual(by_eid[10].result, 0)
                self.assertTrue(by_eid[10].has_start)
                self.assertEqual(by_eid[10].src_host, "h1")
                self.assertEqual(by_eid[10].dst_host, "h1")
                self.assertEqual(by_eid[20].action, "read")
                self.assertEqual(by_eid[20].result, -11)
                self.assertEqual(by_eid[20].effect, "failure")
                self.assertFalse(by_eid[20].has_start)
                self.assertFalse(by_eid[20].has_end)
                self.assertEqual(by_eid[20].src_kind, "pipe")
                self.assertEqual(by_eid[30].action, "write")
                self.assertIsNone(by_eid[30].result)
                self.assertEqual(by_eid[30].effect, "")
                self.assertEqual(by_eid[30].dst_kind, "pipe")

                p_attr = reader.vertex_attr("Process", "h1|host|200|2000")
                self.assertEqual(p_attr["uid"], 1000)
                self.assertEqual(p_attr["container_host_root_rw"], True)
                f_attr = reader.vertex_attr("File", "/tmp/a")
                self.assertEqual(f_attr["file_type"], "pipe")
            finally:
                reader.close()

    def test_temporal_pruning_reuses_stage1_raw_events_without_db_query(self) -> None:
        raw_events = [
            {
                "id": "ProcessToFile:1:write", "event_id": 1, "rel": "p2f", "rel_full": "ProcessToFile",
                "action": "write", "syscall": "write", "start_ns": 10, "end_ns": 10, "result": 16,
                "bytes": 16, "effect": "success",
                "src_kind": "Process", "src_key": "h1|host|10|1", "src_host": "h1", "src_file_type": None,
                "dst_kind": "File", "dst_key": "/tmp/target", "dst_host": "h1", "dst_file_type": "file",
            },
            {
                "id": "FileToProcess:2:read", "event_id": 2, "rel": "f2p", "rel_full": "FileToProcess",
                "action": "read", "syscall": "read", "start_ns": 5, "end_ns": 5, "result": 8,
                "bytes": 8, "effect": "success",
                "src_kind": "File", "src_key": "/tmp/in", "src_host": "h1", "src_file_type": "file",
                "dst_kind": "Process", "dst_key": "h1|host|10|1", "dst_host": "h1", "dst_file_type": None,
            },
            {
                "id": "FileToProcess:3:read", "event_id": 3, "rel": "f2p", "rel_full": "FileToProcess",
                "action": "read", "syscall": "read", "start_ns": 20, "end_ns": 20, "result": 8,
                "bytes": 8, "effect": "success",
                "src_kind": "File", "src_key": "/tmp/late", "src_host": "h1", "src_file_type": "file",
                "dst_kind": "Process", "dst_key": "h1|host|99|1", "dst_host": "h1", "dst_file_type": None,
            },
        ]
        confirmed = {
            edge_key({"src": "/bin/cat", "syscall": "write", "dst": "/tmp/target"}): {
                "src": "/bin/cat", "syscall": "write", "dst": "/tmp/target",
                "rels": ["p2f"], "origin": "confirmed", "class": "anchor", "event_ids": [1],
            }
        }
        pending = [
            {"src": "/tmp/in", "syscall": "read", "dst": "/bin/cat", "rels": ["f2p"], "origin": "kept", "event_ids": [2]},
            {"src": "/tmp/late", "syscall": "read", "dst": "/bin/other", "rels": ["f2p"], "origin": "kept", "event_ids": [3]},
        ]
        deps = SimpleNamespace(record=SimpleNamespace(
            database="unit-v2", scenario="unit", run_id="r1",
            poi_rows=[{"event_id": 1, "rel": "p2f", "action": "write", "relationship_id": "ignored"}],
            raw_events=raw_events,
        ))
        with patch.object(temporal_pruning, "ReadOnlyGraph", side_effect=AssertionError("不应触发查库")), \
             redirect_stdout(io.StringIO()):
            kept_conf, kept_unex, removed, _ = temporal_pruning.run_bidirectional(deps, confirmed, pending)

        self.assertEqual(len(kept_conf), 1)
        self.assertEqual([e["event_ids"] for e in kept_unex], [[2]])
        self.assertEqual([e["event_ids"] for e in removed], [[3]])

    def test_stage7_companion_events_export_strict_match_and_no_unretained_sibling_leak(self) -> None:
        raw_events = [
            {
                "id": "FileToProcess:50:rename", "event_id": 50, "rel": "f2p", "rel_full": "FileToProcess",
                "action": "rename", "syscall": "rename", "start_ns": 100, "end_ns": 100, "result": 0,
                "bytes": 0, "effect": "success",
                "src_kind": "File", "src_key": "/tmp/old", "src_host": "h1", "src_file_type": "file",
                "dst_kind": "Process", "dst_key": "h1|host|10|1", "dst_host": "h1", "dst_file_type": None,
            },
            {
                # 同 event_id=50 的另一侧边，但研究点一最终未保留它，导出时绝不能混入
                "id": "ProcessToFile:50:rename", "event_id": 50, "rel": "p2f", "rel_full": "ProcessToFile",
                "action": "rename", "syscall": "rename", "start_ns": 100, "end_ns": 100, "result": 0,
                "bytes": 0, "effect": "success",
                "src_kind": "Process", "src_key": "h1|host|10|1", "src_host": "h1", "src_file_type": None,
                "dst_kind": "File", "dst_key": "/tmp/new", "dst_host": "h1", "dst_file_type": "file",
            },
            {
                "id": "ProcessToFile:60:write", "event_id": 60, "rel": "p2f", "rel_full": "ProcessToFile",
                "action": "write", "syscall": "write", "start_ns": 200, "end_ns": 205, "result": 32,
                "bytes": 32, "effect": "success",
                "src_kind": "Process", "src_key": "h1|host|10|1", "src_host": "h1", "src_file_type": None,
                "dst_kind": "File", "dst_key": "/srv/out", "dst_host": "h1", "dst_file_type": "file",
            },
        ]
        vertex_attrs = {
            "Process:h1|host|10|1": {"kind": "Process", "key": "h1|host|10|1", "content": "/bin/mv", "host_id": "h1", "pid": 10},
            "File:/tmp/old": {"kind": "File", "key": "/tmp/old", "content": "/tmp/old", "host_id": "h1", "file_type": "file"},
            "File:/tmp/new": {"kind": "File", "key": "/tmp/new", "content": "/tmp/new", "host_id": "h1", "file_type": "file"},
            "File:/srv/out": {"kind": "File", "key": "/srv/out", "content": "/srv/out", "host_id": "h1", "file_type": "file"},
        }
        confirmed = [{
            "src": "/bin/mv", "syscall": "write", "dst": "/srv/out",
            "src_label": "Process", "dst_label": "File", "rels": ["p2f"],
            "src_identities": [["Process", "h1|host|10|1"]],
            "dst_identities": [["File", "/srv/out"]],
            "event_ids": [60], "origin": "confirmed", "class": "anchor", "verdict": "all",
        }]
        unexcluded = [{
            "src": "/tmp/old", "syscall": "rename", "dst": "/bin/mv",
            "src_label": "File", "dst_label": "Process", "rels": ["f2p"],
            "src_identities": [["File", "/tmp/old"]],
            "dst_identities": [["Process", "h1|host|10|1"]],
            "event_ids": [50], "origin": "kept", "class": "ambiguous", "verdict": "mixed",
        }]
        payload = build_events_export(
            "unit", "unit-v2",
            confirmed_edges=confirmed,
            unexcluded_edges=unexcluded,
            raw_events=raw_events,
            vertex_attrs=vertex_attrs,
            poi_rows=[{"event_id": 60, "rel": "p2f", "action": "write"}],
        )
        self.assertEqual([e["id"] for e in payload["events"]], ["FileToProcess:50:rename", "ProcessToFile:60:write"])
        self.assertEqual(payload["events"][0]["report_status"], "unexcluded")
        self.assertEqual(payload["events"][1]["report_status"], "confirmed")
        self.assertNotIn("File:/tmp/new", payload["entities"])
        self.assertEqual(payload["poi_events"], ["ProcessToFile:60:write"])

        # 缺失事件编号时必须阻断报错
        with self.assertRaises(RuntimeError):
            build_events_export(
                "unit", "unit-v2",
                confirmed_edges=[{**confirmed[0], "event_ids": [9999]}],
                unexcluded_edges=[],
                raw_events=raw_events,
                vertex_attrs=vertex_attrs,
                poi_rows=[{"event_id": 60, "rel": "p2f", "action": "write"}],
            )

        # s7_reporting.run 传入 deps 时自动同步写出伴生 *.events.json.gz
        with tempfile.TemporaryDirectory() as folder:
            report_path = Path(folder) / "demo.json"
            ctx = PipelineContext(scenario="unit", fold_lib_path="", out_path=str(report_path))
            deps = SimpleNamespace(record=SimpleNamespace(
                database="unit-v2",
                raw_events=raw_events,
                vertex_attrs=vertex_attrs,
                poi_rows=[{"event_id": 60, "rel": "p2f", "action": "write"}],
            ))
            confirmed_map = {edge_key(confirmed[0]): confirmed[0]}
            zero_eval = dict.fromkeys(
                ("recall", "precision", "steps_hit", "steps_total", "reported_triples",
                 "must_hits", "gt_edges", "rule_hits", "rules_total", "rule_misses", "correct_edges"),
                0,
            )
            with patch.object(s7_reporting.scorer, "evaluate", return_value=zero_eval), redirect_stdout(io.StringIO()):
                res = s7_reporting.run(ctx, confirmed_map, unexcluded, [], [], [], [], [], {}, deps=deps)
            ev_path = default_events_path(report_path)
            self.assertEqual(Path(res["events_file"]), ev_path)
            self.assertEqual(res["retained_events"], 2)
            with gzip.open(ev_path, "rt", encoding="utf-8") as fh:
                loaded = json.load(fh)
            self.assertEqual(len(loaded["events"]), 2)


if __name__ == "__main__":
    unittest.main()
