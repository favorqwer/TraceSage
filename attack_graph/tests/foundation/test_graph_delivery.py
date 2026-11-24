"""确认、初筛和待复核边都通过正式报告入口交付。"""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from core.axioms import is_passive_kernel_runtime_edge
from core.context import PipelineContext
from core.stages import s6_pruning, s7_reporting, temporal_pruning
from domain.edge import edge_key
from domain.pool import CandidatePool


class TestGraphDelivery(unittest.TestCase):
    def test_temporal_pruning_records_process_protection_evidence(self):
        def event(eid, rel, source, target, action, timestamp, result=None, src_kind=None):
            return dict(id=str(eid), eid=eid, rel=rel, src=source, dst=target, action=action,
                        start=timestamp, finish=timestamp, result=result, src_kind=src_kind,
                        src_host="host", dst_host="host")

        events = [
            event(1, "ProcessToProcess", "parent", "worker", "exec", 1, 0),
            event(2, "FileToProcess", "pipe", "worker", "read", 2, 12, "pipe"),
            event(3, "FileToProcess", "file", "worker", "read", 2, 12, "file"),
            event(4, "NetworkToProcess", "network", "parent", "recv", 1, 2),
            event(5, "ProcessToProcess", "worker", "parent", "exit", 3),
            event(6, "ProcessToNetwork", "parent", "network", "send", 4, 2),
            event(7, "ProcessToFile", "other", "alert-file", "write", 5, 2),
            event(8, "FileToProcess", "pipe", "other-worker", "read", 2, 12, "pipe"),
        ]
        confirmed = [dict(event_ids=[i], rels=[rel]) for i, rel in
                     [(1, "p2p"), (4, "n2p"), (6, "p2n"), (7, "p2f")]]
        pending = [dict(event_ids=[i], rels=[rel], origin="kept") for i, rel in
                   [(2, "f2p"), (3, "f2p"), (5, "p2p"), (8, "f2p")]]
        deps = SimpleNamespace(record=SimpleNamespace(
            poi_rows=[dict(event_id=7, relationship_id="7")],
            database="unit-v2", scenario="unit", run_id="unit",
        ))
        # 用另一个已经确认的后续输出支持读取，待查的退出事件本身不参与证明。
        events.append(event(9, "ProcessToFile", "worker", "out", "write", 3, 2))
        confirmed.append(dict(event_ids=[9], rels=["p2f"]))
        with patch.object(temporal_pruning, "ReadOnlyGraph") as graph, redirect_stdout(io.StringIO()):
            graph.return_value.run.return_value = events
            kept, removed, stats = temporal_pruning.run(deps, confirmed, pending)
        self.assertEqual([e["event_ids"] for e in kept], [[2], [5]])
        self.assertEqual([e["event_ids"] for e in removed], [[3], [8]])
        self.assertEqual(kept[0]["process_guard_evidence"][2][1:], [1, 9])
        self.assertEqual(kept[1]["process_guard_evidence"][5][1:], [1, 4, 6])
        self.assertEqual(stats["protected_edges"], 2)

    def test_temporal_pruning_uses_alert_and_keeps_unresolved_events(self):
        row = dict(src_host="host", dst_host="host", rel="FileToProcess", dst="process", finish=5)
        events = [
            dict(row, id="alert", eid=4, rel="ProcessToNetwork", src="process",
                 dst="network", start=10, finish=12),
            dict(row, id="reachable", eid=1, src="file1", start=4),
            dict(row, id="too-late", eid=2, src="file2", start=13, finish=14),
            dict(row, id="uncertain", eid=3, src="file3", dst="other", start=None),
        ]
        pending = [dict(event_ids=[i], rels=["f2p"], origin="kept") for i in (1, 2, 3, 5)]
        deps = SimpleNamespace(record=SimpleNamespace(
            poi_rows=[dict(event_id=4, relationship_id="alert")],
            database="unit-v2", scenario="unit", run_id="unit",
        ))
        with patch.object(temporal_pruning, "ReadOnlyGraph") as graph, redirect_stdout(io.StringIO()):
            graph.return_value.run.return_value = events
            kept, removed, stats = temporal_pruning.run(deps, [], pending)
        self.assertEqual([e["event_ids"] for e in kept], [[1], [3], [5]])
        self.assertEqual([e["event_ids"] for e in removed], [[2]])
        self.assertEqual(removed[0]["origin"], "excluded")
        self.assertEqual(stats["kept_incomplete_edges"], 1)
        graph.return_value.close.assert_called_once()

    def test_scoring_excludes_explicitly_rejected_but_keeps_remaining_and_unclassified(self):
        alert = {"src": "/bin/tool", "syscall": "write", "dst": "/tmp/report",
                 "rels": ["p2f"], "origin": "confirmed", "class": "anchor", "event_ids": [3]}
        predecessor = {"src": "/tmp/cache", "syscall": "read", "dst": "/bin/tool",
                       "rels": ["f2p"], "event_ids": [2], "effects": ["success"]}
        rejected = {"src": "/usr/lib/libc.so.6", "syscall": "read", "dst": "/bin/tool",
                    "rels": ["f2p"], "event_ids": [4]}
        upstream = {"src": "/bin/helper", "syscall": "write", "dst": "/tmp/cache",
                    "rels": ["p2f"], "event_ids": [1]}
        alert_key = edge_key(alert)
        with tempfile.TemporaryDirectory() as folder:
            report_path = Path(folder) / "report.json"
            ctx = PipelineContext(scenario="unit", fold_lib_path="", out_path=str(report_path))
            ctx.anchor_triples = [alert_key]
            ctx.anchor_keys = {alert_key}
            pool = CandidatePool([alert, predecessor, rejected, upstream])
            confirmed, debris, pending, excluded = s6_pruning.run(
                ctx, {alert_key: alert}, pool, [], [],
                [dict(predecessor, verdict="skipped", reason="待复核")],
                [dict(rejected, origin="excluded", verdict="none", reason="模型判无关")],
            )

            def score(path, _gt, *, scenario):
                report = json.loads(Path(path).read_text(encoding="utf-8"))
                self.assertEqual(scenario, "unit")
                self.assertEqual([edge["event_ids"] for edge in report["edges"]], [[3], [2], [1]])
                self.assertEqual([edge["origin"] for edge in report["edges"]], ["confirmed", "kept", "kept"])
                self.assertEqual(report["edges"][1]["effects"], ["success"])
                self.assertEqual([edge["event_ids"] for edge in report["excluded"]], [[4]])
                self.assertEqual(report["stats"]["pruned_noise_count"], 1)
                return dict.fromkeys(("recall", "precision", "steps_hit", "steps_total", "reported_triples",
                                      "must_hits", "gt_edges", "rule_hits", "rules_total",
                                      "rule_misses", "correct_edges"), 0)

            with (patch.object(s7_reporting.scorer, "evaluate", side_effect=score) as scorer,
                  redirect_stdout(io.StringIO())):
                result = s7_reporting.run(ctx, confirmed, pending, excluded, [], [], [], debris, {})
            scorer.assert_called_once()
        self.assertEqual(result["retained_edges"], 3)
        self.assertEqual(result["confirmed_edges"], 1)

    def test_runtime_passive_filter_handles_so_and_pyc_without_blocking_sock(self):
        self.assertTrue(is_passive_kernel_runtime_edge({
            "src": "/snap/firefox/8803/usr/lib/libxul.so", "syscall": "read", "dst": "/usr/bin/firefox",
        }))
        self.assertTrue(is_passive_kernel_runtime_edge({
            "src": "/usr/lib/python3/__pycache__/os.cpython-310.pyc", "syscall": "read", "dst": "/usr/bin/python3",
        }))
        self.assertFalse(is_passive_kernel_runtime_edge({
            "src": "/run/php/php8.1-fpm.sock", "syscall": "read", "dst": "/usr/sbin/php-fpm8.1",
        }))
        self.assertFalse(is_passive_kernel_runtime_edge(
            {"src": "/tmp/evil.so", "syscall": "read", "dst": "/usr/bin/app"},
            written_paths={"/tmp/evil.so"},
        ))

    def test_run_bidirectional_prunes_isolated_components_and_blocks_hub_traversal(self):
        def event(eid, rel, source, target, action, timestamp):
            return dict(id=str(eid), eid=eid, rel=rel, src=source, dst=target, action=action,
                        start=timestamp, finish=timestamp, result=0, src_kind=None,
                        src_host="host", dst_host="host")

        events = [
            event(1, "ProcessToFile", "anchor_proc", "payload_file", "write", 10),
            event(2, "ProcessToFile", "fwupd_proc", "dev_null", "write", 2),
            event(3, "FileToProcess", "dev_null", "anchor_proc", "read", 5),
            event(4, "FileToProcess", "udev_file", "fwupd_proc", "read", 1),
            event(5, "ProcessToProcess", "child_cat", "postinst_proc", "exit", 12),
            event(6, "ProcessToFile", "postinst_proc", "svc_unit", "write", 11),
            event(7, "ProcessToFile", "child_cat", "sync_bin", "write", 12),
        ]
        confirmed_map = {}
        for edge in (
            {"src": "/bin/sh", "syscall": "write", "dst": "/tmp/payload", "rels": ["p2f"], "origin": "confirmed", "class": "anchor", "event_ids": [1]},
            {"src": "/usr/libexec/fwupd", "syscall": "write", "dst": "/dev/null", "rels": ["p2f"], "origin": "confirmed", "event_ids": [2]},
            {"src": "/run/udev/data/b7:5", "syscall": "read", "dst": "/usr/libexec/fwupd", "rels": ["f2p"], "origin": "confirmed", "event_ids": [4]},
            {"src": "/var/lib/dpkg/info/pkg.postinst", "syscall": "write", "dst": "/etc/systemd/system/x.service", "rels": ["p2f"], "origin": "confirmed", "event_ids": [6]},
        ):
            confirmed_map[edge_key(edge)] = edge
        pending = [
            {"src": "/dev/null", "syscall": "read", "dst": "/bin/sh", "rels": ["f2p"], "origin": "kept", "event_ids": [3]},
            {"src": "/usr/bin/cat", "syscall": "write", "dst": "/usr/local/bin/x-agent", "rels": ["p2f"], "origin": "kept", "event_ids": [7]},
            {"src": "/usr/bin/cat", "syscall": "exit", "dst": "/var/lib/dpkg/info/pkg.postinst", "rels": ["p2p"], "origin": "kept", "event_ids": [5]},
        ]
        deps = SimpleNamespace(record=SimpleNamespace(
            database="unit", scenario="unit", run_id="r1",
            poi_rows=[{"event_id": 1, "relationship_id": "1"}],
        ))
        graph = SimpleNamespace(close=lambda: None)
        with (patch.object(temporal_pruning, "ReadOnlyGraph", return_value=graph),
              patch.object(temporal_pruning, "_fetch_events", return_value=events),
              redirect_stdout(io.StringIO())):
            kept_conf, kept_unex, removed, _ = temporal_pruning.run_bidirectional(deps, confirmed_map, pending)

        kept_eids = {e["event_ids"][0] for e in kept_conf.values()} | {e["event_ids"][0] for e in kept_unex}
        self.assertIn(1, kept_eids)
        self.assertIn(6, kept_eids)
        self.assertIn(7, kept_eids)
        self.assertNotIn(4, kept_eids)
        removed_eids = {e["event_ids"][0] for e in removed}
        self.assertIn(4, removed_eids)

    def test_run_bidirectional_blocks_kept_dpkg_library_rename_and_bg_pkg_daemons(self):
        def event(eid, rel, source, target, action, timestamp):
            return dict(id=str(eid), eid=eid, rel=rel, src=source, dst=target, action=action,
                        start=timestamp, finish=timestamp, result=0, src_kind=None,
                        src_host="host", dst_host="host")

        events = [
            event(1, "ProcessToFile", "java_proc", "payload", "write", 10),
            event(2, "FileToProcess", "rt_jar", "java_proc", "read", 5),
            event(3, "ProcessToFile", "dpkg_proc", "rt_jar", "rename", 2),
            event(4, "ProcessToProcess", "ua_proc", "dpkg_proc", "exec", 1),
            event(5, "ProcessToFile", "ua_proc", "apt_state", "write", 1),
        ]
        confirmed_map = {}
        for edge in (
            {"src": "/usr/bin/java", "syscall": "write", "dst": "/tmp/p", "rels": ["p2f"], "origin": "confirmed", "class": "anchor", "event_ids": [1]},
            {"src": "/usr/lib/jvm/rt.jar", "syscall": "read", "dst": "/usr/bin/java", "rels": ["f2p"], "origin": "confirmed", "event_ids": [2]},
            {"src": "/usr/bin/unattended-upgrade", "syscall": "write", "dst": "/var/lib/apt/extended_states.x", "rels": ["p2f"], "origin": "confirmed", "event_ids": [5]},
        ):
            confirmed_map[edge_key(edge)] = edge
        pending = [
            {"src": "/usr/bin/dpkg", "syscall": "rename", "dst": "/usr/lib/jvm/rt.jar", "rels": ["p2f"], "origin": "kept", "event_ids": [3]},
            {"src": "/usr/bin/unattended-upgrade", "syscall": "execve", "dst": "/usr/bin/dpkg", "rels": ["p2p"], "origin": "kept", "event_ids": [4]},
        ]
        deps = SimpleNamespace(record=SimpleNamespace(
            database="unit", scenario="unit", run_id="r2",
            poi_rows=[{"event_id": 1, "relationship_id": "1"}],
        ))
        graph = SimpleNamespace(close=lambda: None)
        with (patch.object(temporal_pruning, "ReadOnlyGraph", return_value=graph),
              patch.object(temporal_pruning, "_fetch_events", return_value=events),
              redirect_stdout(io.StringIO())):
            kept_conf, kept_unex, removed, _ = temporal_pruning.run_bidirectional(deps, confirmed_map, pending)

        kept_eids = {e["event_ids"][0] for e in kept_conf.values()} | {e["event_ids"][0] for e in kept_unex}
        self.assertIn(1, kept_eids)
        self.assertIn(2, kept_eids)
        self.assertNotIn(4, kept_eids)
        self.assertNotIn(5, kept_eids)
