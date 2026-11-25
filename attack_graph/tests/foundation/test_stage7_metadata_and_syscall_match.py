"""验证研究点一 5 处通用元数据透传与同 event_id 跨 syscall 精确匹配。"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ATTACK_GRAPH_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = ATTACK_GRAPH_DIR.parent
for p in (str(REPO_ROOT), str(ATTACK_GRAPH_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from core import render as rag_render  # noqa: E402
from core.context import PipelineContext  # noqa: E402
from core.reporting import build_events_export, save_events_export  # noqa: E402
from core.stages import s6_pruning  # noqa: E402
from domain.pool import CandidatePool  # noqa: E402
from attack_path.loader import load_scenario_events  # noqa: E402


class Stage7MetadataAndSyscallMatchTest(unittest.TestCase):
    def test_build_events_export_separates_same_event_id_clone_and_execve_and_exports_metadata(self) -> None:
        raw_events = [
            {
                "id": "ProcessToProcess:1924312:clone",
                "event_id": 1924312,
                "rel": "p2p",
                "rel_full": "ProcessToProcess",
                "action": "clone",
                "syscall": "clone",
                "start_ns": 1000,
                "end_ns": 1005,
                "result": 45949,
                "bytes": 0,
                "effect": "success",
                "src_kind": "Process",
                "src_key": "h1|host|45948|100",
                "src_host": "h1",
                "src_file_type": None,
                "dst_kind": "Process",
                "dst_key": "h1|host|45949|0",
                "dst_host": "h1",
                "dst_file_type": None,
                "dist": 2,
                "via_kind": "Process",
                "via_key": "h1|host|45949|0",
                "support": 1,
            },
            {
                "id": "ProcessToProcess:1924312:exec",
                "event_id": 1924312,
                "rel": "p2p",
                "rel_full": "ProcessToProcess",
                "action": "exec",
                "syscall": "execve",
                "start_ns": 1000,
                "end_ns": 1005,
                "result": 0,
                "bytes": 0,
                "effect": "success",
                "src_kind": "Process",
                "src_key": "h1|host|45949|0",
                "src_host": "h1",
                "src_file_type": None,
                "dst_kind": "Process",
                "dst_key": "h1|host|45949|1000",
                "dst_host": "h1",
                "dst_file_type": None,
                "dist": 1,
                "via_kind": "Process",
                "via_key": "h1|host|45949|1000",
                "support": 1,
            },
            {
                "id": "ProcessToFile:1924400:unlink",
                "event_id": 1924400,
                "rel": "p2f",
                "rel_full": "ProcessToFile",
                "action": "unlink",
                "syscall": "unlink",
                "start_ns": 2000,
                "end_ns": 2005,
                "result": 0,
                "bytes": 0,
                "effect": "success",
                "src_kind": "Process",
                "src_key": "h1|host|45949|1000",
                "src_host": "h1",
                "src_file_type": None,
                "dst_kind": "File",
                "dst_key": "/srv/data.log",
                "dst_host": "h1",
                "dst_file_type": "file",
                "dist": 0,
                "via_kind": "",
                "via_key": "",
                "support": 1,
            },
        ]
        vertex_attrs = {
            "Process:h1|host|45948|100": {"kind": "Process", "key": "h1|host|45948|100", "content": "/usr/bin/postgres"},
            "Process:h1|host|45949|0": {"kind": "Process", "key": "h1|host|45949|0", "content": "/usr/bin/postgres"},
            "Process:h1|host|45949|1000": {"kind": "Process", "key": "h1|host|45949|1000", "content": "/bin/sh"},
            "File:/srv/data.log": {"kind": "File", "key": "/srv/data.log", "content": "/srv/data.log"},
        }
        rag_rules = [
            {
                "motif_id": "M001",
                "entry_source": "exact",
                "lr": 4.25,
                "weighted_lr": 3.8,
                "precision": 0.92,
                "attack_hits": 12,
                "background_hits": 1,
                "support_scenarios": 4,
                "exact_members": 1,
                "partial_members": 0,
            }
        ]
        confirmed_edges = [
            {
                "src": "/usr/bin/postgres",
                "syscall": "clone",
                "dst": "/usr/bin/postgres",
                "rels": ["p2p"],
                "event_ids": [1924312],
                "verdict": "all",
                "llm_verdict": "all",
                "decision_source": "s5_causal_heal",
                "verdict_reason": "db spawn",
                "llm_bundle_id": "L1:B3",
                "llm_bundle_level": 1,
                "llm_bundle_size": 7,
                "rag_rules": rag_rules,
                "origin": "confirmed",
                "class": "story",
                "reason": "healed",
            },
            {
                "src": "/usr/bin/postgres",
                "syscall": "execve",
                "dst": "/bin/sh",
                "rels": ["p2p"],
                "event_ids": [1924312],
                "verdict": "all",
                "llm_verdict": "all",
                "decision_source": "llm_all",
                "verdict_reason": "db shell exec",
                "llm_bundle_id": "L0:B2",
                "llm_bundle_level": 0,
                "llm_bundle_size": 1,
                "rag_rules": rag_rules,
                "origin": "confirmed",
                "class": "story",
                "reason": "llm confirmed",
            },
            {
                "src": "/bin/sh",
                "syscall": "unlink",
                "dst": "/srv/data.log",
                "rels": ["p2f"],
                "event_ids": [1924400],
                "verdict": "",
                "decision_source": "anchor",
                "origin": "confirmed",
                "class": "anchor",
                "reason": "poi",
            },
        ]
        poi_rows = [{"rel": "p2f", "event_id": 1924400, "action": "unlink"}]
        payload = build_events_export(
            "test_sc",
            "attack-test-v2",
            confirmed_edges=confirmed_edges,
            unexcluded_edges=[],
            raw_events=raw_events,
            vertex_attrs=vertex_attrs,
            poi_rows=poi_rows,
        )
        by_id = {ev["id"]: ev for ev in payload["events"]}
        self.assertEqual(len(by_id), 3)
        # clone 与 execve 虽然 event_id 均为 1924312，但不得交叉挂载 membership
        clone_ev = by_id["ProcessToProcess:1924312:clone"]
        exec_ev = by_id["ProcessToProcess:1924312:exec"]
        self.assertEqual(len(clone_ev["memberships"]), 1)
        self.assertEqual(clone_ev["llm_bundle_id"], "L1:B3")
        self.assertEqual(clone_ev["decision_source"], "s5_causal_heal")
        self.assertEqual(len(exec_ev["memberships"]), 1)
        self.assertEqual(exec_ev["llm_bundle_id"], "L0:B2")
        self.assertEqual(exec_ev["decision_source"], "llm_all")
        self.assertEqual(exec_ev["llm_bundle_level"], 0)
        self.assertEqual(exec_ev["llm_bundle_size"], 1)
        self.assertEqual(exec_ev["rag_rules"][0]["motif_id"], "M001")
        self.assertAlmostEqual(exec_ev["rag_rules"][0]["weighted_lr"], 3.8)

        # 验证 attack_path/loader.py 完整加载新字段
        with tempfile.TemporaryDirectory() as tmp:
            p = save_events_export(payload, Path(tmp) / "test.events.json.gz", overwrite=True)
            ds = load_scenario_events(p)
            loaded = {e.id: e for e in ds.events}
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].llm_verdict, "all")
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].decision_source, "llm_all")
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].llm_bundle_id, "L0:B2")
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].llm_bundle_level, 0)
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].llm_bundle_size, 1)
            self.assertEqual(loaded["ProcessToProcess:1924312:exec"].rag_rules[0]["lr"], 4.25)

    def test_render_rule_lines_captures_structured_rag_rules(self) -> None:
        item = {"id": "B1", "size": 2, "syscall": "execve"}
        ranked = [
            {
                "g": {
                    "motif": {
                        "motif_id": "M_TEST",
                        "precision": 0.875,
                        "attack_hits": 7,
                        "background_hits": 1,
                        "support_scenarios": ["s1", "s2", "s3"],
                    },
                    "hops": [
                        {"index": 1, "src_role": "WEB", "syscall": "execve", "dst_role": "SHELL"}
                    ],
                },
                "exact": 2,
                "partial": 0,
                "lr": 3.1415926,
                "weighted_lr": 2.7182818,
            }
        ]
        lines = rag_render._rule_lines(item, ranked, total=1)
        self.assertTrue(lines)
        self.assertIn("_rag_rules", item)
        self.assertEqual(len(item["_rag_rules"]), 1)
        rec = item["_rag_rules"][0]
        self.assertEqual(rec["motif_id"], "M_TEST")
        self.assertEqual(rec["entry_source"], "exact")
        self.assertAlmostEqual(rec["lr"], 3.141593)
        self.assertAlmostEqual(rec["weighted_lr"], 2.718282)
        self.assertEqual(rec["precision"], 0.875)
        self.assertEqual(rec["support_scenarios"], 3)

    def test_s6_pruning_preserves_distinct_prune_stages(self) -> None:
        anchor = {"src": "/bin/sh", "syscall": "unlink", "dst": "/srv/x", "class": "anchor", "decision_source": "anchor"}
        ctx = PipelineContext(scenario="s_test", fold_lib_path="", out_path="")
        ctx.anchor_triples = [("/bin/sh", "unlink", "/srv/x")]
        e_llm_none = {"src": "/usr/bin/a", "syscall": "write", "dst": "/tmp/a", "verdict": "none", "prune_stage": "s4_llm_none"}
        e_prefilter = {"src": "/usr/lib/libc.so", "syscall": "read", "dst": "/usr/bin/a", "prune_stage": "s2_prefilter"}
        e_demoted = {"src": "/usr/bin/a", "syscall": "stat", "dst": "/tmp/b", "prune_stage": "s5_demoted"}
        e_unconf_probe = {"src": "/usr/bin/a", "syscall": "ioctl", "dst": "/dev/tty", "verdict": "unknown"}
        e_kept = {"src": "/usr/bin/a", "syscall": "write", "dst": "/tmp/keep", "verdict": "unknown"}
        pool = CandidatePool([anchor, e_llm_none, e_prefilter, e_demoted, e_unconf_probe, e_kept])

        _, _, final_unex, final_excl = s6_pruning.run(
            ctx,
            purified_confirmed={("/bin/sh", "unlink", "/srv/x"): anchor},
            pool=pool,
            unpromoted_ambiguous=[e_demoted],
            pruned_background=[e_prefilter],
            remaining_ambiguous=[e_unconf_probe, e_kept],
            excluded_edges=[e_llm_none],
        )
        stage_by_key = {(e["src"], e["syscall"], e["dst"]): e.get("prune_stage") for e in final_excl}
        self.assertEqual(stage_by_key[("/usr/bin/a", "write", "/tmp/a")], "s4_llm_none")
        self.assertEqual(stage_by_key[("/usr/lib/libc.so", "read", "/usr/bin/a")], "s2_prefilter")
        self.assertEqual(stage_by_key[("/usr/bin/a", "stat", "/tmp/b")], "s5_demoted")
        self.assertEqual(stage_by_key[("/usr/bin/a", "ioctl", "/dev/tty")], "s6_unconfirmed_filter")
        self.assertEqual(len(final_unex), 1)
        self.assertEqual(final_unex[0]["decision_source"], "unexcluded_kept")


if __name__ == "__main__":
    unittest.main()
