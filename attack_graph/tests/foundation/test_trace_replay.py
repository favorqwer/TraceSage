"""离线重放（.trace.jsonl）单元测试：零大模型调用等价恢复三段式结论与引用守卫。"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from closure.intake import Deps  # noqa: E402
from core.context import PipelineContext  # noqa: E402
from core.stages import s4_decision  # noqa: E402
from llm import judge as judging_mod  # noqa: E402
from llm.client import LlmBudget, LlmRequestLimit, _invoke_with_retry  # noqa: E402
from llm.guard import enforce_citations  # noqa: E402
from llm.replay import INPUT_PROTOCOL, TraceReplay, request_sha256  # noqa: E402
from test_judge_pass import ScriptedBundleModel, build_record  # noqa: E402


class TraceReplayTests(unittest.TestCase):
    def test_replay_restores_original_bundles_and_member_order(self) -> None:
        first = [("p", "write", "b"), ("p", "write", "a")]
        second = [("q", "write", "c")]
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "trace.jsonl"
            payload = [
                {**self.trace_identity(), "scenario": "unit",
                 "items": [{"id": identifier, "level": 0, "members": members}],
                 "result": {"ok": True, "verdicts": {}}}
                for identifier, members in (("B0010", second), ("B0002", first))
            ]
            path.write_text("\n".join(map(json.dumps, payload)) + "\n", encoding="utf-8")
            replay = TraceReplay.from_file(path, expected_scenario="unit",
                                           expected_model=self.trace_identity()["model"])
            self.assertEqual(replay.order_members(set(first + second)), first + second)
            self.assertEqual(replay.order_first_bundles({"later": second, "earlier": first}),
                             ["earlier", "later"])
            with self.assertRaisesRegex(RuntimeError, "候选集合"):
                replay.order_members(set(first))

    def test_request_limit_counts_transport_failures(self) -> None:
        model = Mock()
        model.invoke.side_effect = RuntimeError("transport failure")
        budget = LlmBudget(request_limit=1)
        with patch("llm.client.time.sleep"), self.assertRaises(LlmRequestLimit):
            _invoke_with_retry(model, [], max_retries=1, request_budget=budget)
        self.assertEqual(budget.request_attempts, 1)
        self.assertEqual(model.invoke.call_count, 1)

    def trace_identity(self):
        model = judging_mod.cfg.llm_model()
        return {"input_protocol": INPUT_PROTOCOL, "model": model, "request_sha256": request_sha256(
            model, judging_mod.BUNDLE_SYSTEM, "")}

    def test_s4_decision_replay_matches_live_without_llm_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = pathlib.Path(tmp)
            live_out = tmp_dir / "live.json"
            replay_out = tmp_dir / "replay.json"

            inv_live = build_record()
            model = ScriptedBundleModel()
            deps_live = Deps(scenario=inv_live.scenario, graph=None, record=inv_live, model=model, budget=LlmBudget(), log=lambda _s: None)
            ctx_live = PipelineContext(scenario=inv_live.scenario, fold_lib_path="", out_path=str(live_out))
            candidates = list(inv_live.edges.values())

            live_conf, live_excl, live_kept = s4_decision.run(ctx_live, candidates, None, deps_live, {})
            self.assertGreater(model.calls, 0)
            trace_file = live_out.with_suffix(".trace.jsonl")
            self.assertTrue(trace_file.is_file())

            inv_replay = build_record()
            deps_replay = Deps(scenario=inv_replay.scenario, graph=None, record=inv_replay, model=None, budget=LlmBudget(), log=lambda _s: None)
            ctx_replay = PipelineContext(
                scenario=inv_replay.scenario,
                fold_lib_path="",
                out_path=str(replay_out),
                replay_trace=str(trace_file),
            )
            rep_conf, rep_excl, rep_kept = s4_decision.run(ctx_replay, list(inv_replay.edges.values()), None, deps_replay, {})

            self.assertEqual(ctx_replay.budget.calls, 0)
            self.assertEqual(
                {(e["src"], e["syscall"], e["dst"]) for e in live_conf},
                {(e["src"], e["syscall"], e["dst"]) for e in rep_conf},
            )
            self.assertEqual(
                {(e["src"], e["syscall"], e["dst"]) for e in live_excl},
                {(e["src"], e["syscall"], e["dst"]) for e in rep_excl},
            )
            self.assertEqual(
                {(e["src"], e["syscall"], e["dst"]) for e in live_kept},
                {(e["src"], e["syscall"], e["dst"]) for e in rep_kept},
            )
            self.assertEqual(inv_live.origin, inv_replay.origin)

    def test_guarded_replay_preserves_citation_guard_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_file = pathlib.Path(tmp) / "guarded.trace.jsonl"
            items = [{
                "id": "B0001", "level": 0, "size": 1,
                "members": [["/usr/bin/curl", "write", "/tmp/a"]],
                "syscall": "write",
                "_rule_evidence": {"R1": {"motif_id": "M1", "entry_source": "partial",
                                          "hops": [{"index": 1, "syscall": "write", "src_role": "A", "dst_role": "B"}]}},
                "_rag_member_roles": [],
            }]
            raw_text = json.dumps({"verdicts": [{"id": "B0001", "verdict": "all", "reason": "no citation"}]})
            verdicts = {"B0001": {"id": "B0001", "verdict": "all", "reason": "no citation"}}
            guard_stats = enforce_citations(items, verdicts)
            self.assertEqual(guard_stats["downgraded"], 1)
            trace_file.write_text(
                json.dumps({
                    **self.trace_identity(),
                    "scenario": "unit",
                    "items": [{"id": "B0001", "level": 0, "size": 1, "members": items[0]["members"]}],
                    "result": {"ok": True, "verdicts": verdicts, "_raw_text": raw_text, "calls": 1},
                }) + "\n",
                encoding="utf-8",
            )

            replay = TraceReplay.from_file(trace_file, expected_scenario="unit",
                                           expected_model=self.trace_identity()["model"])
            new_item = dict(items[0], id="B9999")
            res = judging_mod.judge_bundles(replay, [new_item], "", budget=LlmBudget())
            self.assertTrue(res["ok"])
            self.assertTrue(res.get("_replayed"))
            self.assertEqual(res["verdicts"]["B9999"]["verdict"], "mixed")
            self.assertEqual(res["verdicts"]["B9999"]["_rag_guard"], "all without citation while evidence exists")

    def test_replay_rejects_mismatched_scenario_or_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_file = pathlib.Path(tmp) / "x.trace.jsonl"
            trace_file.write_text(
                json.dumps({
                    **self.trace_identity(),
                    "scenario": "s1",
                    "items": [{"id": "B0001", "level": 0, "size": 1, "members": [["a", "write", "b"]]}],
                    "result": {"ok": True, "verdicts": {"B0001": {"id": "B0001", "verdict": "all", "reason": "ok"}}},
                }) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                TraceReplay.from_file(trace_file, expected_scenario="s2",
                                      expected_model=self.trace_identity()["model"])
            replay = TraceReplay.from_file(trace_file, expected_scenario="s1",
                                           expected_model=self.trace_identity()["model"])
            with self.assertRaises(RuntimeError):
                replay.judge_batch([{"id": "B0002", "level": 0, "size": 1, "members": [("x", "read", "y")]}],
                                   self.trace_identity()["request_sha256"])
            with self.assertRaises(RuntimeError):
                judging_mod.judge_bundles(
                    replay, [{"id": "B0001", "level": 0, "members": [("a", "write", "b")]}],
                    "changed input", budget=LlmBudget())
            trace_file.write_text(json.dumps({"scenario": "s1"}) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "协议"):
                TraceReplay.from_file(trace_file, expected_scenario="s1",
                                      expected_model=self.trace_identity()["model"])

    def test_failed_batch_replays_once_without_retry_overcount(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = pathlib.Path(tmp)
            live_out = tmp_dir / "live.json"
            replay_out = tmp_dir / "replay.json"

            inv_live = build_record()
            failing_model = Mock()
            failing_model.invoke.side_effect = RuntimeError("upstream timeout")
            deps_live = Deps(
                scenario=inv_live.scenario, graph=None, record=inv_live,
                model=failing_model, budget=LlmBudget(), log=lambda _s: None,
            )
            ctx_live = PipelineContext(scenario=inv_live.scenario, fold_lib_path="", out_path=str(live_out))
            with patch("llm.client.time.sleep"), patch.object(judging_mod.cfg, "batch_attempts", return_value=2):
                s4_decision.run(ctx_live, list(inv_live.edges.values()), None, deps_live, {})

            trace_file = live_out.with_suffix(".trace.jsonl")
            inv_replay = build_record()
            deps_replay = Deps(
                scenario=inv_replay.scenario, graph=None, record=inv_replay,
                model=None, budget=LlmBudget(), log=lambda _s: None,
            )
            ctx_replay = PipelineContext(
                scenario=inv_replay.scenario,
                fold_lib_path="",
                out_path=str(replay_out),
                replay_trace=str(trace_file),
            )
            with patch.object(judging_mod.cfg, "batch_attempts", return_value=3):
                _conf, _excl, rep_kept = s4_decision.run(
                    ctx_replay, list(inv_replay.edges.values()), None, deps_replay, {},
                )
            self.assertEqual(deps_replay.model.replayed_batches, deps_replay.model.recorded_batches)
            self.assertEqual(len(rep_kept), len(inv_replay.edges))


if __name__ == "__main__":
    unittest.main()
