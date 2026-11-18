"""Rule-only snapshot contracts and fold isolation, without database or model access."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from rag.build_kg import build_all_folds, build_fold_kg
from rag.stats import RuleStats


class RuleSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.folds = self.root / "folds"
        self.folds.mkdir()
        self.input = self.folds / "test-case.json"
        self.input.write_text(json.dumps({
            "selected": ["M1"], "train_scenarios": ["training-case"],
            "role_cuts": {"example": [1, 3]},
            "motifs": [
                {"id": "M1", "hops": 1, "src_role": "F.r", "dst_role": "P.none",
                 "syscalls": ["read"], "support_scenarios_list": ["training-case"]},
                {"id": "M2", "hops": 1, "src_role": "P.out", "dst_role": "F.w",
                 "syscalls": ["write"]},
            ]}), encoding="utf-8")

    def statistics(self, scenario, path, *, motif_ids):
        self.assertEqual(scenario, "test-case")
        return {mid: RuleStats(mid, 5, 3, 2, 0, 0.6, 8) for mid in motif_ids}

    def test_default_snapshot_preserves_selected_rule_and_training_fold(self):
        with patch("rag.build_kg.load_fold_rule_stats", side_effect=self.statistics):
            kg = build_fold_kg("test-case", self.input)
        self.assertEqual(set(kg), {"version", "fold_of", "train_scenarios", "role_cuts", "motifs", "hops", "counts"})
        self.assertEqual(kg["train_scenarios"], ["training-case"])
        self.assertNotIn("test-case", kg["train_scenarios"])
        self.assertEqual(kg["counts"], {"motifs": 1, "admitted": 1, "hops": 1})
        rule = kg["motifs"][0]
        self.assertEqual(set(rule), {"motif_id", "name", "hops", "role_chain", "syscall_chain", "support_scenarios", "admitted", "source", "version", "stats"})
        self.assertEqual(rule["role_chain"], ["F.r", "P.none"])
        self.assertEqual(rule["stats"]["precision"], 0.6)
        self.assertEqual(kg["hops"][0]["syscall"], "read")

    def test_candidate_snapshot_marks_unselected_rules_without_admitting_them(self):
        with patch("rag.build_kg.load_fold_rule_stats", side_effect=self.statistics):
            kg = build_fold_kg("test-case", self.input, include_candidates=True)
        self.assertEqual(kg["counts"], {"motifs": 2, "admitted": 1, "hops": 2})
        self.assertFalse(next(m for m in kg["motifs"] if m["motif_id"] == "M2")["admitted"])

    def test_manifest_and_written_fold_have_consistent_rule_counts(self):
        with patch("rag.build_kg.load_fold_rule_stats", side_effect=self.statistics):
            manifest = build_all_folds(self.folds, self.root / "out")
        written = json.loads((self.root / "out/folds/test-case.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["counts"], written["counts"])
        self.assertEqual(manifest["folds"]["test-case"]["train_scenarios"], ["training-case"])


if __name__ == "__main__":
    unittest.main()
