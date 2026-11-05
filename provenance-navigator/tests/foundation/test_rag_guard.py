"""束级引用守卫测试（不需要数据库、不需要模型）。"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from navigator.guard import enforce_citations  # noqa: E402


def make_item(*, rule: bool = True, tech: bool = False, syscall: str = "read") -> dict:
    item = {
        "id": "B1",
        "syscall": syscall,
        "_rag_member_roles": [["P.out", syscall, "F.in"]],
        "_rule_evidence": {},
        "_tech_evidence": {},
    }
    if rule:
        item["_rule_evidence"]["R1"] = {
            "motif_id": "MOTIF_1",
            "entry_source": "exact",
            "hops": [{"index": 1, "syscall": syscall,
                      "src_role": "P.out", "dst_role": "F.in"}],
        }
    if tech:
        item["_tech_evidence"]["E1"] = {
            "attack_id": "T1071",
            "observable_ids": ["OBS-1"],
            "conditions": ["角色 N.both 匹配"],
            "confidence": 0.7,
        }
    return item


class CitationGuardTest(unittest.TestCase):
    def test_valid_rule_citation_keeps_all(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1, "reason": "引用 R1 第 1 跳"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")
        self.assertEqual(stats["checked"], 1)
        self.assertEqual(stats["downgraded"], 0)

    def test_reason_only_rule_citation_is_accepted(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "hop": 1, "reason": "按 R1 第 1 跳"}}
        enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")

    def test_missing_hop_downgrades(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "reason": "引用 R1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_hop"], 1)

    def test_hop_not_in_rule_downgrades(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 2, "reason": "引用 R1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_hop"], 1)

    def test_rule_not_in_evidence_downgrades(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "rule_id": "R9", "hop": 1, "reason": "引用 R9"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_rule"], 1)

    def test_syscall_mismatch_downgrades(self):
        item = make_item(syscall="write")
        item["_rule_evidence"]["R1"]["hops"][0]["syscall"] = "read"
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1, "reason": "引用 R1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_alignment"], 1)

    def test_partial_rule_single_role_match_passes(self):
        item = make_item(rule=False)
        item["_rule_evidence"]["R1"] = {
            "motif_id": "MOTIF_1", "entry_source": "partial",
            "hops": [{"index": 1, "syscall": "read",
                      "src_role": "P.out", "dst_role": "N.listen"}],
        }
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1, "reason": "引用 R1"}}
        enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")

    def test_exact_rule_single_role_match_downgrades(self):
        item = make_item(rule=False)
        item["_rule_evidence"]["R1"] = {
            "motif_id": "MOTIF_1", "entry_source": "exact",
            "hops": [{"index": 1, "syscall": "read",
                      "src_role": "P.out", "dst_role": "N.listen"}],
        }
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1, "reason": "引用 R1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_alignment"], 1)

    def test_no_evidence_no_citation_is_not_checked(self):
        item = make_item(rule=False)
        verdicts = {"B1": {"verdict": "all", "reason": "按边的事实判断"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")
        self.assertEqual(stats["no_evidence"], 1)

    def test_no_evidence_rule_citation_downgrades(self):
        item = make_item(rule=False)
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 0, "reason": "引用 R1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["fabricated_citation"], 1)

    def test_no_evidence_tech_citation_downgrades(self):
        item = make_item(rule=False)
        verdicts = {"B1": {"verdict": "all", "tech_id": "E1", "reason": "引用 E1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["fabricated_citation"], 1)

    def test_valid_tech_citation_keeps_all(self):
        item = make_item(rule=False, tech=True)
        verdicts = {"B1": {"verdict": "all", "tech_id": "E1", "reason": "引用 E1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")
        self.assertEqual(stats["bad_technique"], 0)

    def test_tech_citation_not_in_evidence_downgrades(self):
        item = make_item(rule=False, tech=True)
        verdicts = {"B1": {"verdict": "all", "tech_id": "E2", "reason": "引用 E2"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_technique"], 1)

    def test_evidence_exists_but_no_citation_downgrades(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "all", "reason": "看起来是攻击"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["missing_citation"], 1)

    def test_tech_citation_without_tech_evidence_downgrades(self):
        item = make_item(rule=True, tech=False)
        verdicts = {"B1": {"verdict": "all", "tech_id": "E1", "reason": "引用 E1"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_technique"], 1)

    def test_both_rule_and_tech_valid_keeps_all(self):
        item = make_item(rule=True, tech=True)
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1,
                           "tech_id": "E1", "reason": "引用 R1 和 E1"}}
        enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "all")

    def test_one_invalid_among_two_downgrades(self):
        item = make_item(rule=True, tech=True)
        verdicts = {"B1": {"verdict": "all", "rule_id": "R1", "hop": 1,
                           "tech_id": "E9", "reason": "引用 R1 和 E9"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["bad_technique"], 1)

    def test_non_all_verdict_ignored(self):
        item = make_item()
        verdicts = {"B1": {"verdict": "mixed", "reason": "证据不足"}}
        stats = enforce_citations([item], verdicts)
        self.assertEqual(verdicts["B1"]["verdict"], "mixed")
        self.assertEqual(stats["checked"], 0)


if __name__ == "__main__":
    unittest.main()
