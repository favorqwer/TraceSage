"""四道结构闸门（不需要数据库、不需要模型）。

闸门只限制「整束无关」的删边权限：空拆不重判、拆分产生的单条边子束不判、同类里已有相关时
同类判无关要降级、判无关必须过结构凭证。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import llm.judge as guards  # noqa: E402


def item(bid, size, *, dirs=("/etc",), programs=("/bin/bash",), parent=True, vacuous=False):
    entry = {"id": bid, "size": size, "all_dirs": list(dirs), "programs": list(programs),
             "members": [(f"m{bid}{i}", "read", "/etc/x") for i in range(size)]}
    if parent:
        entry["parent"] = {"bid": "B0001", "size": size + 3, "bytes": 1, "objects_n": 1,
                           "t0": 0, "t1": 1, "programs": ["/bin/bash"], "rels": ["f2p"],
                           "syscall": "read", "verdict": "mixed", "reason": "r"}
    if vacuous:
        entry["vacuous"] = True
    return entry


class GuardTest(unittest.TestCase):
    def test_vacuous_and_fanout(self) -> None:
        items = [item("B0002", 1, vacuous=True), item("B0003", 1), item("B0004", 5)]
        vacuous = guards.vacuous_ids(items)
        self.assertEqual(vacuous, {"B0002"})
        ask, skipped, edges = guards.fanout_split(items, vacuous, 1)
        self.assertEqual(skipped, {"B0003"}, "只跳拆分产生的单条边子束")
        self.assertEqual(edges, 1)
        self.assertEqual([it["id"] for it in ask], ["B0004"])

    def test_hot_guard_downgrades_same_class_only(self) -> None:
        items = [item("B0002", 3, dirs=("/etc",)), item("B0003", 2, dirs=("/tmp",)),
                 item("B0004", 2, dirs=("/etc",))]
        verdicts = {"B0002": {"verdict": "all"}, "B0003": {"verdict": "none"},
                    "B0004": {"verdict": "none"}}
        downgraded = guards.hot_guard(items, verdicts)
        self.assertEqual(downgraded, 1)
        self.assertEqual(verdicts["B0003"]["verdict"], "none", "不同类不受影响")
        self.assertEqual(verdicts["B0004"]["verdict"], "mixed")
        self.assertIn("hot:", verdicts["B0004"]["_guard"])

    def test_warrant_guard_requires_credential(self) -> None:
        items = [item("B0002", 3), item("B0003", 3)]
        verdicts = {"B0002": {"verdict": "none"}, "B0003": {"verdict": "none"}}
        facts = {"B0002": {"only_derivation": True}, "B0003": {"only_reader": True}}
        downgraded, recorded = guards.warrant_guard(items, verdicts, lambda it: facts[it["id"]],
                                                    {"deriv", "proc"})
        self.assertEqual(downgraded, 1)
        self.assertEqual(verdicts["B0002"]["verdict"], "mixed",
                         "命中已知误杀模式（全是派生边）→ 降级为要拆")
        self.assertEqual(verdicts["B0003"]["verdict"], "none", "没命中凭证 → 保持删边")
        self.assertEqual(set(recorded), {"B0002", "B0003"}, "逐束的凭证事实随明细落盘")

    def test_warrant_guard_proc_rule(self) -> None:
        items = [item("B0002", 3)]
        verdicts = {"B0002": {"verdict": "none"}}
        facts = {"B0002": {"proc_confirmed": True}}
        downgraded, _recorded = guards.warrant_guard(items, verdicts, lambda it: facts[it["id"]],
                                                     {"proc"})
        self.assertEqual(downgraded, 1, "同一进程已确认 → 命中误杀模式 → 降级")
        self.assertEqual(verdicts["B0002"]["verdict"], "mixed")

    def test_leaf_rule(self) -> None:
        single = item("B0002", 1)
        self.assertTrue(guards.is_leaf(single, "mixed", last_level=False, fanout_min=1))
        self.assertFalse(guards.is_leaf(single, "mixed", last_level=True, fanout_min=1))
        self.assertFalse(guards.is_leaf(item("B0003", 2), "mixed", last_level=False, fanout_min=1))
        self.assertFalse(guards.is_leaf(item("B0004", 1, parent=False), "unknown",
                                        last_level=False, fanout_min=1))


if __name__ == "__main__":
    unittest.main()
