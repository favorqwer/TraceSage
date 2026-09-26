"""编排：整批调用失败 → 二分拆批重试，拆到单条仍失败才记未判定（不得静默变排除）。"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import pagent.core.llm as llm_mod
from pagent.core.llm import LlmBudget
from pagent.orchestration import judging as judging_mod


class SplitRetryTest(unittest.TestCase):
    def test_batch_failure_marks_unjudged(self) -> None:
        original = llm_mod._invoke_with_retry
        llm_mod._invoke_with_retry = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            batch = [("s1", [{"src": "a", "syscall": "read", "dst": "b", "step_key": "s1", "t0": i}
                             for i in range(4)])]
            result = judging_mod.judge_batch(object(), batch, metas={}, poi_t0=0,
                                             min_confidence=0.5, budget=LlmBudget(), log=lambda *_: None)
        finally:
            llm_mod._invoke_with_retry = original
        self.assertEqual(len(result["unjudged"]), 4)
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["excluded"])


if __name__ == "__main__":
    unittest.main()
