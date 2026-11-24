"""Rule KG 统计口径测试（不需要数据库、不需要模型）。"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from rag.stats import compute_rule_stats, fold_mask  # noqa: E402


class FoldMaskTest(unittest.TestCase):
    def test_excludes_only_target_block(self):
        mask = fold_mask(10, 3, 2)  # 剔除 bit3、bit4
        self.assertEqual(mask.bit_count(), 8)
        self.assertEqual(mask & (1 << 3), 0)
        self.assertEqual(mask & (1 << 4), 0)
        self.assertNotEqual(mask & (1 << 2), 0)
        self.assertNotEqual(mask & (1 << 5), 0)

    def test_zero_size_keeps_all(self):
        self.assertEqual(fold_mask(8, 0, 0), (1 << 8) - 1)


class RuleStatsTest(unittest.TestCase):
    def test_precision_and_background(self):
        mask = (1 << 10) - 1
        pos = 0b11          # bit0、bit1
        ignore = 0b100      # bit2
        rule = 0b1111       # bit0、bit1、bit2、bit3
        rec = compute_rule_stats({"M": rule}, pos, ignore, mask, ["M"])["M"]
        self.assertEqual(rec.hits_total, 4)
        self.assertEqual(rec.attack_hits, 2)
        self.assertEqual(rec.ignore_hits, 1)
        self.assertEqual(rec.background_hits, 1)  # bit3
        self.assertAlmostEqual(rec.precision, 2 / 3)
        self.assertEqual(rec.train_keys, 10)

    def test_zero_denominator_is_none(self):
        mask = (1 << 4) - 1
        rec = compute_rule_stats({"M": 0b1}, 0b1, 0b0, mask, ["M"])["M"]
        # rule 只命中 pos 边，没有背景命中；分母=1，查准=1.0
        self.assertEqual(rec.precision, 1.0)
        rec2 = compute_rule_stats({"N": 0b0}, 0b1, 0b0, mask, ["N"])["N"]
        self.assertIsNone(rec2.precision)


if __name__ == "__main__":
    unittest.main()
