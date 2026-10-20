import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core.events import EventRow  # noqa: E402
from provenance.core.kinds import Bucket  # noqa: E402
from provenance.runtime.ledger import Ledger  # noqa: E402


def row(num, call="read", pid=1):
    return EventRow(num=num, ns=num * 10, direction="<", call=call, pid=pid, tid=pid,
                    container_id="host", exe="", cwd="/", ppid=0, ruid="", cmdline="",
                    args={})


class LedgerTest(unittest.TestCase):
    def test_equation_and_gaps(self):
        led = Ledger()
        for num in (5, 7, 8):
            led.ingest(row(num))
        self.assertEqual(led.gap_numbers, 1)
        self.assertEqual(led.gap_segments, 1)
        self.assertEqual(led.gap_stats()["missing_numbers"], 5)  # 末号 8 - 3 行

        led.settle(5, Bucket.COVERED)
        led.settle(7, Bucket.NO_OBJECT)
        led.settle(8, Bucket.UNPAIRED, "stream_end")
        led.final()
        self.assertEqual(led.counts[Bucket.COVERED], 1)
        self.assertEqual(led.counts[Bucket.NO_OBJECT], 1)

    def test_double_settle_is_fatal(self):
        led = Ledger()
        led.ingest(row(1))
        led.settle(1, Bucket.COVERED)
        with self.assertRaises(RuntimeError):
            led.settle(1, Bucket.DROP)

    def test_rollback_is_fatal(self):
        led = Ledger()
        led.ingest(row(10))
        with self.assertRaises(ValueError):
            led.ingest(row(9))

    def test_abnormal_rows_count(self):
        led = Ledger()
        led.ingest(row(1))
        led.ingest_bad("ValueError")
        led.settle(1, Bucket.COVERED)
        led.final()
        self.assertEqual(led.counts[Bucket.ABNORMAL], 1)

    def test_unbalanced_is_fatal(self):
        led = Ledger()
        led.ingest(row(1))
        with self.assertRaises(RuntimeError):
            led.final()


if __name__ == "__main__":
    unittest.main()
