import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core.events import EventRow  # noqa: E402
from provenance.core.pair import PairingPool, should_pair  # noqa: E402


def row(num, ns, direction, call="read", pid=100, tid=100, latency=None,
        cid="host"):
    return EventRow(
        num=num, ns=ns, direction=direction, call=call, pid=pid, tid=tid,
        container_id=cid, exe="/bin/sh", cwd="/", ppid=0, ruid="",
        proc_args="", args={}, latency_ns=latency,
    )


class PairingTest(unittest.TestCase):
    def test_exact_latency_pairs_correct_when_exit_was_lost(self):
        pool = PairingPool()
        pool.push(row(1, 1_000_000_000, ">"))
        pool.push(row(2, 3_000_000_000, ">"))
        got = pool.take(row(3, 3_000_100_000, "<", latency=100_000))
        self.assertEqual(got.num, 2)
        self.assertEqual(pool.counts["exact"], 1)
        self.assertEqual(pool.size, 1)

    def test_multiple_pending_without_latency_is_ambiguous(self):
        pool = PairingPool()
        pool.push(row(1, 1_000_000_000, ">"))
        pool.push(row(2, 2_000_000_000, ">"))
        got = pool.take(row(3, 3_000_000_000, "<", latency=None))
        self.assertIsNone(got)
        self.assertEqual(pool.counts["ambiguous"], 1)
        self.assertEqual(pool.size, 2)

    def test_single_pending_without_latency_pairs(self):
        pool = PairingPool()
        pool.push(row(1, 1_000_000_000, ">"))
        got = pool.take(row(2, 2_000_000_000, "<", latency=None))
        self.assertEqual(got.num, 1)
        self.assertEqual(pool.counts["single_pending"], 1)

    def test_single_pending_with_mismatched_latency_does_not_pair(self):
        pool = PairingPool()
        pool.push(row(1, 1_000_000_000, ">"))
        got = pool.take(row(2, 3_000_000_000, "<", latency=1_000))
        self.assertIsNone(got)
        self.assertEqual(pool.size, 1)
        self.assertEqual(pool.counts["no_partner"], 1)

    def test_two_threads_same_start_are_separate(self):
        pool = PairingPool()
        pool.push(row(1, 1_000_000_000, ">", tid=101))
        pool.push(row(2, 1_000_000_000, ">", tid=102))
        got2 = pool.take(row(3, 1_100_000_000, "<", tid=102,
                             latency=100_000_000))
        got1 = pool.take(row(4, 1_200_000_000, "<", tid=101,
                             latency=200_000_000))
        self.assertEqual(got2.num, 2)
        self.assertEqual(got1.num, 1)

    def test_nonblocking_stale_is_evicted(self):
        pool = PairingPool(timeout_ns=5_000_000_000)
        pool.push(row(1, 1_000_000_000, ">", call="getpid"))
        evicted = pool.push(row(2, 7_000_000_000, ">", call="getpid"))
        self.assertEqual([e.num for e in evicted], [1])
        got = pool.take(row(3, 7_000_100_000, "<", call="getpid",
                             latency=100_000))
        self.assertEqual(got.num, 2)
        self.assertEqual(pool.counts["timeout_evicted"], 1)

    def test_blocking_stale_is_not_timeout_evicted(self):
        pool = PairingPool(timeout_ns=5_000_000_000)
        pool.push(row(1, 1_000_000_000, ">", call="read"))
        evicted = pool.push(row(2, 7_000_000_000, ">", call="read"))
        self.assertEqual(evicted, [])
        got = pool.take(row(3, 7_000_100_000, "<", call="read",
                             latency=100_000))
        self.assertEqual(got.num, 2)
        self.assertEqual(pool.counts["timeout_evicted"], 0)
        self.assertEqual(pool.size, 1)

    def test_ambiguous_tolerance_does_not_consume(self):
        pool = PairingPool(latency_tolerance_ns=1000)
        pool.push(row(1, 1_000, ">"))
        pool.push(row(2, 1_500, ">"))
        got = pool.take(row(3, 3_000, "<", latency=1_750))
        self.assertIsNone(got)
        self.assertEqual(pool.counts["ambiguous"], 1)
        self.assertEqual(pool.size, 2)

    def test_unique_tolerance_candidate_pairs(self):
        pool = PairingPool(latency_tolerance_ns=1000)
        pool.push(row(1, 1_000, ">"))
        pool.push(row(2, 2_200, ">"))
        got = pool.take(row(3, 3_000, "<", latency=1_800))
        self.assertEqual(got.num, 1)
        self.assertEqual(pool.counts["tolerance"], 1)

    def test_single_line_is_not_paired(self):
        self.assertFalse(should_pair(row(1, 1, ">", call="procexit")))
        self.assertTrue(should_pair(row(1, 1, ">", call="read")))

    def test_drain_returns_unmatched(self):
        pool = PairingPool()
        pool.push(row(1, 1, ">"))
        pool.push(row(2, 2, ">"))
        self.assertEqual([e.num for e in pool.drain()], [1, 2])
        self.assertEqual(pool.size, 0)


if __name__ == "__main__":
    unittest.main()
