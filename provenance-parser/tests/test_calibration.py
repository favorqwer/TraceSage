"""校准相关：umount 建边、设计等级、登记但不产边、能力缺口。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core.classify import Tables  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.graph import Outcome  # noqa: E402
from provenance.core.kinds import Bucket, EdgeClass  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402
from provenance.core.stats import RunStats  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.handlers import dispatch  # noqa: E402
from provenance.graph.state import State  # noqa: E402

DATA = ROOT / "data"


def row(num, direction, name, text="", pid=100, ns=1000):
    return EventRow(num=num, ns=ns, direction=direction, call=name, pid=pid, tid=pid,
                    container_id="host", exe="/bin/sh", cwd="/", ppid=1, ruid="0",
                    proc_args="", args=A.parse(text))


def call(name, enter="", exit_=""):
    return Call.build(row(1, ">", name, enter, ns=1000),
                      row(2, "<", name, exit_, ns=1010))


class UmountTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = Tables(DATA)

    def run_call(self, c):
        return dispatch(c, self.t.decide(c), self.ctx)

    def test_umount_success_builds_edge(self):
        out = self.run_call(call("umount", "", "res=0 name=/mnt/data"))
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.P2F, "unmount"))
        self.assertEqual(edge.dst.path, "/mnt/data")
        self.assertEqual(edge.res, 0)
        self.assertEqual([b for _, b, _ in out.buckets], [Bucket.COVERED] * 2)

    def test_umount_failure_is_attempt_not_node(self):
        # 失败时挂载点可能不存在 -> 不建节点，只记 attempts
        out = self.run_call(call("umount", "", "res=-2(ENOENT) name=/run/x.service"))
        self.assertEqual(out.edges, [])
        self.assertEqual(out.attempts[0][1:4], ("unmount", "/run/x.service", 2))
        self.assertIn(Bucket.ATTEMPT, [b for _, b, _ in out.buckets])

    def test_umount2_flags_go_to_ops(self):
        out = self.run_call(call("umount2", "", "res=0 name=/mnt flags=2(MNT_DETACH)"))
        self.assertEqual(len(out.edges), 1)
        self.assertTrue(any(name == "umount2:2" for _, name, _ in out.ops))

    def test_umount_is_no_longer_unclassified(self):
        self.assertIsNotNone(self.t.decide(call("umount", "", "res=0 name=/mnt")).verb)
        self.assertNotIn("umount", self.t.ledger)


class DesignValueTest(unittest.TestCase):
    def setUp(self):
        self.t = Tables(DATA)

    def test_l1_groups_carry_design_level(self):
        for name in ("chown", "utimensat", "ftruncate", "bpf", "keyctl"):
            decision = self.t.decide(call(name, "", ""))
            self.assertEqual(decision.value, "L1", name)

    def test_l3_groups_default_to_l3(self):
        for name in ("poll", "futex", "getpid", "close", "socket"):
            decision = self.t.decide(call(name, "", ""))
            self.assertEqual(decision.value, "L3", name)

    def test_scheduler_noise_is_l4(self):
        self.assertEqual(self.t.decide(call("switch", "", "")).value, "L4")

    def test_emit_calls_are_l1(self):
        self.assertEqual(self.t.decide(call("read", "", "res=1")).value, "L1")


class StatsCalibrationTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = Tables(DATA)
        self.stats = RunStats()

    def feed(self, c):
        out = dispatch(c, self.t.decide(c), self.ctx)
        self.stats.add(c, self.t.decide(c), out)
        return out

    def test_registered_without_edge(self):
        # newfstatat 登记为 probe，但参数全空 -> 零边
        self.feed(call("newfstatat", "", ""))
        self.assertEqual(self.stats.emit_calls.get("newfstatat"), 1)
        self.assertEqual(self.stats.emit_calls_with_edge.get("newfstatat", 0), 0)

    def test_call_with_edge_excluded(self):
        self.feed(call("umount", "", "res=0 name=/mnt"))
        self.assertEqual(self.stats.emit_calls_with_edge.get("umount"), 1)

    def test_capability_gap_recorded(self):
        # utimensat 设计 L1，归 ops -> 记能力缺口
        self.feed(call("utimensat", "", ""))
        self.assertEqual(self.stats.capability_gaps["utimensat"], (1, "L1"))

    def test_scheduler_noise_not_a_gap(self):
        self.feed(call("poll", "", "res=1"))
        self.assertNotIn("poll", self.stats.capability_gaps)

    def test_endpoint_visibility_counted(self):
        self.feed(call("bind", "", "res=0 addr=NULL"))
        self.assertEqual((self.stats.endpoint_total, self.stats.endpoint_with_edge), (1, 0))


if __name__ == "__main__":
    unittest.main()
