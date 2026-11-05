"""校准相关：umount 建边、设计等级、登记但不产边、能力缺口。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.adapters.config import load_classifier  # noqa: E402
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
        self.t = load_classifier(DATA)

    def run_call(self, c):
        return dispatch(c, self.t.decide(c), self.ctx)

    def test_umount_success_builds_edge(self):
        out = self.run_call(call("umount", "", "res=0 name=/mnt/data"))
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.P2F, "umount"))
        self.assertEqual(edge.dst.path, "/mnt/data")
        self.assertEqual(edge.result, 0)
        self.assertEqual([b for _, b, _ in out.buckets], [Bucket.COVERED] * 2)

    def test_umount_failure_is_attempt_not_node(self):
        # 失败时挂载点可能不存在 -> 不建节点，只记 attempts
        out = self.run_call(call("umount", "", "res=-2(ENOENT) name=/run/x.service"))
        self.assertEqual(out.edges, [])
        self.assertEqual(out.attempts[0][1:4], ("umount", "/run/x.service", 2))
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
        self.t = load_classifier(DATA)

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
        self.t = load_classifier(DATA)
        self.stats = RunStats()

    def feed(self, c):
        out = dispatch(c, self.t.decide(c), self.ctx)
        self.stats.add(c, self.t.decide(c), out)
        return out

    def test_registered_without_edge(self):
        # newfstatat 登记为 stat，但参数全空 -> 零边
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


class FileKindTest(unittest.TestCase):
    """File.kind 只保留图上真实存在的类型；匿名 IPC 不建节点。"""

    def setUp(self):
        from provenance.core.kinds import FileKind, file_kind_of
        self.FileKind = FileKind
        self.kind_of = file_kind_of
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = load_classifier(DATA)

    def test_live_kinds_map_directly(self):
        for name in ("file", "directory", "pipe", "unix", "memfd"):
            self.assertEqual(self.kind_of(name).value, name)

    def test_anonymous_ipc_has_no_node(self):
        for name in ("event", "timerfd", "signalfd", "inotify",
                     "eventpoll", "netlink", "bpf", "other"):
            self.assertIsNone(self.kind_of(name), name)

    def test_network_is_not_file(self):
        for name in ("ipv4", "ipv6"):
            self.assertIsNone(self.kind_of(name))

    def test_empty_is_unknown(self):
        self.assertEqual(self.kind_of("").value, "unknown")
        self.assertEqual(self.kind_of(None).value, "unknown")

    def test_no_special_or_netlink_enum(self):
        values = {k.value for k in self.FileKind}
        self.assertNotIn("special", values)
        self.assertNotIn("netlink", values)

    def test_memfd_becomes_synthetic_identity(self):
        out = dispatch(
            call("memfd_create", "name=payload flags=0(MFD_CLOEXEC)",
                 "fd=3(<m>payload)"),
            self.t.decide(call("memfd_create")), self.ctx,
        )
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.P2F, "create"))
        self.assertEqual(edge.dst.path, "memfd:payload")
        self.assertEqual(out.nodes[0].props["file_type"], "memfd")

    def test_memfd_path_not_joined_with_cwd(self):
        # 即使进程 cwd 是 /app，也不得生成 /app/payload
        self.st.proc.observe(row(9, ">", "read", pid=200))
        self.st.proc.observe(row(9, ">", "chdir", "path=/app", pid=200))
        c = Call.build(
            row(10, ">", "memfd_create", "name=payload", pid=200),
            row(11, "<", "memfd_create", "fd=3(<m>payload)", pid=200),
        )
        out = dispatch(c, self.t.decide(c), self.ctx)
        self.assertEqual(out.edges[0].dst.path, "memfd:payload")


class CollectorBlindTest(unittest.TestCase):
    """采集端盲区：<unknown> 单独成桶，与「未归类」分开。"""

    def setUp(self):
        from provenance.core.kinds import Verdict
        self.Verdict = Verdict
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = load_classifier(DATA)

    def test_unknown_event_goes_to_blind_bucket(self):
        c = call("<unknown>", "", "")
        out = dispatch(c, self.t.decide(c), self.ctx)
        self.assertEqual(out.edges, [])
        self.assertEqual({b for _, b, _ in out.buckets}, {Bucket.COLLECTOR_BLIND})
        self.assertEqual({r for _, _, r in out.buckets}, {"collector_unknown"})

    def test_unknown_is_not_unmapped(self):
        d = self.t.decide(call("<unknown>", "", ""))
        self.assertIs(d.verdict, self.Verdict.BLIND)
        self.assertEqual(d.value, "L0")

    def test_blind_does_not_enter_capability_gaps(self):
        from provenance.core.stats import RunStats
        stats = RunStats()
        c = call("<unknown>", "", "")
        stats.add(c, self.t.decide(c), dispatch(c, self.t.decide(c), self.ctx))
        self.assertNotIn("<unknown>", stats.unmapped)
        self.assertNotIn("<unknown>", stats.capability_gaps)


class AliasRegistrationTest(unittest.TestCase):
    """32 位兼容别名：采集端认识，但只在 32 位架构出现。"""

    def setUp(self):
        self.t = load_classifier(DATA)

    def test_stat64_family_goes_to_stat(self):
        for name in ("stat64", "lstat64", "fstat64"):
            d = self.t.decide(call(name, "", ""))
            self.assertEqual((d.verdict.value, d.verb), ("emit", "stat"), name)

    def test_llseek_goes_to_handle(self):
        d = self.t.decide(call("llseek", "", ""))
        self.assertEqual(d.verdict.value, "handle")


class CollectorBlindFileTest(unittest.TestCase):
    """data/collector_blind.txt 的格式自洽。"""

    def test_file_header_matches_body(self):
        import re
        path = DATA / "collector_blind.txt"
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8")
        names = [l for l in text.splitlines() if l and not l.startswith("#")]
        declared = int(re.search(r"# count: (\d+)", text).group(1))
        self.assertEqual(len(names), declared)
        self.assertIn("reboot", names)
        self.assertIn("sync", names)
        match = re.search(r"# critical: (.*)", text)
        self.assertIn("reboot", match.group(1))
