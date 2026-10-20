import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core.classify import DEFERRED_VERBS, Tables  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.kinds import EdgeClass, ObjSource, Verdict  # noqa: E402
from provenance.graph.handlers import HANDLERS  # noqa: E402

DATA = ROOT / "data"


def row(num, direction, call, text="", pid=100, cid="host", ns=1000, exe="/bin/sh",
        cwd="/", ppid=1, ruid="0", cmdline=""):
    return EventRow(
        num=num, ns=ns, direction=direction, call=call, pid=pid, tid=pid,
        container_id=cid, exe=exe, cwd=cwd, ppid=ppid, ruid=ruid,
        cmdline=cmdline, args=A.parse(text),
    )


def call(name, enter="", exit="", pid=100, ns=1000):
    e = row(1, ">", name, enter, pid=pid, ns=ns)
    x = row(2, "<", name, exit, pid=pid, ns=ns + 10)
    return Call.build(e, x)


class TableTest(unittest.TestCase):
    def setUp(self):
        self.t = Tables(DATA)

    def test_verb_enum_is_34(self):
        self.assertEqual(self.t.verb_count() + len(DEFERRED_VERBS), 34)

    def test_every_verb_has_handler(self):
        for name in self.t.verbs:
            self.assertIn(name, HANDLERS, f"动词 {name} 没有 emitter")

    def test_sources_are_known(self):
        for spec in self.t.verbs.values():
            self.assertIsInstance(spec.source, ObjSource)
            self.assertIsInstance(spec.edge, EdgeClass)
            self.assertIn(spec.gate, ("always", "success"))

    def test_openat_dispatch(self):
        d = self.t.decide(call("openat", "", "res=5 flags=577(O_CREAT|O_WRONLY)"))
        self.assertEqual((d.verdict, d.verb), (Verdict.EMIT, "create"))
        d = self.t.decide(call("openat", "", "res=5 flags=0(O_RDONLY)"))
        self.assertEqual((d.verdict, d.reason), (Verdict.DROP, "open_readonly"))
        d = self.t.decide(call("openat", "", "res=5 flags=13377(O_DIRECTORY|O_TMPFILE)"))
        self.assertEqual((d.verdict, d.reason), (Verdict.DROP, "open_tmpfile"))
        d = self.t.decide(call("creat", "", "res=5 flags=577(O_CREAT|O_WRONLY)"))
        self.assertEqual((d.verdict, d.verb), (Verdict.EMIT, "create"))

    def test_ledger_verdicts(self):
        self.assertEqual(self.t.decide(call("close")).verdict, Verdict.HANDLE)
        self.assertEqual(self.t.decide(call("container")).verdict, Verdict.ATTR)
        self.assertEqual(self.t.decide(call("fsync")).verdict, Verdict.DROP)
        self.assertEqual(self.t.decide(call("setuid")).verdict, Verdict.OPS)
        self.assertEqual(self.t.decide(call("no_such_call")).verdict, Verdict.UNMAPPED)

    def test_deferred_kernel_calls_are_ops(self):
        for name in ("bpf", "finit_module", "shmget", "io_uring_setup"):
            self.assertEqual(self.t.decide(call(name)).verdict, Verdict.OPS, name)


if __name__ == "__main__":
    unittest.main()
