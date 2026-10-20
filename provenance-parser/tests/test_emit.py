import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core.classify import Tables  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.kinds import Bucket, EdgeClass, FileKey, NetKey  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.handlers import dispatch  # noqa: E402
from provenance.graph.state import State  # noqa: E402

DATA = ROOT / "data"


def row(num, direction, call, text="", pid=100, ns=1000, cid="host", exe="/bin/sh",
        cwd="/", ppid=1):
    return EventRow(num=num, ns=ns, direction=direction, call=call, pid=pid, tid=pid,
                    container_id=cid, exe=exe, cwd=cwd, ppid=ppid, ruid="0",
                    cmdline="", args=A.parse(text))


def call(name, enter="", exit="", pid=100, ns=1000):
    e = row(1, ">", name, enter, pid=pid, ns=ns)
    x = row(2, "<", name, exit, pid=pid, ns=ns + 10)
    return Call.build(e, x)


class EmitTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = Tables(DATA)
        self._n = 10

    def run_call(self, c):
        return dispatch(c, self.t.decide(c), self.ctx)

    def test_create_success(self):
        out = self.run_call(call(
            "openat", "", "fd=5(<f>/tmp/x) dirfd=-100(AT_FDCWD) name=/tmp/x "
            "flags=577(O_CREAT|O_WRONLY|O_CLOEXEC) res=5"))
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.P2F, "create"))
        self.assertEqual(edge.dst, FileKey("h", "host", "/tmp/x"))
        self.assertEqual(edge.res, 5)
        self.assertIn(Bucket.COVERED, [b for _, b, _ in out.buckets])
        self.assertIsNotNone(self.st.fds.get("host", 100, 5))

    def test_create_failure_goes_to_attempts(self):
        out = self.run_call(call("openat", "", "res=-17(EEXIST) name=/tmp/x flags=577(O_CREAT)"))
        self.assertEqual(out.edges, [])
        self.assertEqual(out.attempts[0][1:4], ("create", "/tmp/x", 17))
        self.assertIn(Bucket.ATTEMPT, [b for _, b, _ in out.buckets])

    def test_read_on_socket_becomes_recv(self):
        out = self.run_call(call(
            "read", "fd=7(<4t>1.2.3.4:5->9.9.9.9:80) size=10", "res=10 data=abc"))
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.N2P, "recv"))
        self.assertEqual(edge.src, NetKey("h", "1.2.3.4:5->9.9.9.9:80"))
        self.assertEqual(edge.head, "abc")
        self.assertEqual(edge.res, 10)

    def test_write_on_file(self):
        out = self.run_call(call(
            "write", "fd=5(<f>/tmp/x) size=3", "res=3 data=abc"))
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.P2F, "write"))

    def test_connect_emits_even_on_failure(self):
        out = self.run_call(call("connect", "fd=7(<4>)",
                                 "res=-115(EINPROGRESS) tuple=1.2.3.4:5->9.9.9.9:80"))
        self.assertEqual(len(out.edges), 1)
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.P2N, "connect"))
        self.assertEqual(out.edges[0].res, -115)

    def test_connect_unusable_tuple_is_evidence_not_graph(self):
        out = self.run_call(call("connect", "fd=7(<4>)",
                                 "res=0 tuple=0.0.0.0:0->9.9.9.9:80"))
        self.assertEqual(out.edges, [])
        self.assertEqual(len(out.attempts), 0)   # 成功但元组不可用：不是失败尝试
        self.assertEqual(len(out.ops), 1)        # 目标串仍留证
        self.assertIn(Bucket.OTHER, [b for _, b, _ in out.buckets])

    def test_self_signal_is_not_an_edge(self):
        out = self.run_call(call("kill", "pid=100(sh) sig=9(SIGKILL)", "res=0"))
        self.assertEqual(out.edges, [])
        self.assertIn("self_signal", [r for _, _, r in out.buckets])

    def test_clone_thread_is_not_a_process(self):
        out = self.run_call(call(
            "clone", "", "res=5(x) flags=33601539(CLONE_THREAD|CLONE_VM|CLONE_FILES)"))
        self.assertEqual(out.edges, [])
        self.assertIn("thread_clone", [r for _, _, r in out.buckets])

    def test_rename_keeps_old_path_on_edge(self):
        out = self.run_call(call(
            "renameat", "", "res=0 oldpath=A(/old) newpath=b(/new)"))
        edge = out.edges[0]
        self.assertEqual((edge.action, edge.old_path), ("rename", "/old"))
        self.assertEqual(edge.dst, FileKey("h", "host", "/new"))

    def test_chmod_mode(self):
        out = self.run_call(call(
            "chmod", "", "res=0 filename=/srv/x mode=0644(S_IWUSR|S_IRUSR)"))
        self.assertEqual(out.edges[0].mode, "0644")

    def test_access_probe(self):
        out = self.run_call(call("access", "mode=4(R_OK)", "res=0 name=/home"))
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.F2P, "probe"))

    def test_exec_splits_identity_and_loads_image(self):
        out = self.run_call(call("execve", "filename=/bin/ls", "res=0 exe=/bin/ls"))
        actions = sorted(edge.action for edge in out.edges)
        self.assertEqual(actions, ["exec", "load_image"])
        p2p = [e for e in out.edges if e.cls is EdgeClass.P2P][0]
        self.assertEqual(p2p.src.born_ns, 0)
        self.assertEqual(p2p.dst.born_ns, 1000)

    def test_proc_mem_derives_p2p_edge(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        out = self.run_call(call(
            "read", "fd=4(<f>/proc/123/mem) size=8", "res=8 data=x"))
        self.assertEqual(len(out.edges), 2)
        self.assertEqual([e.cls for e in out.edges], [EdgeClass.F2P, EdgeClass.P2P])
        self.assertEqual(out.edges[1].action, "mem_read")

    def test_unknown_fd_is_bucketed(self):
        out = self.run_call(call("read", "fd=99(<4>) size=1", "res=1 data=x"))
        self.assertEqual(out.edges, [])
        self.assertIn(Bucket.UNKNOWN_FD, [b for _, b, _ in out.buckets])

    def test_anonymous_mmap(self):
        out = self.run_call(call(
            "mmap", "addr=0 length=4096 prot=7(PROT_READ|PROT_WRITE|PROT_EXEC) "
            "flags=34(MAP_PRIVATE|MAP_ANONYMOUS)", "res=7F00"))
        self.assertEqual(out.edges, [])
        self.assertIn(Bucket.NO_OBJECT, [b for _, b, _ in out.buckets])

    def test_every_edge_endpoint_is_registered(self):
        """写库不变量：每条边的两端都必须在本 Outcome 的节点表里。

        否则 Cypher 的 MATCH 会静默失败，MERGE 不建边而 API 不报错。
        """
        cases = [
            call("openat", "", "res=5 fd=5(<f>/a) name=/a flags=577(O_CREAT)"),
            call("write", "fd=5(<f>/tmp/x) size=3", "res=3 data=abc"),
            call("read", "fd=7(<4t>1.2.3.4:5->9.9.9.9:80) size=1", "res=1 data=x"),
            call("connect", "fd=7(<4>)", "res=0 tuple=1.1.1.1:1->2.2.2.2:2"),
            call("accept", "fd=8(<4>)", "fd=9(<4t>2.2.2.2:2->1.1.1.1:1) tuple=1.1.1.1:1->2.2.2.2:2"),
            call("execve", "filename=/bin/ls", "res=0 exe=/bin/ls"),
            call("renameat", "", "res=0 oldpath=A(/old) newpath=b(/new)"),
            call("clone", "", "res=9(x) flags=0(CLONE_CHILD_SETTID)"),
        ]
        for c in cases:
            out = self.run_call(c)
            keys = {n.key for n in out.nodes}
            for edge in out.edges:
                self.assertIn(edge.src, keys, f"{c.call} 缺源端节点")
                self.assertIn(edge.dst, keys, f"{c.call} 缺宿端节点")

    def test_no_settle_gap(self):
        """每个断言过的 Outcome 都必须把两行都结算掉（账本互斥穷尽）。"""
        for c in (
            call("openat", "", "res=5 fd=5(<f>/a) name=/a flags=577(O_CREAT)"),
            call("connect", "fd=7(<4>)", "res=0 tuple=1.1.1.1:1->2.2.2.2:2"),
            call("kill", "pid=999(x) sig=9(SIGKILL)", "res=-3(ESRCH)"),
        ):
            out = self.run_call(c)
            self.assertEqual(sorted(n for n, _, _ in out.buckets), [1, 2], c.call)


if __name__ == "__main__":
    unittest.main()
