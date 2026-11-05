import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.adapters.config import load_classifier  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.kinds import Bucket, EdgeClass, FileKey, NetKey  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.handlers import dispatch  # noqa: E402
from provenance.graph.objects import ObjectResolver  # noqa: E402
from provenance.graph.state import State  # noqa: E402
from provenance.graph.state.fds import FdEntry  # noqa: E402

DATA = ROOT / "data"


def row(num, direction, call, text="", pid=100, ns=1000, cid="host", exe="/bin/sh",
        cwd="/", ppid=1, buffer_b64="", tid=None):
    return EventRow(num=num, ns=ns, direction=direction, call=call, pid=pid,
                    tid=pid if tid is None else tid,
                    container_id=cid, exe=exe, cwd=cwd, ppid=ppid, ruid="0",
                    proc_args="", args=A.parse(text), buffer_b64=buffer_b64)


def call(name, enter="", exit="", pid=100, ns=1000, buffer_b64="", tid=None):
    e = row(1, ">", name, enter, pid=pid, ns=ns, buffer_b64=buffer_b64, tid=tid)
    x = row(2, "<", name, exit, pid=pid, ns=ns + 10, buffer_b64=buffer_b64, tid=tid)
    return Call.build(e, x)


class EmitTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = load_classifier(DATA)
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
        # res=5 是文件描述符（进程内局部编号），不是结果 -> 不落图
        self.assertIsNone(edge.result)
        self.assertIn(Bucket.COVERED, [b for _, b, _ in out.buckets])
        self.assertIsNotNone(self.st.fds.get("host", 100, 5))

    def test_create_mkdir_keeps_zero(self):
        """mkdir 成功返回 0：0 是实测结果，必须保留。"""
        out = self.run_call(call("mkdir", "name=/tmp/d", "res=0"))
        self.assertEqual(len(out.edges), 1)
        self.assertEqual(out.edges[0].result, 0)

    def test_create_failure_goes_to_attempts(self):
        out = self.run_call(call("openat", "", "res=-17(EEXIST) name=/tmp/x flags=577(O_CREAT)"))
        self.assertEqual(out.edges, [])
        self.assertEqual(out.attempts[0][1:4], ("create", "/tmp/x", 17))
        self.assertIn(Bucket.ATTEMPT, [b for _, b, _ in out.buckets])

    def test_read_on_socket_becomes_recv(self):
        out = self.run_call(call(
            "read", "fd=7(<4t>1.2.3.4:5->9.9.9.9:80) size=10", "res=10 data=abc",
            buffer_b64=base64.b64encode(b"abc").decode("ascii")))
        self.assertEqual(len(out.edges), 1)
        edge = out.edges[0]
        self.assertEqual((edge.cls, edge.action), (EdgeClass.N2P, "recv"))
        self.assertEqual(edge.src, NetKey("h", "1.2.3.4:5->9.9.9.9:80"))
        self.assertEqual(base64.b64decode(edge.payload_b64), b"abc")
        self.assertEqual(edge.result, 10)

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
        self.assertEqual(out.edges[0].result, -115)

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
        parent = self.st.proc.live("host", 100)
        self.assertIsNotNone(parent)
        self.assertIn(5, parent.threads)

    def test_thread_exit_does_not_close_process(self):
        self.st.proc.observe(row(1, ">", "read", pid=100, ns=500))
        parent = self.st.proc.live("host", 100)
        self.assertIsNotNone(parent)
        self.st.proc.on_thread_clone(parent, 101)
        out = self.run_call(call("procexit", pid=100, tid=101, ns=600))
        self.assertEqual(out.edges, [])
        self.assertIn("thread_exit", [r for _, _, r in out.buckets])
        self.assertIsNotNone(self.st.proc.live("host", 100))

    def test_untracked_thread_exit_is_not_a_process_exit(self):
        self.st.proc.observe(row(1, ">", "read", pid=100, ns=500))
        out = self.run_call(call("procexit", pid=100, tid=101, ns=600))
        self.assertEqual(out.edges, [])
        self.assertIn("thread_untracked", [r for _, _, r in out.buckets])
        self.assertIsNotNone(self.st.proc.live("host", 100))

    def test_main_exit_waits_for_worker(self):
        self.st.proc.observe(row(1, ">", "read", pid=100, ns=500))
        parent = self.st.proc.live("host", 100)
        self.assertIsNotNone(parent)
        self.st.proc.on_thread_clone(parent, 101)

        out = self.run_call(call("procexit", pid=100, tid=100, ns=600))
        self.assertEqual(out.edges, [])
        self.assertIn("thread_exit", [r for _, _, r in out.buckets])
        self.assertIsNotNone(self.st.proc.live("host", 100))

        out = self.run_call(call("procexit", pid=100, tid=101, ns=700))
        self.assertEqual(out.edges, [])  # 父进程 pid=1 没有节点，所以只有节点结束、没有边
        self.assertIsNone(self.st.proc.live("host", 100))

    def test_exit_without_live_segment_creates_nothing(self):
        out = self.run_call(call("procexit", pid=999, tid=999, ns=600))
        self.assertEqual(out.edges, [])
        self.assertEqual(out.nodes, [])
        self.assertIn("exit_no_segment", [r for _, _, r in out.buckets])
        self.assertEqual(self.st.proc.counts["exit_no_segment"], 1)

    def test_rename_emits_source_and_target_edges(self):
        out = self.run_call(call(
            "renameat", "", "res=0 oldpath=A(/old) newpath=b(/new)"))
        self.assertEqual(len(out.edges), 2)
        src_edge, dst_edge = out.edges
        self.assertEqual((src_edge.cls, src_edge.action), (EdgeClass.F2P, "rename"))
        self.assertEqual(src_edge.src, FileKey("h", "host", "/old"))
        self.assertEqual((src_edge.dst.pid, src_edge.dst.start_ns), (100, 0))
        self.assertEqual((dst_edge.cls, dst_edge.action), (EdgeClass.P2F, "rename"))
        self.assertEqual(dst_edge.dst, FileKey("h", "host", "/new"))
        self.assertEqual(src_edge.event_id, dst_edge.event_id)
        self.assertFalse(hasattr(src_edge, "from_path"))

    def test_chmod_mode(self):
        out = self.run_call(call(
            "chmod", "", "res=0 filename=/srv/x mode=0644(S_IWUSR|S_IRUSR)"))
        self.assertEqual(out.edges[0].mode, "0644")

    def test_access_probe(self):
        out = self.run_call(call("access", "mode=4(R_OK)", "res=0 name=/home"))
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.F2P, "stat"))

    def test_exec_splits_identity_and_loads_image(self):
        out = self.run_call(call("execve", "filename=/bin/ls", "res=0 exe=/bin/ls"))
        actions = sorted(edge.action for edge in out.edges)
        self.assertEqual(actions, ["exec", "exec"])
        p2p = [e for e in out.edges if e.cls is EdgeClass.P2P][0]
        self.assertEqual(p2p.src.start_ns, 0)
        self.assertEqual(p2p.dst.start_ns, 1000)

    def test_proc_mem_derives_p2p_edge(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        out = self.run_call(call(
            "read", "fd=4(<f>/proc/123/mem) size=8", "res=8 data=x"))
        self.assertEqual(len(out.edges), 2)
        self.assertEqual([e.cls for e in out.edges], [EdgeClass.F2P, EdgeClass.P2P])
        self.assertEqual(out.edges[1].action, "mem_read")
        # 读内存：目标 -> 读取者
        self.assertEqual(out.edges[1].src.pid, 123)
        self.assertEqual(out.edges[1].dst.pid, 100)

    def test_proc_maps_no_p2p(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        out = self.run_call(call(
            "read", "fd=4(<f>/proc/123/maps) size=8", "res=8 data=x"))
        self.assertEqual([e.cls for e in out.edges], [EdgeClass.F2P])

    def test_proc_mem_write_direction(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        out = self.run_call(call(
            "write", "fd=4(<f>/proc/123/mem) size=8", "res=8 data=x"))
        p2p = [e for e in out.edges if e.cls is EdgeClass.P2P][0]
        self.assertEqual(p2p.action, "mem_write")
        self.assertEqual(p2p.src.pid, 100)
        self.assertEqual(p2p.dst.pid, 123)

    def test_proc_mem_mmap_direction(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        out = self.run_call(call(
            "mmap", "fd=4(<f>/proc/123/mem) length=4096 "
            "prot=1(PROT_READ) flags=2(MAP_PRIVATE)", "res=7F00"))
        p2p = [e for e in out.edges if e.cls is EdgeClass.P2P][0]
        self.assertEqual(p2p.action, "mem_read")
        self.assertEqual(p2p.src.pid, 123)
        self.assertEqual(p2p.dst.pid, 100)

    def test_process_vm_read_and_write_direction(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        rd = self.run_call(call("process_vm_readv", "pid=123(x)", "res=1"))
        wr = self.run_call(call("process_vm_writev", "pid=123(x)", "res=1"))
        self.assertEqual((rd.edges[0].src.pid, rd.edges[0].dst.pid), (123, 100))
        self.assertEqual((wr.edges[0].src.pid, wr.edges[0].dst.pid), (100, 123))

    def test_ptrace_read_and_write_direction(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        rd = self.run_call(call(
            "ptrace", "request=2(PTRACE_PEEKDATA) pid=123(x)", "res=0"))
        wr = self.run_call(call(
            "ptrace", "request=5(PTRACE_POKEDATA) pid=123(x)", "res=0"))
        self.assertEqual((rd.edges[0].src.pid, rd.edges[0].dst.pid), (123, 100))
        self.assertEqual((wr.edges[0].src.pid, wr.edges[0].dst.pid), (100, 123))

    def test_pidfd_getfd_and_wait_direction(self):
        self.st.proc.observe(row(9, "<", "read", "fd=3(<f>/x)", pid=123, ns=500))
        got = self.run_call(call("pidfd_getfd", "pid=123(x)", "res=4"))
        waited = self.run_call(call("wait4", "pid=123(x)", "res=0"))
        self.assertEqual((got.edges[0].src.pid, got.edges[0].dst.pid), (123, 100))
        self.assertEqual((waited.edges[0].src.pid, waited.edges[0].dst.pid),
                         (123, 100))

    def test_exit_direction_child_to_parent(self):
        parent = self.st.proc.observe(row(1, ">", "read", pid=1, ns=100))
        self.st.proc.on_clone(parent, 100, 200, "/bin/sh", "sh")
        out = self.run_call(call("exit_group", "", ""))
        self.assertEqual((out.edges[0].src.pid, out.edges[0].dst.pid), (100, 1))

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

    def test_mmap_shared_write_is_p2f(self):
        out = self.run_call(call(
            "mmap", "fd=6(<f>/tmp/x) length=4096 "
            "prot=2(PROT_WRITE) flags=1(MAP_SHARED)", "res=7F00"))
        self.assertEqual(len(out.edges), 1)
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.P2F, "mmap_write"))

    def test_mmap_private_write_is_read_only(self):
        out = self.run_call(call(
            "mmap", "fd=6(<f>/tmp/x) length=4096 "
            "prot=2(PROT_WRITE) flags=2(MAP_PRIVATE)", "res=7F00"))
        self.assertEqual([(e.cls, e.action) for e in out.edges],
                         [(EdgeClass.F2P, "mmap_read")])

    def test_mmap_exec_is_f2p(self):
        out = self.run_call(call(
            "mmap", "fd=6(<f>/tmp/x) length=4096 "
            "prot=5(PROT_READ|PROT_EXEC) flags=2(MAP_PRIVATE)", "res=7F00"))
        self.assertEqual((out.edges[0].cls, out.edges[0].action),
                         (EdgeClass.F2P, "mmap_exec"))

    def test_mmap_shared_readwrite_has_two_edges(self):
        out = self.run_call(call(
            "mmap", "fd=6(<f>/tmp/x) length=4096 "
            "prot=3(PROT_READ|PROT_WRITE) flags=1(MAP_SHARED)", "res=7F00"))
        self.assertEqual({(e.cls, e.action) for e in out.edges},
                         {(EdgeClass.F2P, "mmap_read"), (EdgeClass.P2F, "mmap_write")})

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

    # ---------------------------------------------------------------- fd 状态
    def test_open_readonly_registers_fd_without_edge(self):
        out = self.run_call(call(
            "openat", "",
            "fd=5(<f>/etc/passwd) flags=0(O_RDONLY|O_CLOEXEC) res=5"))
        self.assertEqual(out.edges, [])
        self.assertIn(Bucket.HANDLE, [b for _, b, _ in out.buckets])
        entry = self.st.fds.get("host", 100, 5)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.target.path, "/etc/passwd")
        self.assertTrue(entry.cloexec)

    def test_open_tmpfile_registers_anonymous_fd(self):
        out = self.run_call(call(
            "openat", "",
            "fd=7(<f><UNKNOWN>7) flags=13377(O_TMPFILE|O_RDWR) res=7"))
        self.assertEqual(out.edges, [])
        entry = self.st.fds.get("host", 100, 7)
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.target)

    def test_dup2_alias_uses_exit_result(self):
        self.st.fds.register("host", 100, 3, FdEntry.file("/tmp/a"))
        out = self.run_call(call("dup2", "fd=3(<f>/tmp/a)", "res=5(<f>/tmp/a)"))
        self.assertEqual(out.edges, [])
        entry = self.st.fds.get("host", 100, 5)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.target.path, "/tmp/a")

    def test_fcntl_dupfd_and_setfd(self):
        self.st.fds.register("host", 100, 3, FdEntry.file("/tmp/a"))
        self.run_call(call("fcntl", "fd=3(<f>/tmp/a) cmd=0(F_DUPFD)",
                           "res=6(<f>/tmp/a)"))
        self.assertEqual(self.st.fds.get("host", 100, 6).target.path, "/tmp/a")
        self.run_call(call("fcntl", "fd=3(<f>/tmp/a) cmd=2(F_SETFD) arg=1(FD_CLOEXEC)",
                           "res=0"))
        self.assertTrue(self.st.fds.get("host", 100, 3).cloexec)
        self.assertEqual(self.st.fds.prune_cloexec("host", 100), 1)
        self.assertIsNone(self.st.fds.get("host", 100, 3))
        self.assertIsNotNone(self.st.fds.get("host", 100, 6))

    def test_dirfd_miss_does_not_fall_back_to_cwd(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("openat", "dirfd=9 name=x", "res=0")
        self.assertEqual(resolver.path_arg(c, "name", dirfd_key="dirfd"), "")
        self.assertEqual(st.fds.counts["dirfd_miss"], 1)

    def test_close_range_removes_range(self):
        for fd in (3, 4, 5, 6):
            self.st.fds.register("host", 100, fd, FdEntry.file(f"/{fd}"))
        self.run_call(call("close_range", "first=3 last=5", "res=0"))
        self.assertIsNone(self.st.fds.get("host", 100, 3))
        self.assertIsNone(self.st.fds.get("host", 100, 5))
        self.assertIsNotNone(self.st.fds.get("host", 100, 6))

    def test_exit_destroys_fd_table(self):
        self.st.fds.register("host", 100, 3, FdEntry.file("/a"))
        self.run_call(call("exit_group", "", ""))
        self.assertIsNone(self.st.fds.get("host", 100, 3))

    # ---------------------------------------------------------------- syscall
    def test_edge_has_canonical_and_raw_syscall(self):
        out = self.run_call(call(
            "sendmsg", "fd=7(<4t>1.1.1.1:1->2.2.2.2:2) size=1",
            "res=1 data=x"))
        edge = out.edges[0]
        self.assertEqual(edge.action, "send")
        self.assertEqual(edge.syscall, "sendto")

    def test_pread_keeps_read_family_and_raw_name(self):
        out = self.run_call(call(
            "pread", "fd=5(<f>/tmp/x) size=1", "res=1 data=x"))
        edge = out.edges[0]
        self.assertEqual(edge.action, "read")
        self.assertEqual(edge.syscall, "read")

    def test_mkdirat_keeps_mkdir_family(self):
        out = self.run_call(call(
            "mkdirat", "dirfd=-100(AT_FDCWD) name=/tmp/d", "res=0"))
        edge = out.edges[0]
        self.assertEqual(edge.action, "create")
        self.assertEqual(edge.syscall, "mkdir")


if __name__ == "__main__":
    unittest.main()
