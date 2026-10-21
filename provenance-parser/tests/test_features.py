import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.kinds import Bucket  # noqa: E402
from provenance.core.options import EmitOptions, GraphLimits  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.emitter import GraphEmitter  # noqa: E402
from provenance.graph.handlers import dispatch  # noqa: E402
from provenance.graph.objects import ObjectResolver  # noqa: E402
from provenance.graph.state import State  # noqa: E402
from provenance.graph.state.containers import ContainerState  # noqa: E402
from provenance.graph.state.fds import FdEntry  # noqa: E402
from provenance.graph.store import GraphStore  # noqa: E402

DATA = ROOT / "data"


def row(num, direction, call, text="", pid=100, cid="host", ns=1000,
        cwd="/", exe="/bin/sh", rawres=None, buffer_b64=""):
    return EventRow(
        num=num, ns=ns, direction=direction, call=call, pid=pid, tid=pid,
        container_id=cid, exe=exe, cwd=cwd, ppid=1, ruid="0", proc_args="",
        args=A.parse(text), rawres=rawres, buffer_b64=buffer_b64,
    )


def call(name, enter="", exit="", pid=100, ns=1000, cwd="/", rawres=None):
    e = row(1, ">", name, enter, pid=pid, ns=ns, cwd=cwd)
    x = row(2, "<", name, exit, pid=pid, ns=ns + 10, cwd=cwd, rawres=rawres)
    return Call.build(e, x)


class FeatureTest(unittest.TestCase):
    def test_dirfd_resolution(self):
        st = State.build("h")
        st.fds.register("host", 100, 5, FdEntry("directory", "/base"))
        resolver = ObjectResolver(st)
        c = call("openat", "dirfd=5 name=x", "res=3 fd=6(<f>/base/x)")
        self.assertEqual(resolver.path_arg(c, "name", dirfd_key="dirfd"), "/base/x")

    def test_relative_without_base_uses_question_path(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("openat", "dirfd=-100(AT_FDCWD) name=x", "res=-2", cwd="")
        self.assertEqual(resolver.path_arg(c, "name", dirfd_key="dirfd"), "?x")
        self.assertEqual(resolver.counts["path_unresolved"], 1)

    def test_cwd_and_fchdir_state(self):
        st = State.build("h")
        st.fds.register("host", 100, 7, FdEntry("directory", "/tmp/dir"))
        st.proc.observe(row(1, ">", "chdir", pid=100))
        st.proc.observe_fs(call("chdir", "path=/srv", "res=0"), st.fds)
        self.assertEqual(st.proc.observe(row(2, "<", "read", pid=100)).cwd, "/srv")
        st.proc.observe_fs(call("fchdir", "fd=7(<d>/tmp/dir)", "res=0"), st.fds)
        self.assertEqual(st.proc.observe(row(3, "<", "read", pid=100)).cwd, "/tmp/dir")

    def test_fchdir_uses_token_when_table_misses(self):
        st = State.build("h")
        st.proc.observe(row(1, ">", "read", pid=100))
        st.proc.observe_fs(call("fchdir", "fd=7(<d>/tmp/dir)", "res=0"), st.fds)
        self.assertEqual(st.proc.live("host", 100).cwd, "/tmp/dir")
        self.assertEqual(st.fds.counts["fchdir_from_token"], 1)

    def test_chroot_root_state(self):
        st = State.build("h")
        st.proc.observe(row(1, ">", "chroot", pid=100))
        st.proc.observe_fs(call("chroot", "path=/jail", "res=0"), st.fds)
        self.assertEqual(st.proc.observe(row(2, "<", "read", pid=100)).root, "/jail")
        resolver = ObjectResolver(st)
        self.assertEqual(resolver.norm_path("/etc/passwd", call("read", pid=100)), "/jail/etc/passwd")

    def test_uid_from_geteuid_and_setuid(self):
        st = State.build("h")
        st.proc.observe(row(1, ">", "geteuid", pid=100))
        get = call("geteuid", "", "euid=0(root)", pid=100)
        st.proc.observe_uid(get)
        self.assertEqual(st.proc.observe(row(2, "<", "read", pid=100)).euid, 0)

        setu = call("setuid", "uid=1000(user)", "res=0", pid=100, rawres=0)
        st.proc.observe_uid(setu)
        self.assertEqual(st.proc.observe(row(3, "<", "read", pid=100)).euid, 1000)

        fail = call("setuid", "uid=0(root)", "res=-1(EPERM)", pid=100, rawres=-1)
        st.proc.observe_uid(fail)
        self.assertEqual(st.proc.observe(row(4, "<", "read", pid=100)).euid, 1000)

    def test_rawres_precedence(self):
        c = call("renameat2", "", "res=0 flags=2(RENAME_EXCHANGE)", rawres=0)
        self.assertEqual(c.result, 0)
        c2 = call("read", "", "res=9")
        self.assertEqual(c2.result, 9)

    def test_network_fd_is_not_file(self):
        st = State.build("h")
        emitter = GraphEmitter(st, EmitOptions())
        self.assertIsNone(emitter.file_node("host", "1.2.3.4:1", "ipv4"))

    def test_file_kind_default_and_backfill(self):
        st = State.build("h")
        emitter = GraphEmitter(st, EmitOptions())
        node = emitter.file_node("host", "/x")
        self.assertEqual(node.props["file_type"], "unknown")
        store = GraphStore(None, GraphLimits())
        from provenance.core.graph import Outcome
        store.add(Outcome(nodes=[node]))
        actual = emitter.file_node("host", "/x", "file")
        store.add(Outcome(nodes=[actual]))
        self.assertEqual(store.nodes[node.key].props["file_type"], "file")
        store.add(Outcome(nodes=[emitter.file_node("host", "/x")]))
        self.assertEqual(store.nodes[node.key].props["file_type"], "file")

    def test_container_indexed_mounts(self):
        st = ContainerState()
        st.observe({"id": "c", "name": "", "image": "",
                    "privileged": "false", "mounts": "", "mounts_indexed": []})
        self.assertIsNone(st.get("c").privileged)
        st.observe({
            "id": "c", "name": "web", "image": "alpine",
            "privileged": "true", "mounts": "",
            "mounts_indexed": [{"source": "/", "dest": "/host",
                                "rdwr": "true", "mode": "", "propagation": "rslave"}],
        })
        info = st.get("c")
        self.assertTrue(info.privileged)
        self.assertTrue(info.host_root_rw)
        self.assertEqual(info.backfills, 1)


if __name__ == "__main__":
    unittest.main()
