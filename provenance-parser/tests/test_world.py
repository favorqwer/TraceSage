import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core.events import EventRow  # noqa: E402
from provenance.graph.state import State  # noqa: E402
from provenance.graph.state.fds import FdEntry  # noqa: E402


def row(pid, ns, call="read", cid="host", exe="/bin/sh"):
    return EventRow(num=ns, ns=ns, direction="<", call=call, pid=pid, tid=pid,
                    container_id=cid, exe=exe, cwd="/", ppid=1, ruid="0",
                    cmdline="cmd", args={})


class ProcTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.p = self.st.proc

    def test_observe_unknown_then_clone_then_exec(self):
        parent = self.p.observe(row(10, 100))
        self.assertEqual((parent.born_ns, parent.born_src), (0, "unknown"))

        child = self.p.on_clone(parent, 11, 200, "/bin/sh", "sh")
        self.assertEqual((child.born_ns, child.born_src), (200, "clone"))
        self.assertEqual(self.p.resolve("host", 11, 250).key, child.key)

        new = self.p.on_exec(child, 300, "/bin/ls", "ls")
        self.assertEqual((new.born_ns, new.born_src), (300, "exec"))
        self.assertEqual(self.p.resolve("host", 11, 350).key, new.key)
        self.assertEqual(self.p.resolve("host", 11, 250).key, child.key)

        self.p.on_exit(new, 400)
        self.assertIsNone(self.p.resolve("host", 11, 450))

    def test_pid_reuse_creates_new_segment(self):
        first = self.p.observe(row(20, 100))
        self.p.on_exit(first, 200)
        second = self.p.observe(row(20, 300))
        self.assertNotEqual(first.key, second.key)

    def test_two_unknown_segments_do_not_collide(self):
        first = self.p.observe(row(30, 100))
        self.p.on_exit(first, 200)
        second = self.p.observe(row(30, 300))
        self.assertEqual(second.born_src, "collision")
        self.assertNotEqual(first.key, second.key)
        self.assertEqual(self.p.counts["born_collision"], 1)

    def test_cross_container_pid_is_diagnosed(self):
        self.p.observe(row(40, 100, cid="c1"))
        self.assertIsNone(self.p.resolve_or_none("c2", 40, 150))
        self.assertEqual(self.p.counts["target_pid_other_ns"], 1)

    def test_late_clone_upgrades_unknown_segment(self):
        early = self.p.observe(row(50, 100))
        old_key = early.key
        parent = self.p.observe(row(51, 90))
        child = self.p.on_clone(parent, 50, 95, "/bin/x", "x")
        self.assertIs(child, early)
        self.assertEqual(child.key.born_ns, 95)
        self.assertEqual(self.p.counts["late_clone_upgrade"], 1)
        self.assertNotEqual(old_key, child.key)


class FdTest(unittest.TestCase):
    def setUp(self):
        self.fds = State.build("h").fds

    def test_dup_close_cloexec(self):
        self.fds.register("host", 7, 3, FdEntry("file", "/a"))
        self.fds.register("host", 7, 4, FdEntry("file", "/b", cloexec=True))
        self.fds.dup("host", 7, 3, 5)
        self.assertEqual(self.fds.get("host", 7, 5).name, "/a")
        self.fds.close("host", 7, 3)
        self.assertIsNone(self.fds.get("host", 7, 3))
        self.assertEqual(self.fds.prune_cloexec("host", 7), 1)
        self.assertIsNone(self.fds.get("host", 7, 4))
        self.assertIsNotNone(self.fds.get("host", 7, 5))

    def test_fork_copies_table(self):
        self.fds.register("host", 8, 3, FdEntry("file", "/a"))
        self.fds.fork("host", 8, 9)
        self.assertEqual(self.fds.get("host", 9, 3).name, "/a")

    def test_cap_eviction(self):
        fds = State.build("h").fds
        fds.cap = 2
        for fd in (3, 4, 5):
            fds.register("host", 1, fd, FdEntry("file", f"/{fd}"))
        self.assertIsNone(fds.get("host", 1, 3))
        self.assertIsNotNone(fds.get("host", 1, 5))


class ContainerTest(unittest.TestCase):
    def test_placeholder_is_not_a_conclusion(self):
        st = State.build("h")
        st.containers.observe({"id": "c1", "name": "", "image": "",
                               "privileged": "false", "mounts": ""})
        info = st.containers.get("c1")
        self.assertIsNone(info.privileged)
        self.assertIsNone(info.host_root_rw)

        st.containers.observe({"id": "c1", "name": "web", "image": "alpine",
                               "privileged": "true", "mounts": "/:/host::true:rslave"})
        info = st.containers.get("c1")
        self.assertTrue(info.privileged)
        self.assertTrue(info.host_root_rw)
        self.assertEqual(info.backfills, 1)

    def test_missing_metadata_stays_unknown(self):
        st = State.build("h")
        self.assertEqual(st.containers.props_for("nope"),
                         {"privileged": None, "host_root_rw": None})


if __name__ == "__main__":
    unittest.main()
