"""路径注记解析与句柄客体解析的回归测试（对应“路径注记 / fd 客体名”两类缺陷）。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core.paths import normalize, parse_path_arg, path_value  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.graph.objects import ObjectResolver  # noqa: E402
from provenance.graph.state import State  # noqa: E402
from provenance.graph.state.fds import FdEntry  # noqa: E402


def row(num, direction, name, text="", pid=100, ns=1000, cwd="/"):
    return EventRow(
        num=num, ns=ns, direction=direction, call=name, pid=pid, tid=pid,
        container_id="host", exe="/bin/sh", cwd=cwd, ppid=1, ruid="0",
        proc_args="", args=A.parse(text), rawres=None, buffer_b64="",
    )


def call(name, enter="", exit="", pid=100, ns=1000, cwd="/"):
    enter_row = row(1, ">", name, enter, pid=pid, ns=ns, cwd=cwd)
    exit_row = row(2, "<", name, exit, pid=pid, ns=ns + 10, cwd=cwd)
    return Call.build(enter_row, exit_row)


class PathAnnotationTest(unittest.TestCase):
    def test_dot_annotation_is_stripped(self):
        self.assertEqual(parse_path_arg(".(/srv/www/s8-site/uploads)"),
                         (".", "/srv/www/s8-site/uploads"))

    def test_relative_with_dirs_annotation_is_stripped(self):
        # 旧实现只看“括号前有没有 /”，这一形态整串被当成路径（10 库共 884 个脏顶点）
        raw = "base/1(/var/lib/postgresql/14/main/base/1)"
        self.assertEqual(parse_path_arg(raw),
                         ("base/1", "/var/lib/postgresql/14/main/base/1"))
        self.assertEqual(path_value(raw), "/var/lib/postgresql/14/main/base/1")

    def test_in_chroot_relative_annotation(self):
        self.assertEqual(path_value("cache.php(/cache.php)"), "/cache.php")

    def test_plain_filename_with_parens_is_not_stripped(self):
        self.assertEqual(parse_path_arg("/tmp/a(1)"), ("/tmp/a(1)", ""))
        self.assertEqual(path_value("/tmp/a(1)"), "/tmp/a(1)")

    def test_trailing_suffix_after_parens_is_not_stripped(self):
        self.assertEqual(path_value("/tmp/a (copy).txt"), "/tmp/a (copy).txt")

    def test_no_annotation(self):
        self.assertEqual(parse_path_arg("/plain/path"), ("/plain/path", ""))


class ChrootStateTest(unittest.TestCase):
    """chroot 根与建点必须来自同一解析结果（vsftpd 案例的回归）。"""

    def _resolver(self):
        st = State.build("h")
        return st, ObjectResolver(st)

    def test_chroot_target_uses_annotation(self):
        st, resolver = self._resolver()
        st.proc.observe(row(1, ">", "chroot", pid=100))
        c = call("chroot", "path=.(/srv/www/s8-site/uploads)", "res=0")
        node_path = resolver.path_arg(c, "path")            # handler 解析一次
        st.proc.note_root_target(c.head_row.num, node_path)  # 状态消费同一结果
        resolver.observe_fs(c)
        self.assertEqual(node_path, "/srv/www/s8-site/uploads")
        self.assertEqual(st.proc.live("host", 100).root, node_path)

    def test_relative_path_under_chroot_lands_on_host_view(self):
        st, resolver = self._resolver()
        st.proc.observe(row(1, ">", "chroot", pid=100))
        c = call("chroot", "path=.(/srv/www/s8-site/uploads)", "res=0")
        st.proc.note_root_target(c.head_row.num, resolver.path_arg(c, "path"))
        resolver.observe_fs(c)
        c2 = call("openat", "dirfd=-100(AT_FDCWD) name=cache.php(/cache.php)",
                  "res=3 fd=4(<f>/cache.php)")
        self.assertEqual(resolver.path_arg(c2, "name", dirfd_key="dirfd"),
                         "/srv/www/s8-site/uploads/cache.php")

    def test_chdir_with_annotation(self):
        st, resolver = self._resolver()
        st.proc.observe(row(1, ">", "chdir", pid=100))
        resolver.observe_fs(call("chdir", "path=.(/srv/app)", "res=0"))
        self.assertEqual(st.proc.live("host", 100).cwd, "/srv/app")


class FdTargetTest(unittest.TestCase):
    """句柄客体必须是已解析结果；合成键不得被路径规整改写。"""

    def test_unix_socket_token_is_extracted(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("ioctl")
        fd = A.fd_of("4(<u>0->ffff8bdc02ae3c00 /run/systemd/journal/syslog)")
        target = resolver.target_from_token(c, fd)
        self.assertEqual(target.path, "/run/systemd/journal/syslog")
        self.assertEqual(target.kind, "unix")

    def test_annotated_relative_fd_name_is_resolved(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("read")
        fd = A.Fd(num=4, code="f", kind="file",
                  name="base/1(/var/lib/postgresql/14/main/base/1)")
        target = resolver.target_from_token(c, fd)
        self.assertEqual(target.path, "/var/lib/postgresql/14/main/base/1")

    def test_relative_fd_name_uses_cwd(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("read", cwd="/srv/app")
        fd = A.Fd(num=4, code="f", kind="file", name="conf/app.ini")
        self.assertEqual(resolver.target_from_token(c, fd).path, "/srv/app/conf/app.ini")

    def test_pipe_and_memfd_stay_synthetic(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        c = call("read")
        pipe = A.Fd(num=3, code="p", kind="pipe", name="pipe:[123]")
        memfd = A.Fd(num=5, code="m", kind="memfd", name="payload")
        self.assertEqual(resolver.target_from_token(c, pipe).name, "pipe:[123]")
        self.assertEqual(resolver.target_from_token(c, memfd).name, "memfd:payload")

    def test_from_entry_returns_resolved_key(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        st.fds.register("host", 100, 7, FdEntry.directory("/tmp/dir"))
        c = call("fchdir")
        fd, entry = resolver.fd_entry(c, "fd")
        self.assertIsNone(fd)
        c2 = call("chdir")
        fd2, entry2 = resolver.fd_entry(c2)
        self.assertIsNone(fd2)  # 无 fd 参数

    def test_synthetic_pipe_keeps_name_in_filekey(self):
        st = State.build("h")
        resolver = ObjectResolver(st)
        st.fds.register("host", 100, 3, FdEntry.synthetic("pipe:[9]", "pipe"))
        c = call("write", "fd=3(<p>pipe:[9])")
        fd, entry = resolver.fd_entry(c)
        obj = resolver.from_entry(c, fd, entry)
        self.assertEqual(obj.key.path, "pipe:[9]")
        self.assertEqual(obj.node_kind, "pipe")


if __name__ == "__main__":
    unittest.main()
