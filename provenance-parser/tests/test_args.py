import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.core import paths as P  # noqa: E402


class ArgsTest(unittest.TestCase):
    def test_fd_token_with_space_inside_parens(self):
        text = "fd=9(<u>ffff8bdc0a496000->ffff8bdc0a494c00 public/qmgr) res=0"
        parsed = A.parse(text)
        self.assertEqual(parsed["fd"], "9(<u>ffff8bdc0a496000->ffff8bdc0a494c00 public/qmgr)")
        self.assertEqual(parsed["res"], "0")
        fd = A.fd_of(parsed["fd"])
        self.assertEqual((fd.num, fd.kind), (9, "unix"))

    def test_payload_does_not_swallow_next_key(self):
        parsed = A.parse("res=4 data=.... tuple=NULL")
        self.assertEqual(parsed["data"], "....")
        self.assertEqual(parsed["tuple"], "NULL")

    def test_fd_kinds_and_proto(self):
        fd = A.fd_of("5(<4t>1.2.3.4:5->6.7.8.9:10)")
        self.assertEqual((fd.kind, fd.proto), ("ipv4", "tcp"))
        fd = A.fd_of("5(<6u>::1:5->::2:10)")
        self.assertEqual((fd.kind, fd.proto), ("ipv6", "udp"))
        fd = A.fd_of("5(<d>/tmp)")
        self.assertEqual(fd.kind, "directory")
        fd = A.fd_of("5(<p>)")
        self.assertEqual(fd.kind, "pipe")

    def test_tuple(self):
        self.assertEqual(
            A.tuple_of("100.74.213.15:59360->100.86.108.4:22"),
            ("100.74.213.15", 59360, "100.86.108.4", 22),
        )
        self.assertIsNone(A.tuple_of("0.0.0.0:0"))
        self.assertTrue(A.tuple_usable("1.1.1.1:1->2.2.2.2:2", session=True))
        self.assertFalse(A.tuple_usable("0.0.0.0:1->2.2.2.2:2", session=True))
        self.assertTrue(A.endpoint_usable("0.0.0.0:8443"))
        self.assertFalse(A.endpoint_usable("0.0.0.0:0"))

    def test_numbers_and_flags(self):
        self.assertEqual(A.int_of("18121(postgres)"), 18121)
        self.assertEqual(A.int_of("-115(EINPROGRESS)"), -115)
        self.assertEqual(A.int_of("77BFA2029000"), 0x77BFA2029000)
        self.assertEqual(A.flags_of("577(O_CREAT|O_WRONLY|O_CLOEXEC)"),
                         {"O_CREAT", "O_WRONLY", "O_CLOEXEC"})

    def test_path_value(self):
        self.assertEqual(P.path_value("Cu1ADxgn(/dir/x)"), "/dir/x")
        self.assertEqual(P.path_value("/tmp/a(1)"), "/tmp/a(1)")
        self.assertEqual(P.path_value("/run/systemd/x"), "/run/systemd/x")

    def test_normalize(self):
        self.assertEqual(P.normalize("/a//b/./c/../d/"), "/a/b/d")
        self.assertEqual(P.normalize("x", "/base"), "/base/x")
        self.assertEqual(P.normalize("/"), "/")


if __name__ == "__main__":
    unittest.main()
