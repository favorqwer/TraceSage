"""res 语义规范化（core/results.py）与结果口径的单元测试。"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.core import args as A  # noqa: E402
from provenance.adapters.config import load_classifier  # noqa: E402
from provenance.core.events import Call, EventRow  # noqa: E402
from provenance.core.graph import Outcome  # noqa: E402
from provenance.core.kinds import Bucket  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402
from provenance.core.results import norm_result, result_semantic  # noqa: E402
from provenance.graph.context import EmitContext  # noqa: E402
from provenance.graph.handlers import dispatch  # noqa: E402
from provenance.graph.state import State  # noqa: E402

DATA = ROOT / "data"


class NormResTest(unittest.TestCase):
    def test_unobserved_stays_unobserved(self):
        self.assertIsNone(norm_result("read", "read", None))

    def test_fd_return_is_not_a_result(self):
        # open 家族成功返回 fd 号
        for name in ("openat", "open", "creat"):
            self.assertIsNone(norm_result("create", name, 7))
        # accept 成功返回新套接字
        self.assertIsNone(norm_result("accept", "accept", 9))

    def test_fd_return_failure_keeps_errno(self):
        self.assertEqual(norm_result("create", "openat", -17), -17)
        self.assertEqual(norm_result("accept", "accept4", -11), -11)

    def test_address_return_is_not_a_result(self):
        self.assertIsNone(norm_result("mmap", "mmap", 0x7F0000))
        self.assertEqual(norm_result("mmap", "mmap", -12), -12)

    def test_byte_counts_untouched(self):
        self.assertEqual(norm_result("write", "write", 1024), 1024)
        self.assertEqual(norm_result("recv", "recvfrom", 0), 0)
        self.assertEqual(norm_result("read", "read", -9), -9)

    def test_clone_pid_is_not_a_result(self):
        self.assertIsNone(norm_result("clone", "clone", 1234))
        self.assertEqual(norm_result("clone", "clone", -4), -4)

    def test_memfd_fd_is_not_a_result(self):
        self.assertIsNone(norm_result("create", "memfd_create", 7))

    def test_exit_never_has_res(self):
        self.assertIsNone(norm_result("exit", "procexit", 0))

    def test_semantics_vocabulary(self):
        self.assertEqual(result_semantic("read"), "size")
        self.assertEqual(result_semantic("clone"), "none")
        self.assertEqual(result_semantic("mmap_read"), "errno_only")
        self.assertEqual(result_semantic("mmap_write"), "errno_only")
        self.assertEqual(result_semantic("mmap_exec"), "errno_only")
        self.assertEqual(result_semantic("unlink"), "errno_or_zero")
        self.assertEqual(result_semantic("create"), "zero_or_none_on_success")
        self.assertEqual(result_semantic("accept"), "none")
        self.assertEqual(result_semantic("exit"), "none")
        self.assertEqual(result_semantic("no_such_action"), "unknown")


def row(num, direction, name, text="", pid=100, ns=1000, rawres=None):
    return EventRow(num=num, ns=ns, direction=direction, call=name, pid=pid, tid=pid,
                    container_id="host", exe="/bin/sh", cwd="/", ppid=1, ruid="0",
                    proc_args="", args=A.parse(text), rawres=rawres)


def call(name, enter="", exit_="", rawres=None, enter_rawres=None):
    e = row(1, ">", name, enter, ns=1000, rawres=enter_rawres)
    x = row(2, "<", name, exit_, ns=1010, rawres=rawres)
    return Call.build(e, x)


def _out() -> Outcome:
    """一个已结算的 Outcome（stats.add 要求每个调用至少结算一行）。"""
    out = Outcome()
    out.buckets.append((1, Bucket.COVERED, ""))
    return out


class ResultPipelineTest(unittest.TestCase):
    def setUp(self):
        self.st = State.build("h")
        self.ctx = EmitContext(self.st, EmitOptions())
        self.t = load_classifier(DATA)

    def run_call(self, c):
        return dispatch(c, self.t.decide(c), self.ctx)

    def test_openat_fd_not_written_to_edge(self):
        out = self.run_call(call("openat", "name=/tmp/x flags=577(O_CREAT)", "res=5", rawres=5))
        self.assertEqual(out.edges[0].result, None)

    def test_mmap_failure_writes_errno(self):
        out = self.run_call(call("mmap", "fd=6(<f>/tmp/x) length=4096", "res=-12", rawres=-12))
        self.assertEqual(len(out.edges), 1)
        self.assertEqual((out.edges[0].action, out.edges[0].result), ("mmap_read", -12))

    def test_mmap_success_has_no_res(self):
        out = self.run_call(call("mmap", "fd=6(<f>/tmp/x) length=4096",
                                 "res=7F0000", rawres=0x7F0000))
        self.assertEqual(len(out.edges), 1)
        self.assertIsNone(out.edges[0].result)

    def test_rawres_only_from_exit_row(self):
        # 退出行没有结果、进入行有占位 0：不得把“未观测”写成“实测零”
        c = call("write", "fd=5(<f>/tmp/x) size=3", "", rawres=None, enter_rawres=0)
        self.assertIsNone(c.result)
        self.assertIsNone(c.result_source)

    def test_res_source_reports_origin(self):
        self.assertEqual(call("write", "", "res=3").result_source, "args")
        self.assertEqual(call("write", "", "", rawres=3).result_source, "rawres")
        self.assertIsNone(call("write", "", "").result_source)

    def test_stats_counts_res_from_both_sources(self):
        """统计口径必须与边的 result 同源：rawres 只有值时也算“有结果”。"""
        from provenance.core.stats import RunStats

        stats = RunStats()
        stats.add(call("read", "", "", rawres=12), self.t.decide(call("read")), _out())
        stats.add(call("read", "", "res=7"), self.t.decide(call("read")), _out())
        self.assertEqual(stats.param["read"][:2], [2, 2])
        self.assertEqual(stats.result_source["read"], {"rawres": 1, "args": 1})

    def test_missing_result_is_not_an_attempt(self):
        # 执行没有退出行：不得伪造 errno=0 的“尝试未成立”
        out = self.run_call(call("execve", "filename=/bin/nope", ""))
        self.assertEqual(out.attempts, [])
        self.assertEqual({(b, r) for _, b, r in out.buckets},
                         {(Bucket.OTHER, "result_unobserved:exec")})

    def test_confirmed_failure_is_an_attempt(self):
        out = self.run_call(call("execve", "filename=/bin/nope", "res=-2", rawres=-2))
        self.assertEqual(out.attempts[0][1:4], ("exec", "/bin/nope", 2))
        self.assertIn(Bucket.ATTEMPT, [b for _, b, _ in out.buckets])

    def test_bind_without_result_is_not_zero_errno(self):
        out = self.run_call(call("bind", "", ""))
        self.assertEqual(out.attempts, [])
        self.assertEqual({(b, r) for _, b, r in out.buckets},
                         {(Bucket.OTHER, "result_unobserved:bind")})


if __name__ == "__main__":
    unittest.main()
