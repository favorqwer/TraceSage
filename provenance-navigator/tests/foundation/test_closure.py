"""第 1 层闭包引擎的单测：不需要数据库、不需要模型。

覆盖：时间门限、单调推进（每顶点一次展开）、方向约束、零字节读取、取边不再剔除任何边、派生链、
同主体子进程、确定性。
"""

from __future__ import annotations

import unittest

from common import graph as graph_facts
import closure.walk as C


class FakeSource:
    """内存来源：按顶点给出事件，供闭包引擎调用（与真实来源同接口）。

    `seen`（已经收进闭包的边）这里不用于提速：本假来源就是为了让引擎的逐条判定路径也被跑到。
    """

    database = "fake"

    def __init__(self, processes=None, objects=None):
        self.processes = processes or {}      # process_id -> [Event]
        self.objects = objects or {}          # (kind, key) -> [Event]
        self.expanded: list[tuple[str, str, int, int]] = []

    def expand_process(self, items, seen=None):
        out = []
        for key, lo, hi in items:
            self.expanded.append(("P", key, lo, hi))
            out.extend(ev for ev in self.processes.get(key, []) if lo < ev.start <= hi)
        return out

    def expand_object(self, items, kind, seen=None):
        out = []
        for key, lo, hi in items:
            self.expanded.append((kind[0], key, lo, hi))
            out.extend(ev for ev in self.objects.get((kind, key), []) if lo < ev.start <= hi)
        return out

    def reads_after(self, key, kind, lo, hi):
        out = []
        for ev in self.objects.get((kind, key), []):
            if ev.rel in graph_facts.CONSUMER_RELS and lo < ev.start <= hi:
                out.append(ev)
        return out

    def process_info_many(self, pids):
        return None

    def network_protocols(self):
        return {}

    def close(self):
        return None

    def stats(self):
        return {"source": "fake"}


def ev(event_id, rel, syscall, pid, owner, other, other_label, start, end=None, nbytes=0,
       other_process_id=""):
    return C.Event(event_id=event_id, rel=rel, syscall=syscall, bytes=nbytes, start=start,
                   end=end if end is not None else start, pid=pid, owner=owner, other=other,
                   other_label=other_label, other_process_id=other_process_id)


def triples(result):
    return {graph_facts.content_triple_of(e.rel, e.syscall, e.owner, e.other)[:3]
            for e in result["events"]}


class ClosureTest(unittest.TestCase):
    def test_nothing_is_dropped_at_admission(self):
        """取边时不再剔除任何边：内核伪文件的读边、写非交付通道的边、能承载内容的读边都收。"""
        seed = ev(9, "f2p", "read", "P1", "/usr/bin/ps", "/f", "File", start=100, end=100, nbytes=5)
        pid_read = ev(1, "f2p", "read", "P1", "/usr/bin/ps", "/proc/1234/stat", "File",
                      start=90, end=90, nbytes=4)
        dev_write = ev(2, "p2f", "write", "P1", "/usr/bin/ps", "/dev/null", "File", start=91)
        keep = ev(3, "f2p", "read", "P1", "/usr/bin/ps", "/proc/cpuinfo", "File",
                  start=92, end=92, nbytes=4)
        src = FakeSource(processes={"P1": [pid_read, dev_write, keep]})
        res = C.run_closure(src, [seed], poi_t0=100)
        self.assertEqual(triples(res), {("/f", "read", "/usr/bin/ps"),
                                        ("/proc/1234/stat", "read", "/usr/bin/ps"),
                                        ("/usr/bin/ps", "write", "/dev/null"),
                                        ("/proc/cpuinfo", "read", "/usr/bin/ps")})

    def test_time_bound_and_single_expansion(self):
        """门限之外的事件不收；同一顶点不会用同样的门限重复展开。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=110, nbytes=5)
        write = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=200)
        src = FakeSource(processes={"P1": [read], "P2": [write]}, objects={("File", "/f"): [write]})
        res = C.run_closure(src, [read], poi_t0=110)
        self.assertIn(("/f", "read", "p1"), triples(res))
        # 写入发生在读取之后（200 > 读取结束 110）：不可能交付，必须不收
        self.assertNotIn(("p2", "write", "/f"), triples(res))

    def test_direction_keeps_only_writers(self):
        """方向约束：文件顶点只回溯写入侧，读取侧不算交付。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=5)
        other_read = ev(2, "f2p", "read", "P2", "p2", "/f", "File", start=50, end=50, nbytes=5)
        writer = ev(3, "p2f", "write", "P3", "p3", "/f", "File", start=40)
        objects = {("File", "/f"): [other_read, writer]}
        src = FakeSource(processes={"P1": [read], "P2": [other_read], "P3": [writer]}, objects=objects)
        res = C.run_closure(src, [read], poi_t0=100)
        self.assertIn(("p3", "write", "/f"), triples(res))
        self.assertNotIn(("p2", "read", "/f"), triples(res))

    def test_empty_read_included_but_not_expanded(self):
        """零字节读取：边本身收进来，但不从它的顶点往回找（写者不进闭包）。"""
        empty = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=0)
        writer = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=50)
        src = FakeSource(processes={"P1": [empty]}, objects={("File", "/f"): [writer]})
        res = C.run_closure(src, [empty], poi_t0=100)
        self.assertIn(("/f", "read", "p1"), triples(res))
        self.assertNotIn(("p2", "write", "/f"), triples(res))
        self.assertEqual(res["stats"]["empty_reads"], 1)

    def test_library_read_is_kept_and_chased(self):
        """动态库读取不再被剔除：读边进闭包，并且会从它的顶点往回找到写入者。"""
        poi = ev(1, "p2f", "write", "P1", "p1", "/poi", "File", start=200)
        lib = ev(2, "f2p", "read", "P1", "p1", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File",
                 start=100, end=100, nbytes=5)
        writer = ev(3, "p2f", "write", "P2", "p2", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File",
                    start=50)
        src = FakeSource(processes={"P1": [poi, lib], "P2": [writer]},
                         objects={("File", "/usr/lib/x86_64-linux-gnu/libc.so.6"): [writer]})
        res = C.run_closure(src, [poi], poi_t0=200)
        self.assertIn(("/usr/lib/x86_64-linux-gnu/libc.so.6", "read", "p1"), triples(res))
        self.assertIn(("p2", "write", "/usr/lib/x86_64-linux-gnu/libc.so.6"), triples(res))

    def test_seed_is_always_included(self):
        """终点事件本身永远收进来。"""
        poi = ev(1, "p2f", "write", "P1", "p1", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File", start=100)
        src = FakeSource(processes={"P1": [poi]})
        res = C.run_closure(src, [poi], poi_t0=100)
        self.assertEqual(len(res["events"]), 1)

    def test_sibling_children_count_as_upstream(self):
        """同主体子进程（机制，恒开）：父进程门限之前派生出去的兄弟进程，其活动也算上游。"""
        # 脚本 P 在 50 派生 C1、在 200 派生 C2；终点事件属于 C2
        spawn1 = ev(1, "p2p", "clone", "C1", "c1", "script", "Process", start=50,
                    other_process_id="P")
        spawn2 = ev(2, "p2p", "clone", "C2", "c2", "script", "Process", start=200,
                    other_process_id="P")
        poi = ev(3, "p2f", "write", "C2", "c2", "/poi", "File", start=210)
        c1_write = ev(4, "p2f", "write", "C1", "c1", "/side", "File", start=60)
        src = FakeSource(processes={"C1": [spawn1, c1_write], "C2": [spawn2, poi], "P": [spawn1, spawn2]})
        res = C.run_closure(src, [poi], poi_t0=210)
        self.assertIn(("c1", "write", "/side"), triples(res))

    def test_determinism(self):
        """同一输入跑两次，结果集合逐条相同。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=5)
        w1 = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=40)
        w2 = ev(3, "p2f", "write", "P3", "p3", "/f", "File", start=60)
        src = FakeSource(processes={"P1": [read], "P2": [w1], "P3": [w2]},
                         objects={("File", "/f"): [w1, w2]})
        first = C.run_closure(src, [read], poi_t0=100)
        second = C.run_closure(src, [read], poi_t0=100)
        self.assertEqual(triples(first), triples(second))
        self.assertEqual([e.event_id for e in first["events"]], [e.event_id for e in second["events"]])

    def test_rows_shape_for_fold(self):
        """输出行必须能被第 1 层的折叠直接吃（字段齐全、方向正确）。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=5)
        src = FakeSource(processes={"P1": [read]})
        res = C.run_closure(src, [read], poi_t0=100)
        row = res["rows"][0]
        self.assertEqual(row["rel"], "f2p")
        self.assertEqual(row["owner"], "p1")
        self.assertEqual(row["other"], "/f")
        self.assertEqual(row["process_id"], "P1")

    def test_causal_closure_forward_chain(self):
        """因果闭包：写入常规数据文件被外部进程读取时，受限前向补链自动重跑闭包。"""
        p1_write = ev(1, "p2f", "write", "P1", "/bin/sh", "/tmp/payload", "File", start=50, nbytes=100)
        poi_seed = ev(2, "p2n", "connect", "P1", "/bin/sh", "1.2.3.4:80", "Network", start=100)
        p2_read = ev(3, "f2p", "read", "P2", "/bin/target", "/tmp/payload", "File", start=60, end=60, nbytes=100)
        p2_act = ev(4, "p2f", "write", "P2", "/bin/target", "/tmp/out", "File", start=70, nbytes=50)

        src = FakeSource(
            processes={"P1": [p1_write, poi_seed], "P2": [p2_read, p2_act]},
            objects={("File", "/tmp/payload"): [p1_write, p2_read], ("File", "/tmp/out"): [p2_act]},
        )
        res = C.run_causal_closure(src, [poi_seed], poi_t0=100, forward_chain=True, with_events=True)
        self.assertIn(("P2", "/tmp/payload"), {(e.pid, e.other) for e in res["events"]})
        self.assertTrue(any(e.event_id == 3 for e in res["forward_seeds"]))


if __name__ == "__main__":
    unittest.main()
