"""第 1 层闭包引擎的单测：不需要数据库、不需要模型。

覆盖：时间门限、单调推进（每顶点一次展开）、方向约束、零字节读取、规则剔除、派生链、
同主体子进程、确定性。
"""

from __future__ import annotations

import unittest

from pagent.layers.l1_reach import closure as C


class FakeSource:
    """内存来源：按顶点给出事件，供闭包引擎调用（与真实来源同接口）。

    `seen`（已经收进闭包的边）这里不用于提速：本假来源就是为了让引擎的逐条判定路径也被跑到
    （事件由 `ev()` 手工构造，规则编码是"未预先判定"，引擎会现算）。
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

    def process_info_many(self, pids):
        return None

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
    return {e.content_triple()[:3] for e in result["events"]}


class ClosureTest(unittest.TestCase):
    def test_time_bound_and_single_expansion(self):
        """门限之外的事件不收；同一顶点不会用同样的门限重复展开。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=110, nbytes=5)
        write = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=200)
        src = FakeSource(processes={"P1": [read], "P2": [write]}, objects={("File", "/f"): [write]})
        res = C.run_closure(src, [read], options=C.Options(), poi_t0=110)
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
        res = C.run_closure(src, [read], options=C.Options(), poi_t0=100)
        self.assertIn(("p3", "write", "/f"), triples(res))
        self.assertNotIn(("p2", "read", "/f"), triples(res))

    def test_empty_read_included_but_not_expanded(self):
        """零字节读取：边本身收进来，但不从它的顶点往回找（写者不进闭包）。"""
        empty = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=0)
        writer = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=50)
        src = FakeSource(processes={"P1": [empty]}, objects={("File", "/f"): [writer]})
        res = C.run_closure(src, [empty], options=C.Options(), poi_t0=100)
        self.assertIn(("/f", "read", "p1"), triples(res))
        self.assertNotIn(("p2", "write", "/f"), triples(res))
        self.assertEqual(res["stats"]["empty_reads"], 1)

    def test_rules_drop_and_do_not_expand(self):
        """规则前移：动态库读取被剔除，且不从它的顶点往回找。"""
        poi = ev(1, "p2f", "write", "P1", "p1", "/poi", "File", start=200)
        lib = ev(2, "f2p", "read", "P1", "p1", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File",
                 start=100, end=100, nbytes=5)
        writer = ev(3, "p2f", "write", "P2", "p2", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File",
                    start=50)
        src = FakeSource(processes={"P1": [poi, lib], "P2": [writer]},
                         objects={("File", "/usr/lib/x86_64-linux-gnu/libc.so.6"): [writer]})
        res = C.run_closure(src, [poi], options=C.Options(), poi_t0=200)
        self.assertEqual(res["stats"]["dropped"].get("r1"), 1)
        self.assertNotIn(("/usr/lib/x86_64-linux-gnu/libc.so.6", "read", "p1"), triples(res))
        self.assertNotIn(("p2", "write", "/usr/lib/x86_64-linux-gnu/libc.so.6"), triples(res))

    def test_seed_is_never_dropped(self):
        """终点事件本身永远收进来（即使它命中规则）。"""
        poi = ev(1, "p2f", "write", "P1", "p1", "/usr/lib/x86_64-linux-gnu/libc.so.6", "File", start=100)
        src = FakeSource(processes={"P1": [poi]})
        res = C.run_closure(src, [poi], options=C.Options(), poi_t0=100)
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
        res = C.run_closure(src, [poi], options=C.Options(), poi_t0=210)
        self.assertIn(("c1", "write", "/side"), triples(res))

    def test_determinism(self):
        """同一输入跑两次，结果集合逐条相同。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=5)
        w1 = ev(2, "p2f", "write", "P2", "p2", "/f", "File", start=40)
        w2 = ev(3, "p2f", "write", "P3", "p3", "/f", "File", start=60)
        src = FakeSource(processes={"P1": [read], "P2": [w1], "P3": [w2]},
                         objects={("File", "/f"): [w1, w2]})
        first = C.run_closure(src, [read], options=C.Options(), poi_t0=100)
        second = C.run_closure(src, [read], options=C.Options(), poi_t0=100)
        self.assertEqual(triples(first), triples(second))
        self.assertEqual([e.event_id for e in first["events"]], [e.event_id for e in second["events"]])

    def test_rows_shape_for_fold(self):
        """输出行必须能被第 2 层折叠直接吃（字段齐全、方向正确）。"""
        read = ev(1, "f2p", "read", "P1", "p1", "/f", "File", start=100, end=100, nbytes=5)
        src = FakeSource(processes={"P1": [read]})
        res = C.run_closure(src, [read], options=C.Options(), poi_t0=100)
        row = res["rows"][0]
        self.assertEqual(row["rel"], "f2p")
        self.assertEqual(row["owner"], "p1")
        self.assertEqual(row["other"], "/f")
        self.assertTrue(row["step_key"].startswith("S:P1:"))


if __name__ == "__main__":
    unittest.main()
