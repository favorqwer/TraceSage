"""顶点-时间索引快照的单测：格式往返 + 与数据库直查逐条等价（不需要真数据库）。

用一个小型内存假库驱动两条来源：`DbSource`（跑那几条 Cypher 文本）与 `SnapshotReader`
（跑二进制索引），对同一批顶点、同一批门限比对事件集合必须**完全相同**。
"""

from __future__ import annotations

import unittest

from foundation.layers.l1_reach import graph_index as snap
from foundation.layers.l1_reach import walk as C
from foundation.layers.l1_reach.walk import SnapshotReader
from tests.foundation.db_source import DbSource

DB = "unit-test-index"


class StubGraph:
    """最小假库：只认快照构建器用到的那几条查询文本。"""

    database = DB

    def __init__(self):
        self.processes = [
            {"key": "1p1", "content": "/p1", "pid": "1", "name": "p1", "exepath": "/p1",
             "args": "-x", "cwd": "/"},
            {"key": "2p2", "content": "/p2", "pid": "2", "name": "p2", "exepath": "/p2",
             "args": "", "cwd": "/tmp"},
            {"key": "3p3", "content": "/p3", "pid": "3", "name": "p3", "exepath": "/p3",
             "args": "", "cwd": "/"},
        ]
        self.files = [{"key": "/f", "content": "/f"}, {"key": "pipe:[1]", "content": "pipe:[1]"},
                      {"key": "/proc/1/limits", "content": "/proc/1/limits"}]
        self.networks = [{"key": "10.0.0.1:1->10.0.0.2:2", "content": "10.0.0.1:1->10.0.0.2:2",
                         "protocol": "tcp"}]
        # (rel, event_id, start, end, syscall, bytes, a_key, b_key)
        self.edges = [
            ("p2f", 1, 40, 40, "write", 10, "2p2", "/f"),
            ("f2p", 2, 100, 105, "read", 7, "/f", "1p1"),
            ("p2p", 3, 30, 900, "clone", 0, "1p1", "2p2"),
            ("p2n", 4, 110, 110, "sendto", 5, "1p1", "10.0.0.1:1->10.0.0.2:2"),
            ("n2p", 5, 120, 120, "recvfrom", 5, "10.0.0.1:1->10.0.0.2:2", "1p1"),
            ("p2f", 6, 130, 130, "connect", 0, "1p1", "pipe:[1]"),
            ("p2f", 7, 140, 140, "write", 3, "1p1", "pipe:[1]"),
            ("p2f", 8, 150, 150, "write", 4, "3p3", "/proc/1/limits"),
            ("f2p", 9, 160, 165, "read", 4, "/proc/1/limits", "1p1"),
        ]

    def _content(self, key):
        for group in (self.processes, self.files, self.networks):
            for item in group:
                if item["key"] == key:
                    return str(item["content"])
        return key

    def _kind_of(self, key):
        for group, kind in ((self.processes, "Process"), (self.files, "File"),
                            (self.networks, "Network")):
            if any(item["key"] == key for item in group):
                return kind
        return ""

    def _row(self, rel, e):
        """按真实查询的列契约拼行：owner 是拥有这条边的进程，other 是另一端。"""
        _, event_id, start, end, syscall, nbytes, a_key, b_key = e
        if rel in ("p2f", "p2n"):
            pid, other_key = a_key, b_key
        elif rel in ("f2p", "n2p"):
            pid, other_key = b_key, a_key
        else:                                        # p2p：归子进程，另一端是父进程
            pid, other_key = b_key, a_key
        return {"event_id": event_id, "starttime": start, "endtime": end, "syscall": syscall,
                "bytes": nbytes, "rel": rel, "pid": pid, "owner": self._content(pid),
                "other": self._content(other_key), "other_label": self._kind_of(other_key),
                "other_process_id": a_key if rel == "p2p" else ""}

    def _incident(self, rel, e, key):
        """这条边是不是"以 key 为拥有者"（进程展开用）。"""
        _, _, _, _, _, _, a_key, b_key = e
        owner = a_key if rel in ("p2f", "p2n") else b_key
        return owner == key

    def run(self, cypher, params=None):
        params = params or {}
        if "RETURN count(e) AS edges" in cypher:
            return [{"edges": len(self.edges), "max_event_id": max(e[1] for e in self.edges)}]
        if "MATCH (p:Process) RETURN" in cypher:
            return list(self.processes)
        if "MATCH (f:File) RETURN" in cypher:
            return list(self.files)
        if "MATCH (n:Network) RETURN" in cypher:
            return list(self.networks)
        if "AS rel, e.syscall AS syscall" in cypher:
            # 进程读写过的对象端点（子进程把关用）
            pid = str(params.get("pid") or "")
            out = []
            for e in self.edges:
                rel = e[0]
                if rel not in ("p2f", "f2p", "p2n", "n2p") or not self._incident(rel, e, pid):
                    continue
                other_key = e[7] if rel in ("p2f", "p2n") else e[6]
                out.append({"rel": rel, "syscall": e[4], "key": self._content(other_key),
                            "label": self._kind_of(other_key)})
            return out
        if "UNWIND $items AS it" in cypher:
            out = []
            for item in params.get("items", []):
                key, lo, hi = str(item["key"]), int(item["lo"]), int(item["hi"])
                for e in self.edges:
                    rel, start = e[0], e[2]
                    if not lo < start <= hi:
                        continue
                    if "File {file_id: it.key}" in cypher:
                        if rel != "p2f" or e[7] != key:
                            continue
                    elif "Network {network_id: it.key}" in cypher:
                        if rel != "p2n" or e[7] != key:
                            continue
                    elif "(p:Process {process_id: it.key})" in cypher:
                        # 进程展开：自己拥有的边 + 派生边的父进程那一侧（同主体子进程）
                        if not (self._incident(rel, e, key) or (rel == "p2p" and e[6] == key)):
                            continue
                    else:
                        continue
                    out.append(self._row(rel, e))
            return out
        for rel in ("p2f", "f2p", "p2n", "n2p", "p2p"):
            if f"[e:{rel}]" in cypher or f"|{rel}]" in cypher:
                last, limit = int(params.get("last", 0)), int(params.get("limit", 1000))
                rows = [e for e in self.edges if e[0] == rel and e[1] > last][:limit]
                return [{"event_id": e[1], "starttime": e[2], "endtime": e[3],
                         "syscall": e[4], "bytes": e[5], "a_key": e[6], "b_key": e[7]}
                        for e in rows]
        return []

    def close(self):
        return None


def event_key(ev):
    """逐字段比对用（两条来源必须给出同一个事件）。"""
    return (ev.event_id, ev.rel, ev.syscall, ev.bytes, ev.start, ev.end, ev.pid, ev.owner,
            ev.other, ev.other_label, ev.other_process_id)


class SnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = StubGraph()
        cls.meta = snap.build_snapshot(cls.graph, log=lambda *_: None)

    def test_meta_and_files(self):
        self.assertEqual(self.meta["format"], snap.FORMAT_VERSION)
        self.assertEqual(self.meta["edges"], len(self.graph.edges))
        for name in ("meta.json", "vertices.json", "offsets.json", "adj.bin"):
            self.assertTrue((snap.snapshot_dir(DB) / name).is_file(), name)

    def test_db_and_index_agree(self):
        """两条来源对同一批顶点、同一批门限给出完全相同的事件集合。"""
        cases = [("process", [("1p1", -1, 10 ** 15), ("2p2", -1, 10 ** 15)], None),
                 ("object_file", [("/f", -1, 10 ** 15)], "File"),
                 ("object_net", [("10.0.0.1:1->10.0.0.2:2", -1, 10 ** 15)], "Network"),
                 ("window", [("1p1", 100, 10 ** 15)], None)]
        db = DbSource(self.graph)
        idx = SnapshotReader(DB)
        try:
            for name, items, kind in cases:
                if kind is None:
                    a = sorted(event_key(e) for e in db.expand_process(items))
                    b = sorted(event_key(e) for e in idx.expand_process(items))
                else:
                    a = sorted(event_key(e) for e in db.expand_object(items, kind))
                    b = sorted(event_key(e) for e in idx.expand_object(items, kind))
                self.assertEqual(a, b, name)
        finally:
            db.close()
            idx.close()

    def test_network_protocol_in_vertices(self):
        """网络顶点的传输层协议要进索引顶点表，并可按端点查回来。"""
        idx = SnapshotReader(DB)
        try:
            self.assertEqual(idx.network_protocols(), {"10.0.0.1:1->10.0.0.2:2": "tcp"})
            vid = idx._id_of[("Network", "10.0.0.1:1->10.0.0.2:2")]
            self.assertEqual(idx.vertices[vid].get("protocol"), "tcp")
        finally:
            idx.close()

    def test_connect_is_not_delivery(self):
        """连接建立不算交付：管道上的 connect 边不进"写入侧"，write 边进。"""
        idx = SnapshotReader(DB)
        try:
            events = idx.expand_object([("pipe:[1]", -1, 10 ** 15)], "File")
            self.assertEqual([e.event_id for e in events], [7])
        finally:
            idx.close()

    def test_nondelivery_not_expanded(self):
        """非交付通道：只收边、不展开（两条来源都必须如此，并各自计数）。"""
        db = DbSource(self.graph)
        idx = SnapshotReader(DB)
        try:
            self.assertEqual(db.expand_object([("/proc/1/limits", -1, 10 ** 15)], "File"), [])
            self.assertEqual(idx.expand_object([("/proc/1/limits", -1, 10 ** 15)], "File"), [])
            self.assertEqual(sum(db.nondelivery_not_expanded.values()), 1)
            self.assertEqual(sum(idx.nondelivery_not_expanded.values()), 1)
            self.assertEqual(db.nondelivery_not_expanded, idx.nondelivery_not_expanded)
        finally:
            db.close()
            idx.close()

    def test_nondelivery_read_kept_but_no_upstream(self):
        """从非交付通道读：这条读边照收（它是链上的真实操作），但不把写过它的别的进程拉进来。"""
        read = C.Event(event_id=9, rel="f2p", syscall="read", bytes=4, start=160, end=165,
                       pid="1p1", owner="/p1", other="/proc/1/limits", other_label="File")
        idx = SnapshotReader(DB)
        try:
            res = C.run_closure(idx, [read], poi_t0=160)
            ids = [e.event_id for e in res["events"]]
            self.assertIn(9, ids, "读取非交付通道的那条边必须收进来")
            self.assertNotIn(8, ids, "不该沿非交付通道往回找写入者（那个写者没有别的理由在链上）")
            self.assertGreaterEqual(sum(idx.nondelivery_not_expanded.values()), 1,
                                    "跑闭包的经过里必须真的跳过了非交付通道")
        finally:
            idx.close()

    def test_parent_side_spawn_included(self):
        """派生边的父进程那一侧也收（同主体子进程算上游，机制恒开）。"""
        idx = SnapshotReader(DB)
        try:
            self.assertIn(3, [e.event_id for e in idx.expand_process([("1p1", -1, 10 ** 15)])])
            self.assertIn(3, [e.event_id for e in idx.expand_process([("2p2", -1, 10 ** 15)])])
        finally:
            idx.close()

    def test_index_closure_matches_db_closure(self):
        """整条闭包在两条来源上一致（拿同一个种子跑）。"""
        seed = C.Event(event_id=2, rel="f2p", syscall="read", bytes=7, start=100, end=105,
                       pid="1p1", owner="/p1", other="/f", other_label="File")
        db = DbSource(self.graph)
        idx = SnapshotReader(DB)
        try:
            a = C.run_closure(db, [seed], poi_t0=100)
            b = C.run_closure(idx, [seed], poi_t0=100)
        finally:
            db.close()
            idx.close()
        self.assertEqual(sorted(event_key(e) for e in a["events"]),
                         sorted(event_key(e) for e in b["events"]))


class FailingGraph(StubGraph):
    """边导出到第 n 次查询时抛错：模拟索引构造中途失败。"""

    database = "unit-test-fail-index"

    def __init__(self, fail_at_edge_query: int = 0):
        """`fail_at_edge_query=0` 表示不失败（用于先建一份可用的索引）。"""
        super().__init__()
        self.fail_at = fail_at_edge_query
        self.edge_queries = 0

    def run(self, cypher, params=None):
        if "ORDER BY e.event_id" in cypher:
            self.edge_queries += 1
            if self.fail_at and self.edge_queries >= self.fail_at:
                raise RuntimeError("模拟：边导出中途失败")
        return super().run(cypher, params)


class AtomicBuildTest(unittest.TestCase):
    """构造中途失败：不能再留下一个“可用”的索引，也不能留下临时文件。"""

    def test_failed_build_leaves_no_index_and_no_temp(self):
        graph = FailingGraph()
        snap.build_snapshot(graph, log=lambda *_: None)                 # 先成功建一次
        self.assertIsNotNone(snap.read_meta(graph.database))

        with self.assertRaises(RuntimeError):
            snap.build_snapshot(FailingGraph(fail_at_edge_query=3), log=lambda *_: None)

        # 描述文件是“这份索引可用”的唯一标记：失败后必须已撤掉，下次运行才会重建
        self.assertIsNone(snap.read_meta(graph.database), "失败后描述文件应已撤掉")
        leftovers = sorted(p.name for p in snap.snapshot_dir(graph.database).glob("*.tmp"))
        self.assertEqual(leftovers, [], f"失败后仍有临时文件：{leftovers}")


if __name__ == "__main__":
    unittest.main()
