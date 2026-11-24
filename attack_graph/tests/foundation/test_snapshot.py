"""单文件 .tsg 索引与内存参照图的逐条等价单测（完全离线，零数据库依赖）。"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import settings as cfg  # noqa: E402
from closure import traversal as C  # noqa: E402
from closure.policy import event_ruling, object_ruling  # noqa: E402
from closure.snapshot import TSGSource  # noqa: E402
from domain.edge import PRODUCER_RELS, labels_of, owner_is_source  # noqa: E402

if str(cfg.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(cfg.REPO_ROOT))
from tsg.format import TSGWriter  # noqa: E402


class MemoryReferenceSource:
    """纯内存参照图来源（用于与 TSGSource 逐条对拍，不依赖 Neo4j）。"""

    def __init__(self, processes: list[dict], files: list[dict], networks: list[dict], edges: list[tuple]) -> None:
        self.database = "unit-test-tsg"
        self.processes = {p["key"]: p for p in processes}
        self.files = {f["key"]: f for f in files}
        self.networks = {n["key"]: n for n in networks}
        self.edges = list(edges)
        self.nondelivery_not_expanded: dict[str, int] = {}

    def _content(self, kind: str, key: str) -> str:
        table = {"Process": self.processes, "File": self.files, "Network": self.networks}[kind]
        return str((table.get(key) or {}).get("content") or key)

    def _to_event(self, e: tuple) -> C.Event:
        rel, eid, start, end, syscall, nbytes, a_key, b_key = e
        kind_a, kind_b = labels_of(rel)
        if owner_is_source(rel):
            pid, owner = a_key, self._content(kind_a, a_key)
            other_label = kind_b
            other = b_key if other_label in ("File", "Network") else self._content(kind_b, b_key)
            other_pid = b_key if other_label == "Process" else ""
        else:
            pid, owner = b_key, self._content(kind_b, b_key)
            other_label = kind_a
            other = a_key if other_label in ("File", "Network") else self._content(kind_a, a_key)
            other_pid = a_key if other_label == "Process" else ""
        return C.Event(
            event_id=eid, rel=rel, syscall=syscall, bytes=nbytes, start=start, end=end,
            pid=pid, owner=owner, other=other, other_label=other_label, other_process_id=other_pid,
        )

    def parent_of_process(self, key: str):
        return None

    def birth_of_process(self, key: str) -> int:
        return 0

    def expand_process(self, items: list[tuple[str, int, int]], seen=None) -> list[C.Event]:
        out: list[C.Event] = []
        for key, lo, hi in items:
            for e in self.edges:
                rel, eid, start, _end, _sc, _nb, a_key, b_key = e
                if not lo < start <= hi:
                    continue
                owner = a_key if rel in PRODUCER_RELS else b_key
                if not (owner == key or (rel == "p2p" and a_key == key)):
                    continue
                if seen is not None and (eid, rel) in seen:
                    continue
                out.append(self._to_event(e))
        return out

    def expand_object(self, items: list[tuple[str, int, int]], kind: str, seen=None) -> list[C.Event]:
        out: list[C.Event] = []
        target_rel = "p2f" if kind == "File" else "p2n"
        for key, lo, hi in items:
            if kind == "File":
                ruling = object_ruling(key)
                if "no_expand" in ruling.effects:
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
            for e in self.edges:
                rel, eid, start, _end, sc, nb, _a, b_key = e
                if rel != target_rel or b_key != key or not lo < start <= hi:
                    continue
                if "not_delivery" in event_ruling(rel, sc, nb).effects:
                    continue
                if seen is not None and (eid, rel) in seen:
                    continue
                out.append(self._to_event(e))
        return out

    def close(self) -> None:
        return None


def event_key(ev: C.Event) -> tuple:
    return (ev.event_id, ev.rel, ev.syscall, ev.bytes, ev.start, ev.end, ev.pid, ev.owner,
            ev.other, ev.other_label, ev.other_process_id)


class SnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tsg_path = Path(cls._tmp.name) / "unit.tsg"
        cls.processes = [
            {"key": "1p1", "content": "/p1", "pid": 1, "name": "p1", "exepath": "/p1", "args": "-x", "host_id": "h"},
            {"key": "2p2", "content": "/p2", "pid": 2, "name": "p2", "exepath": "/p2", "args": "", "host_id": "h"},
            {"key": "3p3", "content": "/p3", "pid": 3, "name": "p3", "exepath": "/p3", "args": "", "host_id": "h"},
        ]
        cls.files = [
            {"key": "/f", "content": "/f", "host_id": "h", "file_type": "file"},
            {"key": "pipe:[1]", "content": "pipe:[1]", "host_id": "h", "file_type": "pipe"},
            {"key": "/proc/1/limits", "content": "/proc/1/limits", "host_id": "h", "file_type": "file"},
        ]
        cls.networks = [
            {"key": "10.0.0.1:1->10.0.0.2:2", "content": "10.0.0.1:1->10.0.0.2:2", "protocol": "tcp", "host_id": "h"},
        ]
        cls.edges = [
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
        w = TSGWriter(cls.tsg_path, scenario="unit", database="unit-v2")
        for p in cls.processes:
            w.add_vertex("Process", p["key"], p)
        for f in cls.files:
            w.add_vertex("File", f["key"], f)
        for n in cls.networks:
            w.add_vertex("Network", n["key"], n)
        for rel, eid, st, en, sc, nb, a_key, b_key in cls.edges:
            ka, kb = labels_of(rel)
            w.add_edge(
                rel=rel, src_kind=ka, src_key=a_key, dst_kind=kb, dst_key=b_key,
                event_id=eid, start_ns=st, end_ns=en, syscall=sc, action=sc, bytes_val=nb,
            )
        cls.meta = w.finish()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _ref(self) -> MemoryReferenceSource:
        return MemoryReferenceSource(self.processes, self.files, self.networks, self.edges)

    def test_meta_and_single_file(self) -> None:
        self.assertEqual(self.meta["edges"], len(self.edges))
        self.assertTrue(self.tsg_path.is_file())
        self.assertEqual([p.name for p in self.tsg_path.parent.iterdir()], ["unit.tsg"])

    def test_memory_and_tsg_agree(self) -> None:
        cases = [
            ("process", [("1p1", -1, 10 ** 15), ("2p2", -1, 10 ** 15)], None),
            ("object_file", [("/f", -1, 10 ** 15)], "File"),
            ("object_net", [("10.0.0.1:1->10.0.0.2:2", -1, 10 ** 15)], "Network"),
            ("window", [("1p1", 100, 10 ** 15)], None),
        ]
        ref = self._ref()
        idx = TSGSource(self.tsg_path)
        try:
            for name, items, kind in cases:
                if kind is None:
                    a = sorted(event_key(e) for e in ref.expand_process(items))
                    b = sorted(event_key(e) for e in idx.expand_process(items))
                else:
                    a = sorted(event_key(e) for e in ref.expand_object(items, kind))
                    b = sorted(event_key(e) for e in idx.expand_object(items, kind))
                self.assertEqual(a, b, name)
        finally:
            idx.close()

    def test_network_protocol_and_process_info(self) -> None:
        idx = TSGSource(self.tsg_path)
        try:
            self.assertEqual(idx.network_protocols(), {"10.0.0.1:1->10.0.0.2:2": "tcp"})
            info = idx.process_info("1p1")
            self.assertEqual(info["exepath"], "/p1")
            self.assertEqual(info["args"], "-x")
            self.assertEqual(idx.process_info("missing"), {})
        finally:
            idx.close()

    def test_connect_is_not_delivery(self) -> None:
        idx = TSGSource(self.tsg_path)
        try:
            events = idx.expand_object([("pipe:[1]", -1, 10 ** 15)], "File")
            self.assertEqual([e.event_id for e in events], [7])
        finally:
            idx.close()

    def test_nondelivery_not_expanded(self) -> None:
        ref = self._ref()
        idx = TSGSource(self.tsg_path)
        try:
            self.assertEqual(ref.expand_object([("/proc/1/limits", -1, 10 ** 15)], "File"), [])
            self.assertEqual(idx.expand_object([("/proc/1/limits", -1, 10 ** 15)], "File"), [])
            self.assertEqual(ref.nondelivery_not_expanded, idx.nondelivery_not_expanded)
        finally:
            idx.close()

    def test_nondelivery_read_kept_but_no_upstream(self) -> None:
        read = C.Event(event_id=9, rel="f2p", syscall="read", bytes=4, start=160, end=165,
                       pid="1p1", owner="/p1", other="/proc/1/limits", other_label="File")
        idx = TSGSource(self.tsg_path)
        try:
            res = C.run_closure(idx, [read], poi_t0=160)
            ids = [e.event_id for e in res["events"]]
            self.assertIn(9, ids)
            self.assertNotIn(8, ids)
            self.assertGreaterEqual(sum(idx.nondelivery_not_expanded.values()), 1)
        finally:
            idx.close()

    def test_parent_side_spawn_included(self) -> None:
        idx = TSGSource(self.tsg_path)
        try:
            self.assertIn(3, [e.event_id for e in idx.expand_process([("1p1", -1, 10 ** 15)])])
            self.assertIn(3, [e.event_id for e in idx.expand_process([("2p2", -1, 10 ** 15)])])
        finally:
            idx.close()

    def test_index_closure_matches_memory_closure(self) -> None:
        seed = C.Event(event_id=2, rel="f2p", syscall="read", bytes=7, start=100, end=105,
                       pid="1p1", owner="/p1", other="/f", other_label="File")
        ref = self._ref()
        idx = TSGSource(self.tsg_path)
        try:
            a = C.run_closure(ref, [seed], poi_t0=100)
            b = C.run_closure(idx, [seed], poi_t0=100)
        finally:
            idx.close()
        self.assertEqual(sorted(event_key(e) for e in a["events"]),
                         sorted(event_key(e) for e in b["events"]))


class AtomicBuildTest(unittest.TestCase):
    def test_aborted_tsg_build_leaves_no_file_and_no_temp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsg_path = Path(tmp) / "fail.tsg"
            w = TSGWriter(tsg_path, scenario="fail")
            w.add_vertex("Process", "h|host|1|1", {"content": "/p1"})
            w.abort()
            self.assertFalse(tsg_path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
