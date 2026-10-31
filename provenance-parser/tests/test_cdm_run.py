import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm.mapping import EventTable  # noqa: E402
from provenance.adapters.cdm.run import CdmRunOptions, run_cdm  # noqa: E402
from provenance.core.options import EmitOptions, GraphLimits  # noqa: E402

HOST = "HOST-T"
BASE_NS = 1_523_378_600_000_000_000


class FakeGraph:
    """最小图出口：只实现 run_cdm 用到的三个方法。"""

    class Snapshot:
        def __init__(self, nodes):
            self.total = len(nodes)
            self.by_label = {}
            for node in nodes:
                label = type(node.key).__name__.replace("Key", "")
                self.by_label[label] = self.by_label.get(label, 0) + 1
            self.written_nodes = len(nodes)
            self.written_edges = 0

    def __init__(self):
        self.nodes = {}
        self.outcomes = 0

    def add(self, outcome):
        self.outcomes += 1
        for node in outcome.nodes:
            self.nodes.setdefault(node.key, node)

    def flush(self):
        return None

    def snapshot(self):
        return self.Snapshot(self.nodes.values())


def _record(datum_type: str, body: dict) -> bytes:
    payload = {
        "datum": {f"com.bbn.tc.schema.avro.cdm18.{datum_type}": body},
        "CDMVersion": "18",
        "source": "SOURCE_LINUX_THEIA",
    }
    return (json.dumps(payload) + "\n").encode()


def _subject(uuid: str, pid: int, start_ns: int) -> bytes:
    return _record("Subject", {
        "uuid": uuid, "type": "SUBJECT_PROCESS", "cid": pid,
        "parentSubject": None, "hostId": HOST, "localPrincipal": None,
        "startTimestampNanos": start_ns, "cmdLine": None,
        "properties": {"map": {"ppid": "1", "path": "/usr/bin/firefox"}},
    })


def _file(uuid: str, path: str) -> bytes:
    return _record("FileObject", {
        "uuid": uuid,
        "baseObject": {"hostId": HOST, "properties": {"map": {"path": path}}},
        "type": "FILE_OBJECT_FILE",
    })


def _write(uuid: str, subject: str, obj: str, ts: int, size: int) -> bytes:
    return _record("Event", {
        "uuid": uuid, "sequence": {"long": 1}, "type": "EVENT_WRITE",
        "threadId": {"int": 1}, "hostId": HOST,
        "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": subject},
        "predicateObject": {"com.bbn.tc.schema.avro.cdm18.UUID": obj},
        "predicateObject2": None,
        "timestampNanos": ts, "size": {"long": size},
        "properties": {"map": {"rc": str(size)}},
    })


def _mprotect(uuid: str, subject: str, ts: int) -> bytes:
    return _record("Event", {
        "uuid": uuid, "sequence": {"long": 1}, "type": "EVENT_MPROTECT",
        "threadId": {"int": 1}, "hostId": HOST,
        "subject": {"com.bbn.tc.schema.avro.cdm18.UUID": subject},
        "predicateObject": None, "predicateObject2": None,
        "timestampNanos": ts, "properties": {"map": {}},
    })


def _pack(path: Path, members: list[tuple[str, list[bytes]]]) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, lines in members:
            payload = b"".join(lines)
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


class RunOrderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = EventTable.load(ROOT / "data" / "cdm_events.toml")

    def _archive(self, tmp: str) -> Path:
        path = Path(tmp) / "order.tar.gz"
        # 物理顺序故意写成 .2 在前、.1 在后（与 THEIA 归档的 .1,.10,…,.2 同形态）
        member_two = [
            _subject("S-2", 200, BASE_NS + 20),
            _file("F-2", "/tmp/b"),
            _write("E-2", "S-2", "F-2", BASE_NS + 20, 20),
        ]
        member_one = [
            _subject("S-1", 100, BASE_NS + 10),
            _file("F-1", "/tmp/a"),
            _write("E-1", "S-1", "F-1", BASE_NS + 10, 10),
        ]
        _pack(path, [("x.json.2", member_two), ("x.json.1", member_one)])
        return path

    def _run(self, archive: Path, tmp: str, *, sort_members: bool):
        options = CdmRunOptions(
            scenario="ORDER",
            host_id=HOST,
            archive=str(archive),
            database="db",
            dry_run=True,
            member_from=1,
            member_to=2,
            sort_members=sort_members,
            out_dir=str(Path(tmp) / ("sorted" if sort_members else "tar")),
            progress_every_s=3600,
        )
        graph = FakeGraph()
        payload = run_cdm(options, GraphLimits(), EmitOptions(keep_payload=False),
                          self.table, graph)
        return payload, graph

    def test_tar_order_is_reported_as_non_monotonic(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(tmp)
            payload, graph = self._run(archive, tmp, sort_members=False)
        self.assertEqual(payload["member_order"]["mode"], "tar")
        self.assertFalse(payload["member_order"]["time_monotonic"])
        self.assertEqual(payload["graph"]["edges"], 2)
        # 两个成员各一个进程 + 一个文件
        self.assertEqual(len(graph.nodes), 4)

    def test_sorted_order_is_monotonic(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(tmp)
            payload, graph = self._run(archive, tmp, sort_members=True)
        self.assertEqual(payload["member_order"]["mode"], "sorted")
        self.assertTrue(payload["member_order"]["time_monotonic"])
        self.assertEqual(payload["graph"]["edges"], 2)

    def test_ledger_balances_and_results_carry_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(tmp)
            payload, _ = self._run(archive, tmp, sort_members=True)
        events = payload["events"]
        self.assertTrue(events["balanced"])
        self.assertEqual(events["ingested"], 2)
        self.assertEqual(events["result_present"]["rc"], 2)
        self.assertEqual(payload["gaps"]["result_absent"], 0)


class BucketPriorityTest(unittest.TestCase):
    """主体缺失不能吞掉「内核对象无名」这类与主体无关的结论。"""

    @classmethod
    def setUpClass(cls):
        cls.table = EventTable.load(ROOT / "data" / "cdm_events.toml")

    def test_mprotect_with_unknown_subject_stays_drop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prio.tar.gz"
            _pack(path, [("x.json", [
                _subject("S-1", 100, BASE_NS),
                _file("F-1", "/tmp/a"),
                _write("E-1", "S-1", "F-1", BASE_NS + 1, 10),
                _mprotect("E-2", "S-MISSING", BASE_NS + 2),
                _write("E-3", "S-MISSING", "F-1", BASE_NS + 3, 5),
            ])])
            options = CdmRunOptions(
                scenario="PRIO", host_id=HOST, archive=str(path), database="db",
                dry_run=True, out_dir=str(Path(tmp) / "out"), progress_every_s=3600,
            )
            payload = run_cdm(options, GraphLimits(), EmitOptions(keep_payload=False),
                              self.table, FakeGraph())
        buckets = payload["events"]["buckets"]
        # MPROTECT 客体是内存对象：即使主体查不到，结论仍是「内核对象无名」
        self.assertEqual(buckets.get("显式丢弃"), 1)
        self.assertEqual(payload["events"]["unmapped_table_missing"], {})
        # 需要建边的 WRITE 主体查不到 -> 无进程归属
        self.assertEqual(buckets.get("无进程归属"), 1)


if __name__ == "__main__":
    unittest.main()
