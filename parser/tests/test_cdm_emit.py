import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm.emit import CdmEmitter, EventContext  # noqa: E402
from provenance.adapters.cdm.mapping import EventTable  # noqa: E402
from provenance.adapters.cdm.objects import (  # noqa: E402
    FileRec,
    NetRec,
    ObjectIndex,
    SubjectRec,
)
from provenance.core.kinds import Bucket, EdgeClass, FileKey, NetKey, ProcKey  # noqa: E402
from provenance.core.options import EmitOptions  # noqa: E402

HOST = "HOST-A"


def make_index() -> ObjectIndex:
    index = ObjectIndex()
    index.add_principal(
        {"uuid": "P-ROOT", "userId": "0", "properties": {"map": {"euid": "0"}}}
    )
    index.add_subject(SubjectRec(
        uuid="S-PARENT", host_id=HOST, pid=100, start_ns=1000,
        path="/usr/bin/firefox", cmdline="firefox", ppid=1, principal="P-ROOT",
    ))
    index.add_subject(SubjectRec(
        uuid="S-CHILD", host_id=HOST, pid=200, start_ns=2000,
        path="/usr/bin/bash", cmdline="bash", ppid=100, parent="S-PARENT",
        principal="P-ROOT",
    ))
    index.add_file(FileRec(
        uuid="F-1", host_id=HOST, path="/home/admin/cache", ftype="FILE_OBJECT_FILE",
    ))
    index.add_file(FileRec(
        uuid="F-2", host_id=HOST, path="/home/admin/cache.bak", ftype="FILE_OBJECT_FILE",
    ))
    index.add_netflow(NetRec(
        uuid="N-1", host_id=HOST,
        endpoints="10.0.0.5:40000->2.233.33.53:80", proto="tcp",
    ))
    return index


class EmitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = EventTable.load(ROOT / "data" / "cdm_events.toml")

    def setUp(self):
        self.index = make_index()
        self.emitter = CdmEmitter(HOST, self.index, EmitOptions(keep_payload=False))
        self.emitter.set_source_host(HOST)

    # -- 工具 ----------------------------------------------------------
    def ctx(self, etype, *, subject="S-PARENT", obj=None, obj2=None,
            rc=None, size=None, props=None, event_id=1, ts=5_000):
        obj_kind, obj_rec = (obj if obj else ("", None))
        obj2_kind, obj2_rec = (obj2 if obj2 else ("", None))
        return EventContext(
            event_id=event_id,
            ts_ns=ts,
            etype=etype,
            body={"size": {"long": size}} if size is not None else {},
            props=props or {},
            subject=self.index.subjects.get(subject) if subject else None,
            obj_kind=obj_kind,
            obj=obj_rec,
            obj2_kind=obj2_kind,
            obj2=obj2_rec,
            result_raw=rc,
        )

    def apply(self, etype, **kwargs):
        rule = self.table.get(etype)
        self.assertIsNotNone(rule, etype)
        return self.emitter.apply(rule, self.ctx(etype, **kwargs))

    # -- 数据流 --------------------------------------------------------
    def test_write_to_file(self):
        outcome, bucket, _ = self.apply(
            "EVENT_WRITE", obj=("file", self.index.files["F-1"]), rc=42,
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertEqual(len(outcome.edges), 1)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.P2F)
        self.assertEqual(edge.action, "write")
        self.assertEqual(edge.result, 42)
        self.assertEqual(edge.src, ProcKey(HOST, "", 100, 1000))
        self.assertEqual(edge.dst, FileKey(HOST, "", "/home/admin/cache"))
        # CDM 只有一个时刻：end_ns 必须等于 start_ns，不代表耗时
        self.assertEqual(edge.end_ns, edge.start_ns)
        self.assertIsNone(edge.payload_b64)

    def test_write_to_unnamed_object_is_no_object(self):
        outcome, bucket, reason = self.apply("EVENT_WRITE", obj=("", None), rc=10)
        self.assertIs(bucket, Bucket.NO_OBJECT)
        self.assertEqual(outcome.edges, [])
        self.assertIn("unnamed_object", reason)

    def test_read_from_file_uses_object_to_process_direction(self):
        outcome, bucket, _ = self.apply(
            "EVENT_READ", obj=("file", self.index.files["F-1"]), rc=8,
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.F2P)
        self.assertEqual(edge.src, FileKey(HOST, "", "/home/admin/cache"))
        self.assertEqual(edge.dst, ProcKey(HOST, "", 100, 1000))

    def test_connect_failure_keeps_negative_errno(self):
        outcome, bucket, _ = self.apply(
            "EVENT_CONNECT", obj=("net", self.index.nets["N-1"]), rc=-115,
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.P2N)
        self.assertEqual(edge.action, "connect")
        self.assertEqual(edge.result, -115)
        self.assertEqual(edge.dst, NetKey(HOST, "10.0.0.5:40000->2.233.33.53:80"))

    def test_sendmsg_over_unix_socket_goes_to_file(self):
        outcome, bucket, _ = self.apply(
            "EVENT_SENDMSG", obj=("file", self.index.files["F-1"]), rc=5,
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.P2F)
        self.assertEqual(edge.action, "send")
        self.assertEqual(edge.syscall, "sendto")

    def test_recvmsg_from_net_is_network_to_process(self):
        outcome, bucket, _ = self.apply(
            "EVENT_RECVMSG", obj=("net", self.index.nets["N-1"]), rc=7,
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertIs(outcome.edges[0].cls, EdgeClass.N2P)

    # -- 进程 ----------------------------------------------------------
    def test_clone_links_parent_to_child(self):
        outcome, bucket, _ = self.apply(
            "EVENT_CLONE", obj=("subject", self.index.subjects["S-CHILD"]),
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.P2P)
        self.assertEqual(edge.action, "clone")
        self.assertIsNone(edge.result)  # clone 的返回子 pid 不落 result

    def test_exit_uses_parent_subject(self):
        outcome, bucket, _ = self.apply(
            "EVENT_EXIT", subject="S-CHILD", obj=("subject", self.index.subjects["S-CHILD"]),
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertEqual(edge.src, ProcKey(HOST, "", 100, 1000))
        self.assertEqual(edge.dst, ProcKey(HOST, "", 200, 2000))

    def test_exit_falls_back_to_ppid(self):
        self.index.subjects["S-ORPHAN"] = SubjectRec(
            uuid="S-ORPHAN", host_id=HOST, pid=300, start_ns=3000, ppid=100,
        )
        outcome, bucket, _ = self.apply(
            "EVENT_EXIT", subject="S-ORPHAN", obj=("subject", self.index.subjects["S-ORPHAN"]),
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertEqual(outcome.edges[0].src, ProcKey(HOST, "", 100, 0))
        self.assertEqual(self.emitter.counts["parent_by_ppid"], 1)
        # 端点必须在 out.nodes 里：否则写库时 MATCH 不到，整条边被静默跳过
        keys = {node.key for node in outcome.nodes}
        self.assertIn(outcome.edges[0].src, keys)
        self.assertIn(outcome.edges[0].dst, keys)

    def test_every_edge_endpoint_is_registered(self):
        cases = [
            ("EVENT_WRITE", dict(obj=("file", self.index.files["F-1"]), rc=1)),
            ("EVENT_READ", dict(obj=("file", self.index.files["F-1"]), rc=1)),
            ("EVENT_CONNECT", dict(obj=("net", self.index.nets["N-1"]), rc=0)),
            ("EVENT_CLONE", dict(obj=("subject", self.index.subjects["S-CHILD"]))),
            ("EVENT_OPEN", dict(obj=("file", self.index.files["F-1"]))),
            ("EVENT_MMAP", dict(obj=("file", self.index.files["F-1"]), props={"protection": "PROT_EXEC"})),
            ("EVENT_RENAME", dict(obj=("file", self.index.files["F-1"]),
                                  obj2=("file", self.index.files["F-2"]), rc=0)),
        ]
        for etype, kwargs in cases:
            outcome, _bucket, _reason = self.apply(etype, **kwargs)
            keys = {node.key for node in outcome.nodes}
            for edge in outcome.edges:
                self.assertIn(edge.src, keys, f"{etype} 的 src 未登记")
                self.assertIn(edge.dst, keys, f"{etype} 的 dst 未登记")

    def test_exec_with_file_object(self):
        outcome, bucket, _ = self.apply(
            "EVENT_EXECUTE", obj=("file", self.index.files["F-1"]), rc=0,
        )
        self.assertIs(bucket, Bucket.COVERED)
        edge = outcome.edges[0]
        self.assertIs(edge.cls, EdgeClass.F2P)
        self.assertEqual(edge.action, "exec")
        self.assertEqual(edge.src, FileKey(HOST, "", "/home/admin/cache"))

    def test_exec_with_new_subject_emits_two_edges(self):
        outcome, bucket, _ = self.apply(
            "EVENT_EXECUTE", obj=("subject", self.index.subjects["S-CHILD"]), rc=0,
        )
        self.assertIs(bucket, Bucket.COVERED)
        actions = sorted((edge.cls.value, edge.action) for edge in outcome.edges)
        self.assertEqual(
            actions,
            [("FileToProcess", "exec"), ("ProcessToProcess", "exec")],
        )

    # -- 元数据 --------------------------------------------------------
    def test_open_only_registers_file_type(self):
        outcome, bucket, reason = self.apply(
            "EVENT_OPEN", obj=("file", self.index.files["F-1"]), rc=3,
        )
        self.assertIs(bucket, Bucket.ATTR)
        self.assertEqual(outcome.edges, [])
        self.assertEqual(reason, "file_type")
        self.assertEqual(len(outcome.nodes), 1)
        self.assertEqual(outcome.nodes[0].props["file_type"], "file")

    def test_mprotect_is_dropped_as_kernel_object(self):
        outcome, bucket, reason = self.apply("EVENT_MPROTECT", obj=("", None))
        self.assertIs(bucket, Bucket.DROP)
        self.assertEqual(reason, "kernel_object")
        self.assertEqual(outcome.edges, [])

    def test_open_without_path_is_no_object(self):
        self.index.files["F-NOPATH"] = FileRec(uuid="F-NOPATH", host_id=HOST)
        outcome, bucket, reason = self.apply(
            "EVENT_OPEN", obj=("file", self.index.files["F-NOPATH"]),
        )
        self.assertIs(bucket, Bucket.NO_OBJECT)
        self.assertEqual(reason, "file_path_missing")

    def test_mmap_prot_exec(self):
        outcome, bucket, _ = self.apply(
            "EVENT_MMAP", obj=("file", self.index.files["F-1"]),
            props={"protection": "PROT_READ|PROT_EXEC"}, rc=0,
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertEqual(outcome.edges[0].action, "mmap_exec")

    def test_mmap_shared_write(self):
        outcome, _, _ = self.apply(
            "EVENT_MMAP", obj=("file", self.index.files["F-1"]),
            props={"protection": "PROT_READ|PROT_WRITE", "flags": "MAP_SHARED"}, rc=0,
        )
        self.assertEqual(outcome.edges[0].action, "mmap_write")

    def test_rename_emits_forward_and_back_edges(self):
        outcome, bucket, _ = self.apply(
            "EVENT_RENAME",
            obj=("file", self.index.files["F-1"]),
            obj2=("file", self.index.files["F-2"]),
            rc=0,
        )
        self.assertIs(bucket, Bucket.COVERED)
        forward = [e for e in outcome.edges if e.cls is EdgeClass.P2F]
        backward = [e for e in outcome.edges if e.cls is EdgeClass.F2P]
        self.assertEqual(len(forward), 1)
        self.assertEqual(len(backward), 1)
        self.assertEqual(forward[0].dst, FileKey(HOST, "", "/home/admin/cache.bak"))
        self.assertEqual(forward[0].to_path, "/home/admin/cache")
        self.assertEqual(backward[0].src, FileKey(HOST, "", "/home/admin/cache"))

    def test_rename_without_target_path_keeps_source_only(self):
        outcome, bucket, reason = self.apply(
            "EVENT_RENAME", obj=("file", self.index.files["F-1"]), rc=0,
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertEqual(reason, "rename_target_missing")
        self.assertEqual(len(outcome.edges), 1)
        self.assertIs(outcome.edges[0].cls, EdgeClass.F2P)

    def test_unknown_subject_is_no_owner(self):
        outcome, bucket, reason = self.apply("EVENT_WRITE", subject=None,
                                            obj=("file", self.index.files["F-1"]))
        self.assertIs(bucket, Bucket.NO_OWNER)
        self.assertEqual(reason, "subject_unseen")

    def test_success_gate_without_result_emits_edge_and_marks_unknown(self):
        """没有返回值：不声称成功，但也不抹掉事件（TRACE 全档 create 29,887 条靠这条）。"""
        outcome, bucket, _ = self.apply(
            "EVENT_CREATE_OBJECT", obj=("file", self.index.files["F-1"]),
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertEqual(len(outcome.edges), 1)
        self.assertIsNone(outcome.edges[0].result)
        self.assertEqual(self.emitter.counts["result_absent_edges"], 1)

    def test_mmap_success_address_not_written_to_result(self):
        """mmap 成功返回内存地址，地址不得落 result（它不是字节数）。"""
        outcome, bucket, _ = self.apply(
            "EVENT_MMAP", obj=("file", self.index.files["F-1"]),
            props={"protection": "PROT_READ"}, rc=140_733_000_000_000,
        )
        self.assertIs(bucket, Bucket.COVERED)
        self.assertIsNone(outcome.edges[0].result)

    def test_mmap_failure_keeps_errno(self):
        outcome, _, _ = self.apply(
            "EVENT_MMAP", obj=("file", self.index.files["F-1"]),
            props={"protection": "PROT_READ"}, rc=-12,
        )
        self.assertEqual(outcome.edges[0].result, -12)

    def test_success_gate_with_failure_rc_is_attempt(self):
        outcome, bucket, _ = self.apply(
            "EVENT_CREATE_OBJECT", obj=("file", self.index.files["F-1"]), rc=-13,
        )
        self.assertIs(bucket, Bucket.ATTEMPT)
        self.assertEqual(outcome.edges, [])

    def test_self_loop_is_not_written(self):
        outcome, bucket, _ = self.apply(
            "EVENT_SIGNAL", obj=("subject", self.index.subjects["S-PARENT"]),
        )
        self.assertEqual(outcome.edges, [])
        self.assertIs(bucket, Bucket.OTHER)
        self.assertEqual(self.emitter.counts["self_loop"], 1)


if __name__ == "__main__":
    unittest.main()
