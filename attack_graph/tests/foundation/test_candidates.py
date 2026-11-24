"""候选表单测（不需要数据库、不需要模型）：折叠。

口径（`closure/fold.py`）：折叠只合并不删边——把同一内容三元组的多个事件实例压成一条记录，
实例数、字节数、首末时刻、事件编号、两端身份与入闭包通道都按同一口径汇总，**不做任何判定**。
唯一例外是进程启动期读入且全图未被写入的动态库读取，命中条数单独计入 `dropped_startup_reads`。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import closure.fold as OF


def row(event_id: int, *, pid: str = "7sshd", rel: str = "f2p", other: str = "/etc/passwd",
        syscall: str = "read", at: int = 10, other_process_id: str = "", support: int = 8,
        effect: str = "") -> dict:
    """一条候选边行：只带折叠会看的字段。"""
    return {"event_id": event_id, "rel": rel, "syscall": syscall, "owner": "/usr/sbin/sshd",
            "other": other, "other_label": "Process" if rel == "p2p" else "File",
            "process_id": pid, "other_process_id": other_process_id,
            "starttime": at, "endtime": at + 1, "bytes": 0, "dist": 1, "support": support,
            "via_kind": "", "via_key": "", "effect": effect}


class FoldTest(unittest.TestCase):
    def test_fold_collects_effects(self) -> None:
        """同一三元组的多条实例成败不同：折叠保留集合，不猜唯一值。"""
        rows = [row(1, other="/tmp/x", effect="success"),
                row(2, other="/tmp/x", effect="failure"),
                row(3, other="/tmp/x", effect="success")]
        edge = OF.fold(rows).edges[0]
        self.assertEqual(edge.effects, {"success", "failure"})
        self.assertEqual(edge.to_dict()["effects"], ["failure", "success"])

    def test_fold_without_effect_keeps_empty_set(self) -> None:
        edge = OF.fold([row(1, other="/tmp/y")]).edges[0]
        self.assertEqual(edge.effects, set())
        self.assertEqual(edge.to_dict()["effects"], [])

    def test_fold_merges_same_triple(self) -> None:
        rows = [row(1, pid="100bash", other="/home/u/x", at=10),
                row(2, pid="100bash", other="/home/u/x", at=20)]
        result = OF.fold(rows)
        self.assertEqual(result.raw_instances, 2)
        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.edges[0].instances, 2)
        self.assertEqual(result.edges[0].event_ids, [1, 2])
        self.assertEqual(result.edges[0].t0, 10)
        self.assertTrue(result.edges[0].channels)

    def test_fold_keeps_triples_apart_and_merges_channels(self) -> None:
        """不同三元组各成一条；同一三元组的入闭包通道按位合并（判定层按它细分束）。"""
        rows = [row(1, pid="100bash", other="/home/u/x", at=10, support=1),
                row(2, pid="100bash", other="/home/u/x", at=11, support=4),
                row(3, pid="100bash", other="/home/u/y", at=12, support=2)]
        result = OF.fold(rows)
        self.assertEqual(len(result.edges), 2)
        by_object = {edge.src: edge for edge in result.edges}       # 读边的源端是对象
        self.assertEqual(by_object["/home/u/x"].channels, 5)
        self.assertEqual(by_object["/home/u/y"].channels, 2)

    def test_fold_does_not_drop_anything(self) -> None:
        """折叠不删边：进来的每个实例都要落在某条记录里。"""
        rows = [row(i, pid=f"{100 + i}bash", other=f"/tmp/f{i}", at=i) for i in range(1, 6)]
        result = OF.fold(rows)
        self.assertEqual(sum(edge.instances for edge in result.edges), len(rows))
        self.assertEqual(result.raw_instances, len(rows))

    def test_fold_records_both_end_identities(self) -> None:
        result = OF.fold([row(1, pid="100bash", other="/home/u/x", at=10)])
        edge = result.edges[0]
        self.assertEqual(edge.src_identities, {("File", "/home/u/x")})
        self.assertEqual(edge.dst_identities, {("Process", "100bash")})

    def test_fold_records_enriches_context(self) -> None:
        rows = [row(1, pid="100bash", other="/home/u/x", at=10)]
        records, stats = OF.fold_records(
            rows,
            process_info_fn=lambda pid: {"exepath": "/bin/bash", "name": "bash"},
            process_metas={"100bash": {"t0": 10}},
            network_protocols={},
        )
        self.assertEqual(stats["collapsed_triples"], 1)
        self.assertIn(("/home/u/x", "read", "/usr/sbin/sshd"), records)
        rec = records[("/home/u/x", "read", "/usr/sbin/sshd")]
        self.assertEqual(rec["process_id"], "100bash")

    def test_fold_renders_via_from_structured_fields(self) -> None:
        """`via` 不再由字符串拆回来：直接用 via_kind / via_key 查进程名。"""
        item = row(1, pid="100bash", other="/home/u/x", at=10)
        item.update({"via_kind": "Process", "via_key": "100bash"})
        records, _ = OF.fold_records(
            [item], process_info_fn=lambda pid: {"exepath": "/bin/bash"})
        rec = records[("/home/u/x", "read", "/usr/sbin/sshd")]
        self.assertEqual(rec["via"], "Process /bin/bash")

    def test_fold_counts_startup_library_reads(self) -> None:
        """启动期动态库读取是唯一被折叠跳过的行，命中条数必须计数。"""
        rows = [
            row(1, pid="100bash", rel="f2p", syscall="read",
                other="/usr/lib/libc.so.6", at=10),
            row(2, pid="100bash", rel="p2f", syscall="write", other="/tmp/out", at=20),
        ]
        result = OF.fold(rows)
        self.assertEqual(result.dropped_startup_reads, 1)
        self.assertEqual([edge.dst for edge in result.edges], ["/tmp/out"])

    def test_fold_keeps_library_read_once_written(self) -> None:
        """同一个动态库在闭包内被别的进程写过：不再当作环境初始化依赖。"""
        rows = [
            row(1, pid="100bash", rel="f2p", syscall="read",
                other="/usr/lib/libc.so.6", at=10),
            row(2, pid="100bash", rel="p2f", syscall="write", other="/tmp/out", at=20),
            row(3, pid="200evil", rel="p2f", syscall="write",
                other="/usr/lib/libc.so.6", at=5),
        ]
        result = OF.fold(rows)
        self.assertEqual(result.dropped_startup_reads, 0)
        self.assertIn("/usr/lib/libc.so.6", {edge.src for edge in result.edges})

if __name__ == "__main__":
    unittest.main()
