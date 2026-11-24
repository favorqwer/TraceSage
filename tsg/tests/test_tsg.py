"""单文件 .tsg 索引引擎与离线查询工具单元测试。"""
from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tsg.format import TSGReader, TSGWriter  # noqa: E402
from tsg.query import expand_neighbors, export_sqlite, list_vertex_edges, search_vertices  # noqa: E402


class TestTSGFormatAndQuery(unittest.TestCase):
    def _build_sample(self, path: Path) -> None:
        w = TSGWriter(path, scenario="unit_sc", database="unit-v2", source_scap="unit.scap")
        w.add_vertex("Process", "h1|host|100|1000", {
            "content": "/bin/sh", "host_id": "h1", "container_id": "host",
            "pid": 100, "ppid": 1, "exepath": "/bin/sh", "args": "/bin/sh -c evil",
            "uid": 0, "euid": 0, "container_privileged": None,
        })
        w.add_vertex("Process", "h1|host|200|2000", {
            "content": "/usr/bin/cat", "host_id": "h1", "container_id": "host",
            "pid": 200, "ppid": 100, "exepath": "/usr/bin/cat", "args": "/usr/bin/cat /srv/out",
            "uid": 1000, "euid": 1000, "container_host_root_rw": True,
        })
        w.add_vertex("File", "/tmp/in", {"content": "/tmp/in", "host_id": "h1", "container_id": "host", "file_type": "pipe"})
        w.add_vertex("File", "/srv/out", {"content": "/srv/out", "host_id": "h1", "container_id": "host", "file_type": "file"})
        w.add_vertex("Network", "10.0.0.1:4444->10.0.0.2:80", {
            "content": "10.0.0.1:4444->10.0.0.2:80", "host_id": "h1", "protocol": "tcp",
        })

        # p2p exec + f2p exec 同 event_id 双边
        w.add_edge(
            rel="p2p", src_kind="Process", src_key="h1|host|100|1000",
            dst_kind="Process", dst_key="h1|host|200|2000",
            event_id=10, start_ns=2000, end_ns=2001, syscall="execve", action="exec", result=0,
        )
        w.add_edge(
            rel="f2p", src_kind="File", src_key="/tmp/in",
            dst_kind="Process", dst_key="h1|host|200|2000",
            event_id=10, start_ns=2000, end_ns=2001, syscall="execve", action="exec", result=None,
        )
        # 带 payload_b64 与负 result 的边
        w.add_edge(
            rel="f2p", src_kind="File", src_key="/tmp/in",
            dst_kind="Process", dst_key="h1|host|200|2000",
            event_id=20, start_ns=None, end_ns=None, syscall="read", action="read",
            result=-11, payload_b64="YWJj",
        )
        # 带 mode 的 chmod + 长耗时 (> 4.29s) 溢出 end_ns 测试 + 带 to_path 的 link + POI write
        w.add_edge(
            rel="p2f", src_kind="Process", src_key="h1|host|200|2000",
            dst_kind="File", dst_key="/srv/out",
            event_id=30, start_ns=3000, end_ns=3000 + 10_000_000_000, syscall="chmod", action="chmod",
            result=0, mode="0755",
        )
        w.add_edge(
            rel="p2f", src_kind="Process", src_key="h1|host|200|2000",
            dst_kind="File", dst_key="/srv/out",
            event_id=40, start_ns=4000, end_ns=4010, syscall="write", action="write",
            result=64, payload_b64="UkVBRE1F", to_path="/srv/link",
        )
        w.finish()

    def test_single_file_full_attributes_and_directional_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsg_path = Path(tmp) / "unit.tsg"
            self._build_sample(tsg_path)
            self.assertTrue(tsg_path.is_file())
            # 临时目录必须全部清理，只剩 1 个单文件
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["unit.tsg"])

            with TSGReader(tsg_path) as r:
                self.assertEqual(r.vertex_count, 5)
                self.assertEqual(r.edge_count, 5)
                self.assertEqual(r.parent_of_process("h1|host|200|2000"), "h1|host|100|1000")
                self.assertEqual(r.network_protocols(), {"10.0.0.1:4444->10.0.0.2:80": "tcp"})

                # 按 event_id 直查同编号双边
                e10 = r.find_edges_by_event_id(10, with_extras=True)
                self.assertEqual({e.rel_full for e in e10}, {"ProcessToProcess", "FileToProcess"})

                # NULL 时间戳 + 负 result + payload_b64
                e20 = r.find_edges_by_event_id(20, with_extras=True)
                self.assertEqual(len(e20), 1)
                self.assertIsNone(e20[0].start_ns)
                self.assertIsNone(e20[0].end_ns)
                self.assertEqual(e20[0].result, -11)
                self.assertEqual(e20[0].effect, "failure")
                self.assertEqual(e20[0].payload_b64, "YWJj")
                self.assertEqual(e20[0].src_file_type, "pipe")

                # mode 与溢出 end_ns 与 to_path 与 payload_b64 全属性无损
                e30 = r.find_edges_by_event_id(30, with_extras=True)[0]
                self.assertEqual(e30.mode, "0755")
                self.assertEqual(e30.end_ns, 3000 + 10_000_000_000)
                e40 = r.find_edges_by_event_id(40, with_extras=True)[0]
                self.assertEqual(e40.payload_b64, "UkVBRE1F")
                self.assertEqual(e40.to_path, "/srv/link")

                # 离线 POI 定位
                pois = r.find_poi(kind="file", rel="p2f", syscall="write", key="/srv/out")
                self.assertEqual(len(pois), 1)
                self.assertEqual(pois[0]["event_id"], 40)
                self.assertEqual(pois[0]["process_id"], "h1|host|200|2000")
                self.assertEqual(pois[0]["src_host"], "h1")
                self.assertEqual(pois[0]["dst_kind"], "file")

                # 读写分块隔离：/tmp/in 只有 out 读边(2 条)，in 写边为 0
                in_vid = r.find_vertex_id("File", "/tmp/in")
                self.assertIsNotNone(in_vid)
                self.assertEqual(list(r.iter_block_raw(in_vid, -1, 10**9, outgoing=False)), [])
                self.assertEqual(len(list(r.iter_block_raw(in_vid, -1, 10**9, outgoing=True))), 2)

                # 离线交互查询工具函数
                found_v = search_vertices(r, kind="Process", pattern="evil")
                self.assertEqual([v["pid"] for v in found_v], [100])
                ed_list = list_vertex_edges(r, kind="File", key="/srv/out", direction="in", with_extras=True)
                self.assertEqual([e["event_id"] for e in ed_list], [30, 40])
                nb = expand_neighbors(r, 40, hops=2, direction="backward")
                self.assertIn(10, {item["event_id"] for item in nb})

                # SQLite 导出
                sq_path = Path(tmp) / "audit.sqlite"
                stats = export_sqlite(r, sq_path)
                self.assertEqual(stats, {"vertices": 5, "edges": 5})
                conn = sqlite3.connect(str(sq_path))
                try:
                    c = conn.execute("SELECT mode FROM edges WHERE event_id = 30").fetchone()
                    self.assertEqual(c[0], "0755")
                finally:
                    conn.close()

    def test_abort_cleans_all_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsg_path = Path(tmp) / "fail.tsg"
            w = TSGWriter(tsg_path, scenario="fail")
            w.add_vertex("Process", "h1|host|1|1")
            w.abort()
            self.assertFalse(tsg_path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
