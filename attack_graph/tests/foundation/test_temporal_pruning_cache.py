"""时序剪枝流式取数与同指纹本地事件快照缓存测试。"""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import settings as cfg  # noqa: E402
from core.stages import temporal_pruning  # noqa: E402


class _FakeRealGraph:
    def __init__(self, rows: list[list], fp: dict[str, int]) -> None:
        self._rows = rows
        self._fp = fp
        self.stream_calls: list[tuple[str, dict | None]] = []

    def run(self, cypher: str, params=None):
        if "max(e.event_id)" in cypher:
            return [{"edges": self._fp["edges"], "max_event_id": self._fp["max_event_id"]}]
        raise AssertionError(f"Unexpected run query: {cypher}")

    def stream_values(self, cypher: str, params=None, *, log_params: bool = True):
        self.stream_calls.append((cypher, params))
        if "WHERE e.event_id IN $ids" in cypher:
            wanted = set((params or {}).get("ids") or ())
            return [r for r in self._rows if r[1] in wanted]
        for rel_token in ("ProcessToFile", "FileToProcess", "ProcessToNetwork", "NetworkToProcess", "ProcessToProcess"):
            if f":{rel_token}" in cypher:
                return [r for r in self._rows if r[0] == rel_token]
        return list(self._rows)


class TemporalPruningCacheTests(unittest.TestCase):
    def _sample_rows(self) -> list[list]:
        return [
            ["ProcessToFile", 10, "e10", "p1", "f1", "h1", "h1", 100, 101, "write", 12, None],
            ["FileToProcess", 11, "e11", "f2", "p1", "h1", "h1", None, 90, "read", 0, "pipe"],
            ["ProcessToNetwork", 12, "e12", "p1", "n1", "h1", "h1", 120, 125, "send", -1, None],
        ]

    def test_large_fetch_builds_cache_and_reuses_until_fingerprint_changes(self) -> None:
        rows = self._sample_rows()
        fp1 = {"edges": 3, "max_event_id": 12}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(cfg, "L1_INDEX_DIR", pathlib.Path(tmp)),
                patch.object(temporal_pruning, "_REAL_READONLY_GRAPH", _FakeRealGraph),
                patch.object(temporal_pruning, "_SMALL_QUERY_LIMIT", 1),
                redirect_stdout(io.StringIO()),
            ):
                g1 = _FakeRealGraph(rows, fp1)
                ev1 = temporal_pruning._fetch_events(g1, "db-unit-v2", [10, 12])
                self.assertEqual(len(g1.stream_calls), 5)
                self.assertEqual([e["eid"] for e in ev1], [10, 12])
                self.assertEqual(ev1[1]["result"], -1)

                # 第二次同指纹查询不触发任何 stream_values，保留 None 时间与 file_type
                g2 = _FakeRealGraph(rows, fp1)
                ev2 = temporal_pruning._fetch_events(g2, "db-unit-v2", [11])
                self.assertEqual(g2.stream_calls, [])
                self.assertEqual(len(ev2), 1)
                self.assertIsNone(ev2[0]["start"])
                self.assertEqual(ev2[0]["src_kind"], "pipe")

                # 数据库指纹变化时自动失效并重建缓存
                rows_v2 = rows + [["ProcessToProcess", 13, "e13", "p0", "p1", "h1", "h1", 50, 51, "exec", 0, None]]
                g3 = _FakeRealGraph(rows_v2, {"edges": 4, "max_event_id": 13})
                ev3 = temporal_pruning._fetch_events(g3, "db-unit-v2", [11, 13])
                self.assertEqual(len(g3.stream_calls), 5)
                self.assertEqual({e["eid"] for e in ev3}, {11, 13})

    def test_small_fetch_uses_single_typed_query_without_writing_cache(self) -> None:
        rows = self._sample_rows()
        fp1 = {"edges": 3, "max_event_id": 12}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(cfg, "L1_INDEX_DIR", pathlib.Path(tmp)),
                patch.object(temporal_pruning, "_REAL_READONLY_GRAPH", _FakeRealGraph),
                patch.object(temporal_pruning, "_SMALL_QUERY_LIMIT", 100),
                redirect_stdout(io.StringIO()),
            ):
                g = _FakeRealGraph(rows, fp1)
                ev = temporal_pruning._fetch_events(g, "db-small-v2", [10, 11])
                self.assertEqual(len(g.stream_calls), 1)
                self.assertEqual({e["eid"] for e in ev}, {10, 11})
                self.assertFalse((pathlib.Path(tmp) / "db-small-v2" / "temporal_meta.json").exists())


if __name__ == "__main__":
    unittest.main()
