"""报告采集器：纯统计 + 按事件顺序流式写 edges.csv。"""

from __future__ import annotations

import csv

from ...core.graph import Edge
from ...core.kinds import key_cells
from ...core.options import ReportOptions
from ...core.snapshots import StatsSnapshot
from ...core.stats import RunStats

_EDGE_HEADER = [
    "edge_class", "seq", "evt", "ts_ns", "te_ns", "action", "res", "head",
    "old_path", "target_path", "mode",
    "src_label", "src_host", "src_container", "src_pid", "src_born_ns", "src_path",
    "dst_label", "dst_host", "dst_container", "dst_pid", "dst_born_ns", "dst_path",
]


class ReportCollector:
    def __init__(self, options: ReportOptions) -> None:
        self.options = options
        self.stats = RunStats()
        options.report_dir.mkdir(parents=True, exist_ok=True)
        self._edges_fh = (options.report_dir / "edges.csv").open(
            "w", newline="", encoding="utf-8"
        )
        self._edges_csv = csv.writer(self._edges_fh)
        self._edges_csv.writerow(_EDGE_HEADER)

    def on_event(self, row) -> None:
        self.stats.count_row(row)

    def on_bad(self, bad) -> None:
        self.stats.add_bad(bad.reason, bad.sample)

    def on_call(self, call, decision, outcome) -> None:
        self.stats.add(call, decision, outcome)
        for edge in outcome.edges:
            self._write_edge(edge)

    def on_single_line(self) -> None:
        self.stats.single_line_rows += 1

    def on_no_owner(self, rows: int) -> None:
        self.stats.no_owner_rows += rows

    def _write_edge(self, edge: Edge) -> None:
        self._edges_csv.writerow(
            [edge.cls.value, edge.seq, edge.evt, edge.ts_ns, edge.te_ns, edge.action,
             "" if edge.res is None else edge.res, edge.head or "",
             edge.old_path or "", edge.target_path or "", edge.mode or "",
             *key_cells(edge.src), *key_cells(edge.dst)]
        )

    def snapshot(self) -> StatsSnapshot:
        return self.stats.snapshot()

    def close(self) -> None:
        self._edges_fh.flush()
        self._edges_fh.close()
