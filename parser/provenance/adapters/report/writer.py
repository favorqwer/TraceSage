"""报告落盘编排：CSV + report.json + report.md。"""

from __future__ import annotations

import json

from ...core.options import ReportOptions
from ...core.snapshots import RunSnapshot
from .markdown import write_markdown
from .payload import build_payload
from .tables import write_attempts_csv, write_nodes_csv, write_ops_csv


class ReportWriter:
    def __init__(self, options: ReportOptions) -> None:
        self.options = options

    def write(self, snapshot: RunSnapshot) -> dict:
        report_dir = self.options.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)

        write_nodes_csv(report_dir, snapshot)
        write_ops_csv(report_dir, snapshot)
        write_attempts_csv(report_dir, snapshot)

        payload = build_payload(snapshot, self.options)
        (report_dir / "report.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        write_markdown(report_dir / "report.md", payload)
        return payload
