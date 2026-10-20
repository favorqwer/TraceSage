"""采集端审计：两趟计数，量化模板不可打印的行。"""

from __future__ import annotations

from ...core.audit import Audit
from .template import AUDIT_ALL_TEMPLATE, AUDIT_PID_TEMPLATE, as_bytes


def _scan_counts(source, with_type: bool) -> tuple[int, dict[str, int], int]:
    total = 0
    by_type: dict[str, int] = {}
    max_num = 0
    with source as stream:
        for raw in stream.stream_lines():
            if not raw:
                continue
            total += 1
            parts = as_bytes(raw).rstrip(b"\r\n").split(b"\t")
            try:
                max_num = max(max_num, int(parts[0]))
            except (ValueError, IndexError):
                pass
            if with_type and len(parts) > 1:
                name = parts[1].decode("utf-8", "replace")
                by_type[name] = by_type.get(name, 0) + 1
    return total, by_type, max_num


def run_audit(make_source) -> Audit:
    total, total_by_type, max_num = _scan_counts(
        make_source(AUDIT_ALL_TEMPLATE), True
    )
    pid_rows, pid_by_type, _ = _scan_counts(
        make_source(AUDIT_PID_TEMPLATE), True
    )
    return Audit(total, total_by_type, pid_rows, pid_by_type, max_num)
