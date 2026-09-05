"""Observability helpers for the import pipeline: skip-line bookkeeping,
progress reporting, and human-readable formatting.

The pipeline (pipeline/parser.py) owns the counters; this module owns how
they are printed — keeping all stdout formatting in one place.
"""

import time
from typing import Dict, List

_SKIP_SAMPLE_LIMIT_PER_REASON = 3
_SKIP_SUMMARY_REASON_LIMIT = 10


def format_bytes(bytes_: int) -> str:
    if bytes_ <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(bytes_)
    ui = 0
    while value >= 1024.0 and ui < len(units) - 1:
        value /= 1024.0
        ui += 1
    return f"{value:.2f} {units[ui]}"


def format_duration(duration_millis: int) -> str:
    total_seconds = max(0, duration_millis // 1000)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class SkipLineLogger:
    """Counts skipped log lines grouped by reason, with a few raw samples per
    reason for post-run auditing."""

    def __init__(self) -> None:
        self.skipped_count = 0
        self._reason_counts: Dict[str, int] = {}
        self._reason_samples: Dict[str, List[str]] = {}

    def log(self, line_no: int, line: str, reason: object) -> None:
        self.skipped_count += 1
        reason_str = str(reason)
        self._reason_counts[reason_str] = (
            self._reason_counts.get(reason_str, 0) + 1
        )
        samples = self._reason_samples.setdefault(reason_str, [])
        if len(samples) < _SKIP_SAMPLE_LIMIT_PER_REASON:
            samples.append(line)

    def print_summary(self) -> None:
        if not self._reason_counts:
            return
        sorted_reasons = sorted(
            self._reason_counts.items(),
            key=lambda x: -x[1],
        )[:_SKIP_SUMMARY_REASON_LIMIT]
        print("Skipped line summary (top reasons):")
        for reason, count in sorted_reasons:
            samples = self._reason_samples.get(reason, [])
            print(f"  [{count}x] {reason}")
            for s in samples:
                print(f"    sample: {s[:200]}")


class ProgressReporter:
    """Time-throttled [ImportProgress] printer for long imports."""

    def __init__(self, interval_millis: int) -> None:
        self._interval_millis = interval_millis
        self._parse_start_millis = 0
        self._last_report_millis = 0

    def begin(self) -> None:
        """Anchor the progress clock at import start."""
        now = int(time.time() * 1000)
        self._parse_start_millis = now
        self._last_report_millis = now

    def maybe_report(
        self,
        force: bool,
        phase: str,
        *,
        scanned_lines: int,
        processed_event_lines: int,
        bytes_read: int,
        total_log_bytes: int,
        flush_rounds: int,
    ) -> None:
        now = int(time.time() * 1000)
        if not force and now - self._last_report_millis < self._interval_millis:
            return
        self._last_report_millis = now

        safe_bytes = (
            min(bytes_read, total_log_bytes)
            if total_log_bytes > 0
            else bytes_read
        )
        elapsed = max(1, now - self._parse_start_millis)
        progress = (
            (safe_bytes * 100.0 / total_log_bytes)
            if total_log_bytes > 0
            else 0.0
        )
        mb_per_sec = (safe_bytes / 1048576.0) / (elapsed / 1000.0)
        if safe_bytes > 0 and total_log_bytes > safe_bytes:
            eta = format_duration(
                int(elapsed * (total_log_bytes - safe_bytes) / safe_bytes)
            )
        else:
            eta = "00:00:00"

        print(
            f"[ImportProgress][{phase}] "
            f"{progress:.1f}% "
            f"bytes={format_bytes(safe_bytes)}/"
            f"{format_bytes(total_log_bytes)} "
            f"scannedLines={scanned_lines} "
            f"processedEvents={processed_event_lines} "
            f"rate={mb_per_sec:.2f} MB/s eta={eta} "
            f"flushes={flush_rounds}"
        )
