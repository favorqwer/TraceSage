"""运行轨迹（审计旁路）：一次运行里各阶段的关键计数与耗时，收尾写 JSONL。

轨迹只用于事后归因（墙钟花在哪一步），失败不影响主流程。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def trace_event(trace: list[dict[str, Any]], node: str, **fields: Any) -> None:
    """往轨迹列表追加一条。"""
    trace.append({"node": node, "ts": time.time(), **fields})


def write_trace(path: Path, trace: list[dict[str, Any]]) -> None:
    """把轨迹落盘成 JSONL（每行一条）。"""
    path.write_text("\n".join(json.dumps(t, ensure_ascii=False) for t in trace), encoding="utf-8")
