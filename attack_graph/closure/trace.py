"""运行轨迹记录。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

# ==== 6. 运行轨迹 ====

def trace_event(trace: list[dict[str, Any]], node: str, **fields: Any) -> None:
    trace.append({"node": node, "ts": time.time(), **fields})


def write_trace(path: Path, trace: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(json.dumps(t, ensure_ascii=False) for t in trace), encoding="utf-8")
