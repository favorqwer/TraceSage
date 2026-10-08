"""规则表加载：从 `pagent/rules/` 读 JSON 文件。

**按原样返回**（不做改写）；结果在进程内缓存。规则内容与代码分开，改规则不用改流程代码；
但改剔除表（`filters.json` 的 output 段）或新增条目时要按口径核对（逐条核对六个场景的人工标注，
见 `provenance-agent/README.md`）。
"""

from __future__ import annotations

import json
from typing import Any

from . import settings

_CACHE: dict[str, Any] = {}


def load(name: str) -> Any:
    """读一个规则文件（名字带后缀，例如 `vertices.json`）。"""
    cached = _CACHE.get(name)
    if cached is None:
        cached = json.loads((settings.RULES_DIR / name).read_text(encoding="utf-8"))
        _CACHE[name] = cached
    return cached
