"""规则表加载：从 `foundation/rules/` 读 JSON 文件。

**按原样返回**（不做改写）；结果在进程内缓存。表的形状与校验在 `layers/l1_reach/table.py`；
判据改在表里（现在第 1 层只有一张表 `l1_judgments.json`），流程代码不用动。
"""

from __future__ import annotations

import json
from typing import Any

from . import settings

_CACHE: dict[str, Any] = {}


def load(name: str) -> Any:
    """读一个规则文件（名字带后缀，例如 `l1_judgments.json`）。"""
    cached = _CACHE.get(name)
    if cached is None:
        cached = json.loads((settings.RULES_DIR / name).read_text(encoding="utf-8"))
        _CACHE[name] = cached
    return cached
