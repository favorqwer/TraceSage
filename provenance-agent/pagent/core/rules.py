"""规则表加载：从 `pagent/rules/` 读 JSON 文件。

**按原样返回**（不做改写）；结果在进程内缓存。规则内容与代码分开，加规则不用改流程代码；
但粗筛类规则新增时仍要按口径核对（逐条核对六个场景的人工标注，见 `provenance-agent/README.md`）。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from . import settings

_CACHE: dict[str, Any] = {}


def load(name: str) -> Any:
    """读一个规则文件（名字带后缀，例如 `prefilter.json`）。"""
    cached = _CACHE.get(name)
    if cached is None:
        cached = json.loads((settings.RULES_DIR / name).read_text(encoding="utf-8"))
        _CACHE[name] = cached
    return cached


def fingerprint(names: Iterable[str]) -> str:
    """若干规则文件内容的校核值：规则一改，值就变（第 1 层索引快照拿它判自己是否过期）。"""
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode("utf-8"))
        digest.update((settings.RULES_DIR / name).read_bytes())
    return digest.hexdigest()
