"""提示词加载：从 `foundation/prompts/` 读文本文件。

**按原样返回**（不做 strip、不加换行）；结果在进程内缓存。
"""

from __future__ import annotations

from . import settings

_CACHE: dict[str, str] = {}


def load(name: str) -> str:
    """读一个提示词文件（名字带后缀，例如 `judge_first_pass.md`）。"""
    cached = _CACHE.get(name)
    if cached is None:
        cached = (settings.PROMPTS_DIR / name).read_text(encoding="utf-8")
        _CACHE[name] = cached
    return cached
