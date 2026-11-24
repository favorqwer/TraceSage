"""文本截断与相对时间渲染。"""
from __future__ import annotations

from typing import Any

import settings

def short(text: Any, limit: Any = None) -> str:
    """一句话摘要：换行压成空格并截断；默认长度取参数文件。"""
    if limit is None:
        limit = settings.log_text_limit()
    return str(text or "").replace("\n", " ")[:int(limit)]


def rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数。"""
    try:
        t = int(value or 0)
    except (TypeError, ValueError):
        return "?"
    if not ref_t or not t:
        return str(t)
    return f"{(t - int(ref_t)) / 1e9:+.1f}s"

