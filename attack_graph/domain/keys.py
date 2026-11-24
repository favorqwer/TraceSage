"""路径、容器与进程键拆装。"""
from __future__ import annotations

import re
from typing import Any, Optional

# ==== 2. 路径与端点拆装 ====

_PROCESS_ID = re.compile(r"^[^|]*\|[^|]*\|\d+\|\d+$")


def split_container(content: Any) -> tuple[str, str]:
    """文件内容 →（容器, 纯路径）。恰好一个 `|` 且两侧非空时才认容器前缀。"""
    s = "" if content is None else str(content)
    if s.count("|") == 1:
        container, path = s.split("|", 1)
        if container and path:
            return container, path
    return "host", s


def path_part(content: Any) -> str:
    """文件内容的纯路径部分（剥掉容器前缀）。"""
    return split_container(content)[1]


def split_process_id(process_id: Any) -> tuple[str, str]:
    """进程标识 `主机|容器|pid|启动纳秒` →（主机, 容器）。"""
    parts = str(process_id or "").split("|")
    if len(parts) >= 4:
        return parts[0], (parts[1] or "host")
    return "", "host"


def process_content_or_na(content: Any, process_id: Optional[str] = None) -> str:
    """进程端点内容：图里取不到可执行文件时，标准答案与报告都写 `<NA>`。"""
    s = "" if content is None else str(content)
    if not s:
        return "<NA>"
    if process_id is not None and s == str(process_id):
        return "<NA>"
    if _PROCESS_ID.match(s):
        return "<NA>"
    return s


def split_process_key(key: Any) -> tuple[str, str, int, int] | None:
    """进程顶点键 `主机|容器|pid|启动时刻` →（主机, 容器, pid, 启动纳秒）。"""
    parts = str(key or "").split("|")
    if len(parts) < 4:
        return None
    try:
        return parts[0], (parts[1] or "host"), int(parts[2]), int(parts[3])
    except ValueError:
        return None


def process_identity_variants(pid_raw: Any) -> set[str]:
    """进程键的全部等价标识：自身 + 去掉启动纳秒的三段前缀。"""
    if not pid_raw:
        return set()
    s = str(pid_raw).strip()
    if not s or s == "<NA>":
        return set()
    variants = {s}
    if "|" in s:
        parts = s.split("|")
        if len(parts) >= 3:
            variants.add(f"{parts[0]}|{parts[1]}|{parts[2]}")
    return variants

