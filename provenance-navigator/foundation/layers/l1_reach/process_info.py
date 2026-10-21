"""进程静态属性（第 1 层）：判定层的进程身份摘要要用，缓存在内存里，一次运行内不变。

来源侧把属性灌进缓存（索引来源零查询），数据库直查来源（只给单测用的参照实现）按批查库后灌缓存。
"""

from __future__ import annotations

from typing import Any, Iterable

from ...core.db import ReadOnlyGraph

_PROCESS_INFO_RETURN = (
    "coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS process_id, "
    "p.pid AS pid, coalesce(p.name, '') AS name, "
    "coalesce(p.exe_path, p.exepath, p.name) AS exepath, "
    "coalesce(p.cmdline, p.args, '') AS args, "
    "coalesce(p.cwd, '') AS cwd"
)
_PROCESS_INFO_ONE = (
    f"MATCH (p:Process) WHERE (p.process_id = $pid OR "
    f"(coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) = $pid) "
    f"RETURN {_PROCESS_INFO_RETURN}"
)
_PROCESS_INFO_MANY = (
    f"UNWIND $pids AS pid MATCH (p:Process) "
    f"WHERE (p.process_id = pid OR "
    f"(coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) = pid) "
    f"RETURN {_PROCESS_INFO_RETURN}"
)

_PROCESS_INFO_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def process_info(graph: ReadOnlyGraph, process_id: str) -> dict[str, Any]:
    """进程静态属性（run 内不变）；进程身份摘要会反复用到，故缓存。"""
    key = (graph.database, process_id)
    cached = _PROCESS_INFO_CACHE.get(key)
    if cached is None:
        rows = graph.run(_PROCESS_INFO_ONE, {"pid": process_id})
        cached = rows[0] if rows else {}
        _PROCESS_INFO_CACHE[key] = cached
    return cached


def cache_process_info(database: str, process_id: str, info: dict[str, Any]) -> None:
    """把进程静态属性灌进内存缓存（索引来源用；零查询）。"""
    _PROCESS_INFO_CACHE[(database, process_id)] = info


def prefetch_process_info(graph: ReadOnlyGraph, process_ids: Iterable[str]) -> None:
    """按批查库并灌缓存（数据库直查来源用）：已经缓存过的进程不再查。"""
    missing = [pid for pid in process_ids if (graph.database, pid) not in _PROCESS_INFO_CACHE]
    for chunk in (missing[i:i + 5000] for i in range(0, len(missing), 5000)):
        if not chunk:
            continue
        for row in graph.run(_PROCESS_INFO_MANY, {"pids": chunk}):
            cache_process_info(graph.database, str(row["process_id"]), row)
