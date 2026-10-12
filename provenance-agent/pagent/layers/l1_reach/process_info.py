"""进程静态属性（第 1 层）：判定层的进程身份摘要要用，缓存在内存里，一次运行内不变。

来源侧把属性灌进缓存（索引来源零查询），数据库直查来源（只给单测用的参照实现）按批查库后灌缓存。
常驻服务进程的判定不在这里：那是判据表里的一组图上事实，求值在 `judgments.resident_processes`。
"""

from __future__ import annotations

from typing import Any, Iterable

from ...core.db import ReadOnlyGraph

_PROCESS_INFO_RETURN = ("p.process_id AS process_id, p.pid AS pid, p.name AS name, "
                        "p.exepath AS exepath, p.args AS args, p.cwd AS cwd")
_PROCESS_INFO_ONE = f"MATCH (p:Process {{process_id:$pid}}) RETURN {_PROCESS_INFO_RETURN}"
_PROCESS_INFO_MANY = (f"UNWIND $pids AS pid MATCH (p:Process {{process_id: pid}}) "
                      f"RETURN {_PROCESS_INFO_RETURN}")

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
