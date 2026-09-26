"""步骤定义与进程静态属性（第 1 层内部）。

**一个步骤 = 一个进程实例**，键 `S:<进程标识>:<该进程最早一条被收进闭包的边的开始时刻>`。
步骤只用于判定时的上下文渲染与分组（命令行、工作目录、读写清单），**不参与可达性计算**：
哪些边进闭包由 `closure.py` 的因果规则决定，边的归属由图上的归属规则唯一决定。

进程静态属性（可执行路径、命令行、工作目录）在一次运行内不变，缓存在内存里；索引快照来源
（`sources.SnapshotReader`）直接灌这份缓存，所以走索引时一个查询都不用发。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...core.db import ReadOnlyGraph
from .queries import _PROCESS_INFO_CYPHER

_PROCESS_INFO_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def process_info(graph: ReadOnlyGraph, process_id: str) -> dict[str, Any]:
    """进程静态属性（run 内不变）；步骤摘要（第 2 层）会反复用到，故缓存。"""
    key = (graph.database, process_id)
    cached = _PROCESS_INFO_CACHE.get(key)
    if cached is None:
        rows = graph.run(_PROCESS_INFO_CYPHER, {"pid": process_id})
        cached = rows[0] if rows else {}
        _PROCESS_INFO_CACHE[key] = cached
    return cached


def has_process_info(database: str, process_id: str) -> bool:
    """内存缓存里已有这个进程的静态属性（批量预取后就不必再查库）。"""
    return (database, process_id) in _PROCESS_INFO_CACHE


def cache_process_info(database: str, process_id: str, info: dict[str, Any]) -> None:
    """把进程静态属性灌进内存缓存（索引快照来源用；零查询）。"""
    _PROCESS_INFO_CACHE[(database, process_id)] = info


def make_step_key(process_id: str, t0: int) -> str:
    return f"S:{process_id}:{int(t0)}"


def parse_step_key(key: str) -> tuple[str, int]:
    if not key.startswith("S:"):
        raise ValueError(f"非法步骤 key：{key!r}")
    _, pid, t0 = key.split(":", 2)
    return pid, int(t0)


@dataclass
class Step:
    """一个进程实例（只承载渲染上下文，不参与可达性计算）。"""

    key: str
    process_id: str
    owner: str
    t0: int
    t1: int
    rows: list[dict[str, Any]] = field(repr=False, default_factory=list)

    @property
    def n_edges(self) -> int:
        return len(self.rows)
