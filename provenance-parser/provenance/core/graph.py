"""图变更结果：Node / Edge / Outcome。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .events import Call
from .kinds import Bucket, EdgeClass, NodeKey, ProcKey


@dataclass(slots=True)
class Node:
    key: NodeKey
    props: dict[str, Any] = field(default_factory=dict)
    dirty: bool = True


@dataclass(slots=True)
class Edge:
    cls: EdgeClass
    action: str
    src: NodeKey
    dst: NodeKey
    evt: int
    seq: int
    ts_ns: int
    te_ns: int
    res: int | None = None
    flags: str | None = None
    head: str | None = None
    old_path: str | None = None
    target_path: str | None = None
    mode: str | None = None


@dataclass(slots=True)
class Outcome:
    """一次调用的全部产物。emit 层只能通过它说话。"""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    buckets: list[tuple[int, Bucket, str]] = field(default_factory=list)
    ops: list[tuple[ProcKey, str, int]] = field(default_factory=list)
    attempts: list[tuple[ProcKey, str, str, int, int]] = field(default_factory=list)

    def cover(self, call: Call) -> "Outcome":
        for num in call.rows:
            self.buckets.append((num, Bucket.COVERED, ""))
        return self

    def settle(self, call: Call, bucket: Bucket, reason: str = "") -> "Outcome":
        for num in call.rows:
            self.buckets.append((num, bucket, reason))
        return self
