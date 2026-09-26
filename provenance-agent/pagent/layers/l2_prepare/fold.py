"""折叠与两类结构性伪边剔除（第 2 层内部）。

**折叠是有损压缩**：把同一内容三元组的多个事件实例压成一条记录。压缩的是判定与报告的单位，
不压缩存储（图上每条边都还在），也不改变边集。
保留：源、操作名、目标、两端标签、首次/末次时间、实例数、累计字节、全部事件编号、来源成员步骤。
丢弃（**这就是有损之处，直接决定判定质量的上限**）：实例之间的相对时序；每次实例各自的字节量与
时间（只剩首末与总和）；单个实例的独立判决资格（一条三元组只能有一个判决，所以"同一次操作既有
正常实例、又有恶意实例"时无法拆开，恶意实例会被实例数与累计字节稀释）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# R1（动态链接器读共享库）、R2（系统自带程序的自身执行）的判定在 `core/edge_rules.py`：
# 第 1 层遍历期与这里必须用同一个函数（见该模块说明）。过滤恒开，不可关闭。
from ...core.edge_rules import is_r1, is_r2  # noqa: F401 - 兼容旧引用（`l2.is_r1`）


def _project(row: dict[str, Any]) -> tuple[str, str, str]:
    """一行边记录 -> (src 内容, 操作名, dst 内容)。方向由关系类型唯一决定。"""
    rel = row["rel"]
    owner = row["owner"]
    other = row["other"]
    if rel in ("p2f", "p2n"):
        return owner, row["syscall"], other
    if rel in ("f2p", "n2p"):
        return other, row["syscall"], owner
    if rel == "p2p":
        return other, row["syscall"], owner
    raise ValueError(f"未知关系类型 {rel!r}")


def _labels(row: dict[str, Any]) -> tuple[str, str]:
    """(src 标签, dst 标签)。用于消除 `/usr/bin/mv` 这类"既是进程又是文件"的内容歧义。"""
    rel = row["rel"]
    other_label = row.get("other_label") or "Process"
    if rel in ("p2f", "p2n"):
        return "Process", other_label
    if rel in ("f2p", "n2p"):
        return other_label, "Process"
    return "Process", "Process"


@dataclass
class CollapsedEdge:
    src: str
    syscall: str
    dst: str
    src_label: str = "Process"
    dst_label: str = "Process"
    instances: int = 0
    bytes: int = 0
    event_ids: list[int] = field(default_factory=list)
    t0: int = 0
    t1: int = 0
    rels: set[str] = field(default_factory=set)
    members: set[str] = field(default_factory=set)   # 来源成员步骤（管道组合并时可能有多个）

    def to_dict(self, *, with_event_ids: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "syscall": self.syscall,
            "dst": self.dst,
            "src_label": self.src_label,
            "dst_label": self.dst_label,
            "instances": self.instances,
            "bytes": self.bytes,
            "t0": self.t0,
            "t1": self.t1,
            "rels": sorted(self.rels),
            "member_steps": sorted(self.members),
        }
        if with_event_ids:
            out["event_ids"] = self.event_ids
        return out


@dataclass
class FoldResult:
    edges: list[CollapsedEdge]
    raw_instances: int
    dropped_r1: int
    dropped_r2: int


def fold(rows: Iterable[dict[str, Any]]) -> FoldResult:
    """把事件实例折成内容三元组，并按两类结构性伪边剔除（过滤恒开，不可关闭）。"""
    table: dict[tuple[str, str, str], CollapsedEdge] = {}
    raw = 0
    dropped_r1 = 0
    dropped_r2 = 0
    for row in rows:
        raw += 1
        src, syscall, dst = _project(row)
        if is_r1(src, syscall):
            dropped_r1 += 1
            continue
        if is_r2(src, dst, syscall):
            dropped_r2 += 1
            continue
        key = (src, syscall, dst)
        edge = table.get(key)
        src_label, dst_label = _labels(row)
        if edge is None:
            edge = CollapsedEdge(
                src=src,
                syscall=syscall,
                dst=dst,
                src_label=src_label,
                dst_label=dst_label,
                t0=row["starttime"],
                t1=row["endtime"],
            )
            table[key] = edge
        edge.instances += 1
        edge.bytes += max(0, int(row.get("bytes") or 0))
        edge.event_ids.append(int(row["event_id"]))
        edge.t0 = min(edge.t0, int(row["starttime"]))
        edge.t1 = max(edge.t1, int(row.get("endtime") or row["starttime"]))
        edge.rels.add(row["rel"])
        if row.get("step_key"):
            edge.members.add(str(row["step_key"]))
    edges = sorted(table.values(), key=lambda e: (e.t0, e.src, e.syscall, e.dst))
    return FoldResult(edges=edges, raw_instances=raw, dropped_r1=dropped_r1, dropped_r2=dropped_r2)
