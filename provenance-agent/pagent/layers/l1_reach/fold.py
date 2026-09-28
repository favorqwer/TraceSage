"""折叠（第 1 层尾部，紧接闭包之后）：按内容三元组把重复的事件实例合并成一条记录。

**折叠是有损压缩**：把同一内容三元组的多个事件实例压成一条记录。压缩的是判定与报告的单位，
不压缩存储（图上每条边都还在），也不改变边集。
保留：源、操作名、目标、两端标签、首次/末次时间、实例数、累计字节、全部事件编号、来源进程，
外加**结构上下文**（这条边离终点事件最少几跳 `dist`、从哪个顶点被回推出来 `via`；多个实例取跳数
最小的那份）。
丢弃（**这就是有损之处，直接决定判定质量的上限**）：实例之间的相对时序；每次实例各自的字节量与
时间（只剩首末与总和）；单个实例的独立判决资格（一条三元组只能有一个判决，所以"同一次操作既有
正常实例、又有恶意实例"时无法拆开，恶意实例会被实例数与累计字节稀释）。

**本模块不做任何规则判定，也不删任何边**：五条结构式规则都在取边时判完（同一个规则模块
`core/edge_rules.py`），命中的边根本不进闭包、也就不会出现在行里。所以折叠的输出就是候选表
（交给模型的那一堆内容三元组，也就是召回上限的口径）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .closure import labels_of


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
    members: set[str] = field(default_factory=set)   # 来源进程（同一个内容三元组可能由多个进程产生）
    # 结构上下文（判定时渲染给模型看，不进报告）：离终点事件最少几跳、从哪个顶点被回推出来。
    # `via` 是给人读的显示文本（进程显示可执行路径）；`via_kind` / `via_key` 是原始标识
    # （判定层的“上游交接明细”按它定位上一层顶点：进程侧是进程标识，对象侧是路径本身）。
    dist: int = 0
    via: str = ""
    via_kind: str = ""
    via_key: str = ""

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
            "member_processes": sorted(self.members),
            "dist": self.dist,
            "via": self.via,
            "via_kind": self.via_kind,
            "via_key": self.via_key,
        }
        if with_event_ids:
            out["event_ids"] = self.event_ids
        return out


@dataclass
class FoldResult:
    edges: list[CollapsedEdge]
    raw_instances: int


def _via_label(row: dict[str, Any]) -> str:
    """这条边从哪个顶点被回推出来（空 = 终点事件本身）。"""
    kind = str(row.get("via_kind") or "")
    return f"{kind} {row.get('via_key') or ''}".strip() if kind else "终点事件"


def fold(rows: Iterable[dict[str, Any]]) -> FoldResult:
    """把事件实例折成内容三元组（行里已经没有命中规则的边，所以这里不删边）。"""
    table: dict[tuple[str, str, str], CollapsedEdge] = {}
    raw = 0
    for row in rows:
        raw += 1
        src, syscall, dst = _project(row)
        # 两端标签用于消除 `/usr/bin/mv` 这类"既是进程又是文件"的内容歧义（与取边时的判定共用一份）
        src_label, dst_label = labels_of(row["rel"], str(row.get("other_label") or ""))
        key = (src, syscall, dst)
        edge = table.get(key)
        if edge is None:
            edge = CollapsedEdge(
                src=src,
                syscall=syscall,
                dst=dst,
                src_label=src_label,
                dst_label=dst_label,
                t0=row["starttime"],
                t1=row["endtime"],
                dist=int(row.get("dist") or 0),
                via=_via_label(row),
                via_kind=str(row.get("via_kind") or ""),
                via_key=str(row.get("via_key") or ""),
            )
            table[key] = edge
        elif int(row.get("dist") or 0) < edge.dist:
            # 同一个三元组可能有多个实例：结构上下文取跳数最小的那一份（确定性：相同则保留先到的）
            edge.dist = int(row.get("dist") or 0)
            edge.via = _via_label(row)
            edge.via_kind = str(row.get("via_kind") or "")
            edge.via_key = str(row.get("via_key") or "")
        edge.instances += 1
        edge.bytes += max(0, int(row.get("bytes") or 0))
        edge.event_ids.append(int(row["event_id"]))
        edge.t0 = min(edge.t0, int(row["starttime"]))
        edge.t1 = max(edge.t1, int(row.get("endtime") or row["starttime"]))
        edge.rels.add(row["rel"])
        if row.get("process_id"):
            edge.members.add(str(row["process_id"]))
    edges = sorted(table.values(), key=lambda e: (e.t0, e.src, e.syscall, e.dst))
    return FoldResult(edges=edges, raw_instances=raw)
