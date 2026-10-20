"""候选表（第 1 层尾部）：把事件实例折叠成内容三元组。

**折叠**（`fold`）。把同一内容三元组的多个事件实例压成一条记录，是**有损压缩**：实例之间的
相对时序、各自的字节量与时间会丢（只留首末与总和）；同一三元组只有一个判定结论。折叠本身**不做任何
判定、也不删边**：它把两端各存一份身份、把实例的入闭包通道按位合起来、并留下结构上下文。

折叠的结果就是候选表（交给判定层的那一堆内容三元组，也就是召回上限的口径）。**本层不做任何尾部
裁剪**：第 1 层会「少收」的地方只有两处，都在取数/收边阶段（命中 `no_expand` 的对象不往回找写入者、
零字节的数据读取不再往下展开），边本身照样收。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from ...contracts import triple
from ...core import graph_facts
from . import judgments as J


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
    # 入闭包通道（各实例按位或）：这条三元组是从哪几类顶点被收进闭包的（判定层用作束的细分键）
    channels: int = 0
    # 两端顶点的**身份**（判定层按身份找上层已判过的边用）：进程 → ("Process", 进程标识)、
    # 文件 → ("File", 路径)、网络 → ("Network", 四元组)。内容三元组与报告口径不受影响，
    # 只是多存一份身份，避免“同一个程序跑了 191 次”时把 191 个进程的判定历史混在一起。
    src_identities: set[tuple[str, str]] = field(default_factory=set)
    dst_identities: set[tuple[str, str]] = field(default_factory=set)
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
            "src_identities": sorted([list(x) for x in self.src_identities]),
            "dst_identities": sorted([list(x) for x in self.dst_identities]),
            "dist": self.dist,
            "via": self.via,
            "via_kind": self.via_kind,
            "via_key": self.via_key,
            "channels": self.channels,
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


def _other_identity(row: dict[str, Any]) -> tuple[str, str]:
    """这条边“另一端”（非归属进程那一端）的身份。

    派生边（p2p）的另一端是父进程，取它的进程标识；文件与网络端点取路径 / 四元组。
    取不到标识时返回空串身份，折叠时会被丢弃（宁可这一端没有身份，也不要拿内容冒充身份）。
    """
    label = str(row.get("other_label") or "")
    if label == "Process":
        return label, str(row.get("other_process_id") or "")
    return label, str(row.get("other") or "")


def fold(rows: Iterable[dict[str, Any]]) -> FoldResult:
    """把事件实例折成内容三元组（只合并不删边，过滤进程启动初期未受篡改的标准动态共享库读取）。"""
    rows_list = list(rows) if not isinstance(rows, list) else rows

    # 预扫描：收集本次反向展开中被写入/创建/修改的全部客体，以及各进程首次对外产生动作的时刻
    written_targets: set[str] = set()
    proc_first_action: dict[str, int] = {}
    for row in rows_list:
        rel = str(row.get("rel") or "")
        pid = str(row.get("process_id") or "")
        st = int(row.get("starttime") or 0)
        if rel in graph_facts.PRODUCER_RELS:
            other = str(row.get("other") or "")
            if other:
                written_targets.add(other)
            if pid and (pid not in proc_first_action or st < proc_first_action[pid]):
                proc_first_action[pid] = st
        elif graph_facts.is_derivation(rel):
            if pid and (pid not in proc_first_action or st < proc_first_action[pid]):
                proc_first_action[pid] = st

    table: dict[tuple[str, str, str], CollapsedEdge] = {}
    raw = 0
    for row in rows_list:
        raw += 1
        other_path = str(row.get("other") or "")
        rel = str(row.get("rel") or "")
        sc = str(row.get("syscall") or "")
        pid = str(row.get("process_id") or "")
        st = int(row.get("starttime") or 0)

        # 仅在进程启动期（首次对外动作之前）读入、且全图未曾被写入的标准动态共享库，方视为底层环境初始化依赖
        first_act = proc_first_action.get(pid, float("inf"))
        if J.is_startup_dependency(rel, sc, other_path, st, first_act, written_targets):
            continue

        src, syscall, dst, src_label = graph_facts.content_triple_of(
            row["rel"], row["syscall"], row["owner"], row["other"])
        # 两端标签用于消除 `/usr/bin/mv` 这类"既是进程又是文件"的内容歧义（与取边时的判定共用一份）
        _src_label, dst_label = graph_facts.labels_of(row["rel"])
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
                channels=int(row.get("support") or 0),
            )
            table[key] = edge
        else:
            edge.channels |= int(row.get("support") or 0)
            if int(row.get("dist") or 0) < edge.dist:
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
        # 两端身份：属主那一端一定是进程（归属规则），另一端按标签取；标识为空就丢这一端
        owner_ident = ("Process", str(row.get("process_id") or ""))
        other_ident = _other_identity(row)
        src_ident, dst_ident = ((owner_ident, other_ident) if graph_facts.owner_is_source(row["rel"])
                                else (other_ident, owner_ident))
        if src_ident[1]:
            edge.src_identities.add(src_ident)
        if dst_ident[1]:
            edge.dst_identities.add(dst_ident)
    edges = sorted(table.values(), key=lambda e: (e.t0, e.src, e.syscall, e.dst))
    return FoldResult(edges=edges, raw_instances=raw)


def fold_records(rows: Iterable[dict[str, Any]], *,
                 process_info_fn: Optional[Callable[[str], Any]] = None,
                 process_metas: Optional[dict[str, dict[str, Any]]] = None,
                 network_protocols: Optional[dict[str, str]] = None,
                 ) -> tuple[dict[tuple[str, str, str], dict[str, Any]], dict[str, Any]]:
    """一步直接折叠为带完整渲染上下文的候选三元组字典映射，消除上层二次循环包装。"""
    folded = fold(rows)
    metas = process_metas or {}
    protocols = network_protocols or {}
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in folded.edges:
        rec = edge.to_dict(with_event_ids=True)
        via = str(rec.get("via") or "")
        if via.startswith("Process ") and process_info_fn:
            pid = via.split(" ", 1)[1]
            info = process_info_fn(pid)
            shown = str(info.get("exepath") or info.get("name") or "") if info else ""
            rec["via"] = f"Process {shown or pid}"
        members = sorted(rec.get("member_processes") or [])
        if members:
            rec["process_id"] = min(members, key=lambda k: (int((metas.get(k) or {}).get("t0") or 0), k))
        # 网络端点协议
        src_label = str(rec.get("src_label") or "")
        dst_label = str(rec.get("dst_label") or "")
        if src_label == "Network":
            rec["network_protocol"] = protocols.get(str(rec.get("src") or ""), "")
        elif dst_label == "Network":
            rec["network_protocol"] = protocols.get(str(rec.get("dst") or ""), "")
        else:
            rec["network_protocol"] = ""
        records[triple(rec)] = rec
    return records, {"raw_instances": folded.raw_instances, "collapsed_triples": len(records)}
