"""图状态出口：节点登记、边缓冲、度统计；写库通过 GraphWriter 端口注入。"""

from __future__ import annotations

from ..core.graph import Edge, Node, Outcome
from ..core.kinds import NodeKey, label_of
from ..core.options import GraphLimits
from ..core.ports import GraphWriter
from ..core.snapshots import GraphSnapshot


class GraphStore:
    def __init__(self, writer: GraphWriter | None, limits: GraphLimits) -> None:
        self.writer = writer
        self.limits = limits
        self.nodes: dict[NodeKey, Node] = {}
        self.dirty: dict[NodeKey, Node] = {}
        self.buf_edges: list[Edge] = []
        self.degree_out: dict[NodeKey, int] = {}
        self.degree_in: dict[NodeKey, int] = {}
        self.written_nodes = 0
        self.written_edges = 0

    def add(self, outcome: Outcome) -> None:
        for node in outcome.nodes:
            existing = self.nodes.get(node.key)
            if existing is None:
                if len(self.nodes) >= self.limits.node_registry_max:
                    raise RuntimeError(
                        f"节点登记表超过上限 {self.limits.node_registry_max}："
                        "请调大 node_registry_max 或减小捕获范围（内存纪律）"
                    )
                self.nodes[node.key] = node
                self.dirty[node.key] = node
                continue
            changed = False
            for key, value in node.props.items():
                if value is None:
                    continue
                if (key == "file_type" and value == "unknown"
                        and existing.props.get(key) not in (None, "unknown")):
                    continue
                if existing.props.get(key) != value:
                    existing.props[key] = value
                    changed = True
            if changed:
                self.dirty[node.key] = existing
        for edge in outcome.edges:
            self.buf_edges.append(edge)
            self.degree_out[edge.src] = self.degree_out.get(edge.src, 0) + 1
            self.degree_in[edge.dst] = self.degree_in.get(edge.dst, 0) + 1
        if (len(self.buf_edges) >= self.limits.edge_batch
                or len(self.dirty) >= self.limits.vertex_batch):
            self.flush()

    def flush(self) -> None:
        if not self.buf_edges and not self.dirty:
            return
        if self.writer is not None:
            if self.dirty:
                batch = list(self.dirty.values())
                self.writer.write_nodes(batch)
                self.written_nodes += len(batch)
            if self.buf_edges:
                batch_edges = self.buf_edges
                self.writer.write_edges(batch_edges)
                self.written_edges += len(batch_edges)
        else:
            self.written_nodes += len(self.dirty)
            self.written_edges += len(self.buf_edges)
        self.dirty.clear()
        self.buf_edges = []

    def close(self) -> None:
        self.flush()
        if self.writer is not None:
            self.writer.close()

    # -- 收尾快照 ------------------------------------------------------
    def top_degree(self, limit: int = 5):
        out = sorted(self.degree_out.items(), key=lambda kv: -kv[1])[:limit]
        incoming = sorted(self.degree_in.items(), key=lambda kv: -kv[1])[:limit]
        return {"out": out, "in": incoming}

    def snapshot(self) -> GraphSnapshot:
        by_label: dict[str, int] = {}
        for key in self.nodes:
            label = label_of(key)
            by_label[label] = by_label.get(label, 0) + 1
        tree = self.top_degree()
        return GraphSnapshot(
            nodes=self.nodes,
            total=len(self.nodes),
            by_label=by_label,
            top_out=tree["out"],
            top_in=tree["in"],
            written_nodes=self.written_nodes,
            written_edges=self.written_edges,
        )
