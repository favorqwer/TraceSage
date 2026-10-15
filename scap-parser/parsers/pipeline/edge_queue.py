"""Edge buffering: per-relation queues, flush thresholds, and the p2p
forward-flow bookkeeping (execve-registered parent->child edges get their
end time extended by the parent's later tracked events until the final
flush)."""

from typing import Dict, List

from ..model.event_edge import EventEdge

# 五种方向化事件边（AGENTS.md §1）。
EDGE_RELS = ("p2p", "p2f", "f2p", "p2n", "n2p")

# 中间 flush 参与阈值的四种关系；p2p 只在导入结束的最终 flush 写入。
_THRESHOLD_RELS = ("p2f", "f2p", "p2n", "n2p")


class EdgeQueues:
    """Buffers generated edges per relation type until a flush."""

    def __init__(self) -> None:
        self._queues: Dict[str, List[EventEdge]] = {rel: [] for rel in EDGE_RELS}
        self.totals: Dict[str, int] = {rel: 0 for rel in EDGE_RELS}
        self._forward_flow: Dict[str, EventEdge] = {}

    def queue(self, rel: str, edge: EventEdge) -> None:
        """Buffer one edge of the given relation type and bump its total."""
        self._queues[rel].append(edge)
        self.totals[rel] += 1

    def edges(self, rel: str) -> List[EventEdge]:
        return self._queues[rel]

    def should_flush(self, edge_limit: int) -> bool:
        # p2p 边不计入 flush 阈值，只在导入结束的最终 flush 写入。
        return sum(len(self._queues[rel]) for rel in _THRESHOLD_RELS) >= edge_limit

    def clear(self, include_p2p: bool) -> None:
        """Empty the buffered edge queues; p2p only when included in the flush."""
        for rel in _THRESHOLD_RELS:
            self._queues[rel].clear()
        if include_p2p:
            self._queues["p2p"].clear()

    # ------------------------------------------------------------------
    # p2p forward-flow: execve registers the parent->child edge under the
    # PARENT's process key (pid+name taken from ptid in the execve args),
    # while extend lookups key on the acting process — so it is the parent's
    # later tracked events (read/write/... via _update_p2p_links) that
    # extend the edge's end time up to the final flush; the child's own
    # events never match the registration key.
    # ------------------------------------------------------------------
    def register_forward(self, key: str, edge: EventEdge) -> None:
        self._forward_flow[key] = edge

    def extend_forward(self, key: str, end_ns: int) -> None:
        forward_edge = self._forward_flow.get(key)
        if forward_edge is not None and forward_edge.end_ns < end_ns:
            forward_edge.end_ns = end_ns
