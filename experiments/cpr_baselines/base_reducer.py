"""所有因果图压缩算法的统一抽象基类与接口契约。

每个基线算法必须继承此类并实现抽象方法，保证所有基线在相同的生命周期、
相同的数据流接口与相同的度量指标下进行评测。
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple

from .event import CompressedEdge, EntityKind, TraceEvent


class BaseGraphReducer(ABC):
    """图压缩算法抽象基类。"""

    def __init__(self, name: str):
        self.name: str = name
        self.total_events_in: int = 0
        self.total_edges_out: int = 0
        self.total_nodes_in: Set[str] = set()
        self.total_nodes_out: Set[str] = set()
        self.elapsed_ns: int = 0
        self._start_time: float = 0.0

    @abstractmethod
    def reset(self) -> None:
        """重置内部所有状态机与缓存结构，用于开启新场景的评测。"""
        self.total_events_in = 0
        self.total_edges_out = 0
        self.total_nodes_in.clear()
        self.total_nodes_out.clear()
        self.elapsed_ns = 0

    @abstractmethod
    def process_event(self, event: TraceEvent) -> Optional[CompressedEdge]:
        """在线消费一条系统调用事件。

        返回值：
        - 若返回 CompressedEdge，表示该事件产生了一条被保留的压缩边；
        - 若返回 None，表示该事件被当前算法判定为冗余事件并在线消除。
        """
        pass

    @abstractmethod
    def finish(self) -> List[CompressedEdge]:
        """数据流结束时的收尾冲刷。

        部分算法（如连续写聚合、NodeMerge模板聚类）在流末尾可能存在挂起未发射的边，
        调用此方法完成最终的状态折叠与边输出。
        """
        pass

    @abstractmethod
    def export_graph(self) -> Tuple[Set[str], List[CompressedEdge]]:
        """导出压缩后的完整图拓扑结构。

        返回值：
        - Set[str]: 压缩后保留的节点物理标识集合
        - List[CompressedEdge]: 压缩后保留的所有边列表
        """
        pass

    def record_input_event(self, event: TraceEvent) -> None:
        """记录输入事件统计信息。"""
        self.total_events_in += 1
        self.total_nodes_in.add(event.src_id)
        self.total_nodes_in.add(event.dst_id)

    def get_stats(self) -> Dict[str, Any]:
        """导出统计指标。"""
        raw_events = self.total_events_in
        raw_nodes = len(self.total_nodes_in)
        reduced_edges = self.total_edges_out
        reduced_nodes = len(self.total_nodes_out)

        edge_reduction_ratio = (1.0 - (reduced_edges / raw_events)) * 100.0 if raw_events > 0 else 0.0
        node_reduction_ratio = (1.0 - (reduced_nodes / raw_nodes)) * 100.0 if raw_nodes > 0 else 0.0
        elapsed_sec = self.elapsed_ns / 1_000_000_000.0
        throughput = (raw_events / elapsed_sec) if elapsed_sec > 0 else 0.0

        return {
            "algorithm": self.name,
            "raw_events": raw_events,
            "raw_nodes": raw_nodes,
            "reduced_edges": reduced_edges,
            "reduced_nodes": reduced_nodes,
            "edge_reduction_ratio_pct": round(edge_reduction_ratio, 2),
            "node_reduction_ratio_pct": round(node_reduction_ratio, 2),
            "elapsed_ms": round(elapsed_sec * 1000.0, 3),
            "throughput_events_per_sec": round(throughput, 1),
        }
