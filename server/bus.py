"""TraceSage-Studio 异步事件总线 (EventStreamBus)。

包含会话级异步队列、50ms 微批聚合与断线重连环形缓冲区。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional
from server.schemas import EventEnvelope


class EventStreamBus:
    def __init__(self, task_id: str, ring_buffer_size: int = 1000, batch_window_ms: float = 50.0):
        self.task_id = task_id
        self.queue: asyncio.Queue[EventEnvelope] = asyncio.Queue()
        self.ring_buffer: List[EventEnvelope] = []
        self.ring_buffer_size = ring_buffer_size
        self.batch_window_ms = batch_window_ms
        self._seq: int = 0
        self._lock = asyncio.Lock()

        # 微批聚合缓冲
        self._batch_nodes: Dict[str, Any] = {}
        self._batch_edges: Dict[str, Any] = {}
        self._flush_task: Optional[asyncio.Task] = None

    def _next_seq_id(self) -> str:
        self._seq += 1
        return f"evt_seq_{self._seq:06d}"

    async def emit(self, event_type: str, data: Dict[str, Any]) -> None:
        """立即发布一个独立信封事件。"""
        async with self._lock:
            envelope = EventEnvelope(
                id=self._next_seq_id(),
                event=event_type,
                task_id=self.task_id,
                timestamp_ns=time.time_ns(),
                data=data,
            )
            self.ring_buffer.append(envelope)
            if len(self.ring_buffer) > self.ring_buffer_size:
                self.ring_buffer.pop(0)

            await self.queue.put(envelope)

    async def emit_log(self, message: str, level: str = "info", source: str = "engine") -> None:
        """发送实时控制台审计日志。"""
        await self.emit("console_log", {
            "level": level,
            "source": source,
            "message": message,
            "timestamp_ns": time.time_ns(),
        })

    async def emit_progress(
        self, stage: str, percent: float, description: str, current_round: int = 0, processed_count: int = 0
    ) -> None:
        """发送细粒度多阶段调查进度。"""
        await self.emit("investigation_progress", {
            "stage": stage,
            "percent": round(percent, 1),
            "description": description,
            "current_round": current_round,
            "processed_count": processed_count,
        })

    async def emit_graph_delta_buffered(
        self, nodes: Optional[List[Dict[str, Any]]] = None, edges: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """将图节点与边加入微批缓冲区，50ms 内合并推送。"""
        async with self._lock:
            if nodes:
                for n in nodes:
                    self._batch_nodes[str(n.get("id"))] = n
            if edges:
                for e in edges:
                    self._batch_edges[str(e.get("id") or e.get("event_id"))] = e

            # 若累积达到 100 个元素则立即刷新
            if len(self._batch_nodes) + len(self._batch_edges) >= 100:
                await self._flush_unlocked()
            elif self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._scheduled_flush())

    async def _scheduled_flush(self) -> None:
        await asyncio.sleep(self.batch_window_ms / 1000.0)
        async with self._lock:
            await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        if not self._batch_nodes and not self._batch_edges:
            return
        payload = {
            "nodes": list(self._batch_nodes.values()),
            "edges": list(self._batch_edges.values()),
        }
        self._batch_nodes.clear()
        self._batch_edges.clear()

        envelope = EventEnvelope(
            id=self._next_seq_id(),
            event="graph_delta",
            task_id=self.task_id,
            timestamp_ns=time.time_ns(),
            data=payload,
        )
        self.ring_buffer.append(envelope)
        if len(self.ring_buffer) > self.ring_buffer_size:
            self.ring_buffer.pop(0)

        await self.queue.put(envelope)

    async def flush(self) -> None:
        """主动强制清空所有待发图增量微批。"""
        async with self._lock:
            await self._flush_unlocked()

    def get_events_after(self, last_event_id: str) -> List[EventEnvelope]:
        """依据客户端提交的 Last-Event-ID 追溯未发事件。"""
        try:
            seq_num = int(last_event_id.replace("evt_seq_", ""))
            return [e for e in self.ring_buffer if int(e.id.replace("evt_seq_", "")) > seq_num]
        except (ValueError, AttributeError):
            return list(self.ring_buffer)
