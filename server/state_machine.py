"""TraceSage-Studio 调查状态机控制器 (InvestigationStateMachine)。

控制各阶段状态转移，管理人机在环 (HITL) 协程挂起与租约超时降级。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional
from server.bus import EventStreamBus
from server.schemas import HitlRequestPayload, InvestigationStage


class InvestigationStateMachine:
    def __init__(self, task_id: str, bus: EventStreamBus, lease_timeout_sec: int = 300):
        self.task_id = task_id
        self.bus = bus
        self.lease_timeout_sec = lease_timeout_sec
        self.current_stage: InvestigationStage = InvestigationStage.PENDING
        
        self.hitl_event = asyncio.Event()
        self.active_hitl_request: Optional[HitlRequestPayload] = None
        self.human_decisions: Dict[str, str] = {}
        
        # 内存快照存储
        self.snapshot_nodes: Dict[str, Dict[str, Any]] = {}
        self.snapshot_edges: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, Any] = {}
        self.error_message: Optional[str] = None

    async def transition_to(self, new_stage: InvestigationStage, metadata: Optional[Dict[str, Any]] = None) -> None:
        """执行合法状态转移并广播 stage_changed 事件。"""
        self.current_stage = new_stage
        payload = {"stage": new_stage.value}
        if metadata:
            payload.update(metadata)
        await self.bus.emit("stage_changed", payload)

    async def record_graph_elements(
        self, nodes: Optional[List[Dict[str, Any]]] = None, edges: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """更新内部图快照，并向事件总线推送增量。"""
        if nodes:
            for n in nodes:
                self.snapshot_nodes[str(n.get("id"))] = n
        if edges:
            for e in edges:
                self.snapshot_edges[str(e.get("id") or e.get("event_id"))] = e

        await self.bus.emit_graph_delta_buffered(nodes=nodes, edges=edges)

    async def request_human_intervention(self, edge: Dict[str, Any], reason: str) -> str:
        """触发人在回路中断挂起协程，启动租约倒计时。"""
        edge_id = str(edge.get("id") or edge.get("event_id") or "unknown_edge")
        req_id = f"hitl_{self.task_id}_{time.time_ns()}"
        expire_at_ns = time.time_ns() + (self.lease_timeout_sec * 1_000_000_000)

        payload = HitlRequestPayload(
            request_id=req_id,
            task_id=self.task_id,
            edge_id=edge_id,
            reason=reason,
            edge=edge,
            expire_at_ns=expire_at_ns,
            timeout_seconds=self.lease_timeout_sec,
        )
        self.active_hitl_request = payload

        # 状态转移至 AWAITING_HITL
        await self.transition_to(
            InvestigationStage.AWAITING_HITL,
            {"request_id": req_id, "edge_id": edge_id, "timeout_seconds": self.lease_timeout_sec},
        )
        await self.bus.emit("hitl_pause", payload.model_dump())

        self.hitl_event.clear()
        try:
            # 挂起当前任务协程，等待人工通过 REST API 调用 submit_decision
            await asyncio.wait_for(self.hitl_event.wait(), timeout=self.lease_timeout_sec)
            decision = self.human_decisions.get(req_id, "exclude_benign")
        except asyncio.TimeoutError:
            # 租约超时执行阻断诚实降级：不伪造成果，转为 unexcluded
            decision = "unexcluded_timeout"
        finally:
            self.active_hitl_request = None

        return decision

    def submit_decision(self, request_id: str, decision: str) -> bool:
        """接收外部人工提交的判定，解除协程阻塞。"""
        if not self.active_hitl_request or self.active_hitl_request.request_id != request_id:
            return False
        self.human_decisions[request_id] = decision
        self.hitl_event.set()
        return True

    def fail(self, error: str) -> None:
        self.current_stage = InvestigationStage.FAILED
        self.error_message = error
