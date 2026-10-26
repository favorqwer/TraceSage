"""TraceSage-Studio FastAPI 路由端点定义。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from server.bus import EventStreamBus
from server.config import settings
from server.engine_adapter import AsyncPipelineExecutor
from server.schemas import (
    DecisionSubmitRequest,
    InvestigationCreateRequest,
    InvestigationStage,
    ScenarioInfo,
)
from server.state_machine import InvestigationStateMachine

router = APIRouter(prefix="/api/v1")

# 活跃任务上下文存储
TASKS: Dict[str, Dict[str, Any]] = {}


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "TraceSage-Studio"}


@router.get("/scenarios", response_model=List[ScenarioInfo])
async def list_available_scenarios():
    """获取所有可用评测场景与其 POI 锚点信息。"""
    scenarios_file = settings.SCENARIOS_FILE_PATH
    if not scenarios_file.exists():
        raise HTTPException(status_code=500, detail="Scenarios configuration file not found")

    with open(scenarios_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = []
    scenarios_dict = data.get("scenarios", {})
    for name, item in scenarios_dict.items():
        result.append(
            ScenarioInfo(
                name=name,
                database=item.get("database", ""),
                description=item.get("description", ""),
                poi=item.get("poi", {}),
            )
        )
    return result


@router.post("/investigations")
async def create_investigation(req: InvestigationCreateRequest):
    """启动一个新的调查任务并创建其异步事件流。"""
    task_id = f"inv_{req.scenario_name}_{int(asyncio.get_event_loop().time() * 1000)}"
    bus = EventStreamBus(task_id, ring_buffer_size=2000, batch_window_ms=50.0)
    sm = InvestigationStateMachine(task_id, bus, lease_timeout_sec=req.params.hitl_lease_timeout_sec)
    executor = AsyncPipelineExecutor(task_id, req.scenario_name, req.mode, req.rules_from, sm, bus, params=req.params)

    TASKS[task_id] = {
        "task_id": task_id,
        "scenario_name": req.scenario_name,
        "mode": req.mode,
        "bus": bus,
        "sm": sm,
        "executor": executor,
    }

    # 启动后台异步任务
    asyncio.create_task(executor.execute())

    return {
        "task_id": task_id,
        "scenario_name": req.scenario_name,
        "status": InvestigationStage.PENDING.value,
    }


@router.get("/investigations/{task_id}/events")
async def stream_events(task_id: str, last_event_id: Optional[str] = Header(None)):
    """建立 SSE 长连接，流式推送图增量、规则匹配与人在回路挂起事件。"""
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    bus: EventStreamBus = TASKS[task_id]["bus"]
    sm: InvestigationStateMachine = TASKS[task_id]["sm"]

    async def event_generator():
        # 若带有 Last-Event-ID，先重放断线期间缺失的事件
        if last_event_id:
            missed_events = bus.get_events_after(last_event_id)
            for evt in missed_events:
                yield f"id: {evt.id}\nevent: {evt.event}\ndata: {evt.model_dump_json()}\n\n"

        while True:
            # 等待新事件
            try:
                envelope = await asyncio.wait_for(bus.queue.get(), timeout=15.0)
                yield f"id: {envelope.id}\nevent: {envelope.event}\ndata: {envelope.model_dump_json()}\n\n"
                bus.queue.task_done()
                # 若任务终止则安全关闭长连接
                if envelope.event == "stage_changed" and envelope.data.get("stage") in (
                    InvestigationStage.COMPLETED.value,
                    InvestigationStage.FAILED.value,
                ):
                    break
            except asyncio.TimeoutError:
                # 保持心跳包
                yield f": ping\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/investigations/{task_id}/graph")
async def get_graph_snapshot(task_id: str):
    """获取当前任务的完整图快照（用于首屏刷新或断线重连全量重置）。"""
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    sm: InvestigationStateMachine = TASKS[task_id]["sm"]
    return {
        "task_id": task_id,
        "stage": sm.current_stage.value,
        "nodes": list(sm.snapshot_nodes.values()),
        "edges": list(sm.snapshot_edges.values()),
        "active_hitl_request": sm.active_hitl_request.model_dump() if sm.active_hitl_request else None,
    }


@router.post("/investigations/{task_id}/decision")
async def submit_human_decision(task_id: str, req: DecisionSubmitRequest):
    """提交人在回路决策，唤醒被挂起的状态机协程。"""
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    sm: InvestigationStateMachine = TASKS[task_id]["sm"]
    success = sm.submit_decision(req.request_id, req.decision)
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Decision rejected: request_id mismatch, lease expired, or task not in awaiting state",
        )

    return {"status": "accepted", "request_id": req.request_id, "decision": req.decision}
