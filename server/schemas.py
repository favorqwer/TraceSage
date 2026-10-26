"""TraceSage-Studio 强类型数据模型与 CloudEvents 契约规范。"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class InvestigationStage(str, Enum):
    PENDING = "PENDING"
    EXTRACTING_CLOSURE = "EXTRACTING_CLOSURE"
    MATCHING_RULES = "MATCHING_RULES"
    LLM_ARBITRATING = "LLM_ARBITRATING"
    AWAITING_HITL = "AWAITING_HITL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class NodeData(BaseModel):
    id: str
    label: Literal["Process", "File", "Network"]
    host_id: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class EdgeData(BaseModel):
    id: str
    source: str
    target: str
    type: str
    action: str
    syscall: str
    start_ns: int
    end_ns: Optional[int] = None
    result: Optional[int] = None
    status: Literal["confirmed", "unexcluded", "excluded"] = "confirmed"
    confirmed_by: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphDeltaPayload(BaseModel):
    nodes: List[NodeData] = Field(default_factory=list)
    edges: List[EdgeData] = Field(default_factory=list)
    is_initial_batch: bool = False


class RuleMatchPayload(BaseModel):
    edge_id: str
    motif_id: str
    motif_name: str = ""
    confidence: float = 1.0
    reason: str = ""


class LlmTokenPayload(BaseModel):
    bundle_id: str
    token: str
    is_thought: bool = True


class ConsoleLogPayload(BaseModel):
    level: Literal["info", "warn", "error", "success"] = "info"
    source: str = "engine"
    message: str
    timestamp_ns: int


class ProgressPayload(BaseModel):
    stage: str
    percent: float
    description: str
    current_round: int = 0
    total_rounds: Optional[int] = None
    processed_count: int = 0


class HitlRequestPayload(BaseModel):
    request_id: str
    task_id: str
    edge_id: str
    reason: str
    edge: Dict[str, Any]
    expire_at_ns: int
    timeout_seconds: int = 300


class EventEnvelope(BaseModel):
    id: str
    event: str
    task_id: str
    timestamp_ns: int
    data: Dict[str, Any] = Field(default_factory=dict)


class InvestigationParameters(BaseModel):
    matcher_min_lor: float = Field(default=2.5, ge=0.0, le=10.0, description="基模准入对数优势比(LOR)置信下界阈值")
    matcher_min_conf: float = Field(default=0.50, ge=0.0, le=1.0, description="基模准入最小精确率阈值")
    max_closure_rounds: Optional[int] = Field(default=None, ge=1, le=30, description="因果闭包最大迭代展开轮数")
    hitl_enabled: bool = Field(default=False, description="是否启用人在回路中断审查")
    hitl_lease_timeout_sec: int = Field(default=120, ge=30, le=600, description="人在回路租约等待超时秒数")
    llm_budget_calls: int = Field(default=10, ge=1, le=50, description="慢速通道大模型仲裁配额上限")
    llm_temperature: float = Field(default=0.0, ge=0.0, le=1.0, description="大模型采样温度")


class InvestigationCreateRequest(BaseModel):
    scenario_name: str
    mode: Literal["rules", "hybrid", "llm-only"] = "rules"
    rules_from: Literal["frozen", "fresh"] = "frozen"
    params: InvestigationParameters = Field(default_factory=InvestigationParameters)


class DecisionSubmitRequest(BaseModel):
    request_id: str
    edge_id: str
    decision: Literal["confirm_attack", "exclude_benign"]
    analyst_notes: str = ""


class ScenarioInfo(BaseModel):
    name: str
    database: str
    description: str
    poi: Dict[str, Any] = Field(default_factory=dict)
