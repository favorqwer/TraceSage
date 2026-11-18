"""Rule KG 的数据结构。

这些节点只存在于规则知识图谱，不回写 `attack-*-v2` 溯源场景库。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Hop:
    motif_id: str
    index: int
    src_role: str
    syscall: str
    dst_role: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Motif:
    motif_id: str
    name: str
    hops: int
    role_chain: List[str]
    syscall_chain: List[str]
    support_scenarios: List[str]
    admitted: bool
    source: str
    version: str
    stats: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    case_id: str
    description: str = ""
    attack_phases: List[str] = field(default_factory=list)
    source_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCard:
    motif_id: str
    motif_name: str
    hops: int
    hop_chain: List[Dict[str, Any]]
    matched_edges: List[List[str]]
    coverage: float
    attack_hits: int
    background_hits: int
    ignore_hits: int
    precision: Optional[float]
    cases: List[str]
    source: str
    version: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
