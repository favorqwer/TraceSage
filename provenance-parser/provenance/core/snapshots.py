"""收尾快照：报告只读这些值对象，不再碰运行中的 Ledger / State / GraphSink。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit import Audit
from .graph import Node
from .kinds import NodeKey


@dataclass(slots=True)
class LedgerSnapshot:
    buckets: dict[str, int]
    equation: dict[str, Any]
    top_reasons: list[tuple[str, int]]
    gaps: dict[str, int]
    ingested: int
    settled: int
    abnormal: int


@dataclass(slots=True)
class StatsSnapshot:
    param: dict[str, list[int]]
    ops: dict[Any, list[int]]
    attempts: dict[Any, list[int]]
    unmapped: dict[str, int]
    edges_by_action: dict[str, int]
    edges_by_class: dict[str, int]
    bad: dict[str, int]
    bad_samples: dict[str, list[str]]
    by_type: dict[str, int]
    enter_rows: int
    exit_rows: int
    no_owner_rows: int
    single_line_rows: int
    edge_rows: int


@dataclass(slots=True)
class GraphSnapshot:
    nodes: dict[NodeKey, Node]
    total: int
    by_label: dict[str, int]
    top_out: list[tuple[NodeKey, int]]
    top_in: list[tuple[NodeKey, int]]
    written_nodes: int
    written_edges: int


@dataclass(slots=True)
class StateSnapshot:
    proc: dict[str, int]
    fds: dict[str, int]
    containers: list[dict[str, object]]


@dataclass(slots=True)
class RunSnapshot:
    scenario: str
    host_id: str
    scap: str
    backend: str
    dry_run: bool
    database: str
    elapsed_s: float
    coverage: dict[str, int]
    ledger: LedgerSnapshot
    stats: StatsSnapshot
    graph: GraphSnapshot
    state: StateSnapshot
    audit: Audit | None
    node_registry_max: int
