"""运行时统计聚合：只记数，不写文件、不碰图状态。"""

from __future__ import annotations

from .classify import Decision
from .events import Call
from .graph import Outcome
from .kinds import Bucket, Verdict
from .snapshots import StatsSnapshot


class RunStats:
    def __init__(self) -> None:
        self.param: dict[str, list[int]] = {}
        self.ops: dict[tuple, list[int]] = {}
        self.attempts: dict[tuple, list[int]] = {}
        self.unmapped: dict[str, int] = {}
        self.edges_by_action: dict[str, int] = {}
        self.edges_by_class: dict[str, int] = {}
        self.bad: dict[str, int] = {}
        self.bad_samples: dict[str, list[str]] = {}
        self.by_type: dict[str, int] = {}
        self.enter_rows = 0
        self.exit_rows = 0
        self.no_owner_rows = 0
        self.single_line_rows = 0
        self.edge_rows = 0

    def count_row(self, row) -> None:
        self.by_type[row.call] = self.by_type.get(row.call, 0) + 1
        if row.is_enter:
            self.enter_rows += 1
        else:
            self.exit_rows += 1

    def add_bad(self, reason: str, sample: str) -> None:
        self.bad[reason] = self.bad.get(reason, 0) + 1
        samples = self.bad_samples.setdefault(reason, [])
        if len(samples) < 3:
            samples.append(sample[:200])

    def add(self, call: Call, decision: Decision, outcome: Outcome) -> None:
        if not outcome.buckets:
            raise RuntimeError(f"调用 {call.call}@{call.evt} 没有结算任何行")
        slot = self.param.setdefault(call.call, [0, 0, 0])
        slot[0] += 1
        if call.number("res") is not None:
            slot[1] += 1
        if any(b is Bucket.COVERED for _, b, _ in outcome.buckets):
            slot[2] += 1
        if decision.verdict is Verdict.UNMAPPED:
            self.unmapped[call.call] = self.unmapped.get(call.call, 0) + 1

        for proc, name, ts in outcome.ops:
            agg = self.ops.setdefault((proc, name), [0, ts, ts])
            agg[0] += 1
            agg[1] = min(agg[1], ts)
            agg[2] = max(agg[2], ts)
        for proc, verb, target, errno, ts in outcome.attempts:
            agg = self.attempts.setdefault((proc, verb, target, errno), [0, ts, ts])
            agg[0] += 1
            agg[1] = min(agg[1], ts)
            agg[2] = max(agg[2], ts)

        for edge in outcome.edges:
            self.edges_by_action[edge.action] = self.edges_by_action.get(edge.action, 0) + 1
            self.edges_by_class[edge.cls.value] = self.edges_by_class.get(edge.cls.value, 0) + 1
            self.edge_rows += 1

    def snapshot(self) -> StatsSnapshot:
        return StatsSnapshot(
            param={k: list(v) for k, v in self.param.items()},
            ops=dict(self.ops),
            attempts=dict(self.attempts),
            unmapped=dict(self.unmapped),
            edges_by_action=dict(self.edges_by_action),
            edges_by_class=dict(self.edges_by_class),
            bad=dict(self.bad),
            bad_samples={k: list(v) for k, v in self.bad_samples.items()},
            by_type=dict(self.by_type),
            enter_rows=self.enter_rows,
            exit_rows=self.exit_rows,
            no_owner_rows=self.no_owner_rows,
            single_line_rows=self.single_line_rows,
            edge_rows=self.edge_rows,
        )
