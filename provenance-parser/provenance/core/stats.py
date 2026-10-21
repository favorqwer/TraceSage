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
        self.edges_by_syscall: dict[str, int] = {}
        self.edges_by_class: dict[str, int] = {}
        self.bad: dict[str, int] = {}
        self.bad_samples: dict[str, list[str]] = {}
        self.by_type: dict[str, int] = {}
        self.enter_rows = 0
        self.exit_rows = 0
        self.no_owner_rows = 0
        self.single_line_rows = 0
        self.edge_rows = 0
        self.result_source: dict[str, dict[str, int]] = {}
        # action -> [null, negative, zero, positive] 四分类（报告里的 result 哨兵）
        self.edge_result: dict[str, list[int]] = {}
        # 登记为建边的调用：总次数 vs 真正产出边的次数
        self.emit_calls: dict[str, int] = {}
        self.emit_calls_with_edge: dict[str, int] = {}
        # 零边调用的主因（取第一个非 COVERED 桶的 reason）
        self.emit_no_edge_reason: dict[str, str] = {}
        # 设计上该建边（value=L1/L2）但归了记账/丢弃：按调用名记次数
        self.capability_gaps: dict[str, tuple[int, str]] = {}
        # bind/listen：总次数 vs 能拿到监听地址的次数
        self.endpoint_total = 0
        self.endpoint_with_edge = 0
        self.pid_present_rows = 0
        self.missing_by_field: dict[str, dict[str, int]] = {}

    def count_row(self, row) -> None:
        self.by_type[row.call] = self.by_type.get(row.call, 0) + 1
        if row.pid > 0:
            self.pid_present_rows += 1
        for field in row.na_fields:
            by_type = self.missing_by_field.setdefault(field, {})
            by_type[row.call] = by_type.get(row.call, 0) + 1
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
        # 口径必须与边上的 res 同源（Call.result 优先 %evt.rawres），
        # 否则报告里的“能取到返回值的条数”永远无法与 edges.csv 对账。
        if call.result is not None:
            slot[1] += 1
            origin = call.result_source
            if origin is not None:
                per = self.result_source.setdefault(
                    call.call, {"rawres": 0, "args": 0}
                )
                per[origin] += 1
        if any(b is Bucket.COVERED for _, b, _ in outcome.buckets):
            slot[2] += 1
        if decision.verdict is Verdict.UNMAPPED:
            self.unmapped[call.call] = self.unmapped.get(call.call, 0) + 1

        # 「登记但不产边」：动词表声明建边，实际一条边也没产出
        if decision.verdict is Verdict.EMIT:
            self.emit_calls[call.call] = self.emit_calls.get(call.call, 0) + 1
            if outcome.edges:
                self.emit_calls_with_edge[call.call] = (
                    self.emit_calls_with_edge.get(call.call, 0) + 1
                )
            else:
                reason = ""
                for _, bucket, why in outcome.buckets:
                    if bucket is not Bucket.COVERED:
                        reason = why or bucket.value
                        break
                self.emit_no_edge_reason[call.call] = reason or "unknown"
        # 「能力缺口」：设计等级 L1/L2 却因为拿不到客体而归了记账/丢弃
        elif decision.verdict in (Verdict.OPS, Verdict.DROP) and decision.value in ("L1", "L2"):
            count, value = self.capability_gaps.get(call.call, (0, decision.value))
            self.capability_gaps[call.call] = (count + 1, value)
        # 监听端点能否拿到地址（bind/TCP listen 的数据源缺口）
        if call.call in ("bind", "listen"):
            self.endpoint_total += 1
            if outcome.edges:
                self.endpoint_with_edge += 1

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
            self.edges_by_syscall[edge.syscall] = self.edges_by_syscall.get(edge.syscall, 0) + 1
            self.edges_by_class[edge.cls.value] = self.edges_by_class.get(edge.cls.value, 0) + 1
            self.edge_rows += 1
            bins = self.edge_result.setdefault(edge.action, [0, 0, 0, 0])
            if edge.result is None:
                bins[0] += 1
            elif edge.result < 0:
                bins[1] += 1
            elif edge.result == 0:
                bins[2] += 1
            else:
                bins[3] += 1

    def snapshot(self) -> StatsSnapshot:
        return StatsSnapshot(
            param={k: list(v) for k, v in self.param.items()},
            ops=dict(self.ops),
            attempts=dict(self.attempts),
            unmapped=dict(self.unmapped),
            edges_by_action=dict(self.edges_by_action),
            edges_by_syscall=dict(self.edges_by_syscall),
            edges_by_class=dict(self.edges_by_class),
            bad=dict(self.bad),
            bad_samples={k: list(v) for k, v in self.bad_samples.items()},
            by_type=dict(self.by_type),
            enter_rows=self.enter_rows,
            exit_rows=self.exit_rows,
            no_owner_rows=self.no_owner_rows,
            single_line_rows=self.single_line_rows,
            edge_rows=self.edge_rows,
            result_source={k: dict(v) for k, v in self.result_source.items()},
            edge_result={k: list(v) for k, v in self.edge_result.items()},
            emit_calls=dict(self.emit_calls),
            emit_calls_with_edge=dict(self.emit_calls_with_edge),
            emit_no_edge_reason=dict(self.emit_no_edge_reason),
            capability_gaps=dict(self.capability_gaps),
            endpoint_total=self.endpoint_total,
            endpoint_with_edge=self.endpoint_with_edge,
            pid_present_rows=self.pid_present_rows,
            missing_by_field={k: dict(v) for k, v in self.missing_by_field.items()},
        )
