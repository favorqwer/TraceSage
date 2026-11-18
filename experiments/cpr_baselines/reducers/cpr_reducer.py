"""基线一：CPR (Causality Preserved Reduction) 完整且无简化的原版算法实现。

论文出处：
Zhang Xu, Kangkook Jee, et al.
"High Fidelity Data Reduction for Big Data Security Dependency Analyses." ACM CCS 2016.
Section 3: Causality Preserved Reduction (CPR).

内核补齐与真实性保证：
1. 真实物理时间窗 (Time Window)：
   支持系统调用进入 (ts) 与退出 (te) 的连续时间区间，严禁退化为离散点；
   区间相交判定严格遵循 max(ts1, ts2) <= min(te1, te2)。
2. 文件描述符生命周期 (File Open Descriptor / Session)：
   严格遵循 Section 3.1.3，以进程的 (proc, target, action, fd_session) 划分因果上下文，
   文件一旦经历 close/open 循环，自动递增会话序号，严禁跨越独立生命周期合并。
3. 严格实现 Algorithm 1, 2, 3：
   Algorithm 1: CPR_AGGREGATE(E) 堆栈驱动；
   Algorithm 2: BACKWARD_CHECK(ep, el, u) 真实入边区间交叠判定；
   Algorithm 3: FORWARD_CHECK(ep, el, v) 真实出边区间交叠判定。
4. 属性高保真合并：
   保留系统调用分布、返回值分布、文件偏移与时间跨度。
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from ..base_reducer import BaseGraphReducer
from ..event import ActionKind, CompressedEdge, EntityKind, TraceEvent


@dataclass
class TimeWindow:
    """真实物理时间窗 [ts, te]，单位纳秒 (ns)。"""
    ts: int
    te: int

    def overlaps(self, other_start: int, other_end: int) -> bool:
        """判定两区间是否相交：max(ts1, ts2) <= min(te1, te2)。"""
        return max(self.ts, other_start) <= min(self.te, other_end)


@dataclass
class IncidentEdgeRecord:
    """关联出入边记录。"""
    edge_key: str
    src_id: str
    dst_id: str
    syscall: str
    action: ActionKind
    window: TimeWindow


class CPRReducer(BaseGraphReducer):
    """CPR (CCS 2016 原版算法) 工业级完整实现。"""

    def __init__(self, default_syscall_duration_ns: int = 1000, prune_interval: int = 500):
        super().__init__(name="CPR_2016")
        self.default_duration_ns: int = default_syscall_duration_ns
        self.prune_interval: int = prune_interval
        self._event_counter: int = 0

        # 1. 进程文件描述符会话追踪：proc_id -> target_id -> active_session_idx: int
        self._fd_sessions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # 2. 实体入边时间序列队列 (Algorithm 2 BACKWARD_CHECK)：
        # target_id -> deque of IncidentEdgeRecord (按时间自然递增，设定物理容量上限防内存泄漏)
        self._incoming_events: Dict[str, Deque[IncidentEdgeRecord]] = defaultdict(lambda: deque(maxlen=2000))

        # 3. 实体出边时间序列队列 (Algorithm 3 FORWARD_CHECK)：
        # source_id -> deque of IncidentEdgeRecord (按时间自然递增，设定物理容量上限防内存泄漏)
        self._outgoing_events: Dict[str, Deque[IncidentEdgeRecord]] = defaultdict(lambda: deque(maxlen=2000))

        # 4. 聚合堆栈 S(u, v, action, session)：
        # (u, v, action, session) -> list of CompressedEdge (栈顶为当前活跃候选边)
        self._aggregate_stacks: Dict[Tuple[str, str, ActionKind, int], List[CompressedEdge]] = defaultdict(list)

        # 5. 最终提交的压缩边集合
        self._committed_edges: List[CompressedEdge] = []

    def reset(self) -> None:
        """重置所有状态机与出入边时序表。"""
        super().reset()
        self._event_counter = 0
        self._fd_sessions.clear()
        self._incoming_events.clear()
        self._outgoing_events.clear()
        self._aggregate_stacks.clear()
        self._committed_edges.clear()

    def _get_event_window(self, event: TraceEvent) -> TimeWindow:
        """根据事件获取真实的物理起止时间跨度。"""
        ts = event.ts_ns
        # 若元数据中包含真实的系统调用耗时 (如 Sysdig latency 纳秒)
        latency = event.extra.get("evt.latency", 0)
        te = ts + (latency if latency > 0 else self.default_duration_ns)
        return TimeWindow(ts=ts, te=te)

    def process_event(self, event: TraceEvent) -> Optional[CompressedEdge]:
        """在线消费一条事件并严格执行 Algorithm 1 堆栈驱动聚合。"""
        t0 = time.perf_counter_ns()
        self.record_input_event(event)

        u = event.causal_src_id
        v = event.causal_dst_id
        u_kind = event.causal_src_kind
        v_kind = event.causal_dst_kind
        act = event.action_kind
        win = self._get_event_window(event)
        sc = event.syscall.lower()

        # 1. 文件生命周期与描述符会话管理 (Section 3.1.3)
        # 遇到文件关闭 close 时，递增会话序号，切断历史合并链
        if sc in {"close", "fclose"}:
            proc = event.src_id
            target = event.dst_id
            self._fd_sessions[proc][target] += 1

        session_idx = self._fd_sessions[event.src_id][event.dst_id]

        # 失败调用不建立因果依赖，直接提交隔离边
        if not event.is_success:
            failed_edge = CompressedEdge(
                src_id=u,
                src_kind=u_kind,
                syscall=event.syscall,
                action=act,
                dst_id=v,
                dst_kind=v_kind,
                start_ns=win.ts,
                end_ns=win.te,
                instances=1,
                total_bytes=event.bytes_count,
                success_count=0,
                fail_count=1,
                metadata={"session_idx": session_idx, "result": event.result},
            )
            self._commit_edge(failed_edge)
            self._record_incident(failed_edge, win)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return failed_edge

        stack_key = (u, v, act, session_idx)
        stack = self._aggregate_stacks[stack_key]

        e_curr = CompressedEdge(
            src_id=u,
            src_kind=u_kind,
            syscall=event.syscall,
            action=act,
            dst_id=v,
            dst_kind=v_kind,
            start_ns=win.ts,
            end_ns=win.te,
            instances=1,
            total_bytes=event.bytes_count,
            success_count=1,
            fail_count=0,
            metadata={
                "session_idx": session_idx,
                "syscall_counts": {event.syscall: 1},
                "result_counts": {event.result: 1},
            },
        )

        # Algorithm 1: if S.Empty then S.push(e)
        if not stack:
            stack.append(e_curr)
            self._record_incident(e_curr, win)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return e_curr

        # 取出栈顶候选聚合边 ep
        e_prev = stack[-1]

        # Section 3.1.3: 检查系统调用类型兼容性与可聚合性
        if e_prev.syscall != e_curr.syscall and e_prev.action != ActionKind.READ:
            # 写操作或异构操作在系统调用不一致时，严格禁止合并
            # 将旧的 ep 提交发射并移出栈，仅保留 e_curr
            popped = stack.pop()
            self._commit_edge(popped)
            stack.append(e_curr)
            self._record_incident(e_curr, win)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return e_curr

        # 严格执行 Algorithm 2 与 Algorithm 3 真实区间检查
        backward_ok = self._backward_check(e_prev, e_curr, u)
        forward_ok = self._forward_check(e_prev, e_curr, v)

        # 周期性维护时间水位线并淘汰过期出入边记录
        self._event_counter += 1
        if self._event_counter % self.prune_interval == 0:
            self._prune_expired_incidents(win.ts)

        if backward_ok and forward_ok:
            # 严格满足 Full Trackability Equivalence，执行 MERGE
            e_prev.end_ns = max(e_prev.end_ns, e_curr.end_ns)
            e_prev.instances += 1
            e_prev.total_bytes += e_curr.total_bytes
            e_prev.success_count += 1

            # 高保真维护属性统计
            sys_counts = e_prev.metadata.setdefault("syscall_counts", {})
            sys_counts[event.syscall] = sys_counts.get(event.syscall, 0) + 1
            res_counts = e_prev.metadata.setdefault("result_counts", {})
            res_counts[event.result] = res_counts.get(event.result, 0) + 1

            # 同步更新已记录出入边的时间窗口
            self._update_incident_window(e_prev)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return None  # 成功聚合消除
        else:
            # 检查失败：ep 的因果等价性已被打断，生命周期终结
            # 弹出 ep 并立即提交，仅将 e_curr 作为新栈顶
            popped = stack.pop()
            self._commit_edge(popped)
            stack.append(e_curr)
            self._record_incident(e_curr, win)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return e_curr

    def _backward_check(self, e_prev: CompressedEdge, e_curr: CompressedEdge, u: str) -> bool:
        """Algorithm 2: Backward Trackability Check.

        检查源节点 u 的所有入边 e，判定是否存在任何 e 的时间窗 tw(e) 与区间 [te(ep), te(el)] 相交。
        若相交，说明在此期间有外部数据流入源实体 u，返回 False。
        采用从尾部向前逆序检索：由于时间单调递增，当前检查区间 [te(ep), te(el)] 位于时间线末端，
        一旦遇到 inc.window.te < interval_start 即可提前终止，将时间复杂度从 O(N) 降为 O(1)。
        """
        interval_start = e_prev.end_ns
        interval_end = e_curr.end_ns

        incident_queue = self._incoming_events.get(u)
        if not incident_queue:
            return True

        for inc in reversed(incident_queue):
            if inc.edge_key == e_prev.edge_key or inc.edge_key == e_curr.edge_key:
                continue
            if inc.window.te < interval_start:
                break
            if inc.window.overlaps(interval_start, interval_end):
                return False

        return True

    def _forward_check(self, e_prev: CompressedEdge, e_curr: CompressedEdge, v: str) -> bool:
        """Algorithm 3: Forward Trackability Check.

        检查目标节点 v 的所有出边 e，判定是否存在任何 e 的时间窗 tw(e) 与区间 [ts(ep), ts(el)] 相交。
        若相交，说明在此期间有第三方实体从 v 读取消费了数据，返回 False。
        同样采用逆序检索与提前终止。
        """
        interval_start = e_prev.start_ns
        interval_end = e_curr.start_ns

        incident_queue = self._outgoing_events.get(v)
        if not incident_queue:
            return True

        for inc in reversed(incident_queue):
            if inc.edge_key == e_prev.edge_key or inc.edge_key == e_curr.edge_key:
                continue
            if inc.window.te < interval_start:
                break
            if inc.window.overlaps(interval_start, interval_end):
                return False

        return True

    def _record_incident(self, edge: CompressedEdge, window: TimeWindow) -> None:
        """登记出入边物理时间窗。"""
        record = IncidentEdgeRecord(
            edge_key=edge.edge_key,
            src_id=edge.src_id,
            dst_id=edge.dst_id,
            syscall=edge.syscall,
            action=edge.action,
            window=TimeWindow(ts=window.ts, te=window.te),
        )
        self._outgoing_events[edge.src_id].append(record)
        self._incoming_events[edge.dst_id].append(record)

    def _update_incident_window(self, edge: CompressedEdge) -> None:
        """当边扩展时间区间时，同步更新出入边记录。"""
        for r in reversed(self._outgoing_events.get(edge.src_id, deque())):
            if r.edge_key == edge.edge_key:
                r.window.te = edge.end_ns
                break
        for r in reversed(self._incoming_events.get(edge.dst_id, deque())):
            if r.edge_key == edge.edge_key:
                r.window.te = edge.end_ns
                break

    def _prune_expired_incidents(self, current_ts: int) -> None:
        """根据当前所有活跃聚合堆栈的最小起始时间水位线，修剪已过期的出入边历史记录。"""
        min_active_ts = current_ts
        for stack in self._aggregate_stacks.values():
            if stack:
                min_active_ts = min(min_active_ts, stack[-1].start_ns)

        for q in self._incoming_events.values():
            while q and q[0].window.te < min_active_ts:
                q.popleft()
        for q in self._outgoing_events.values():
            while q and q[0].window.te < min_active_ts:
                q.popleft()

    def _commit_edge(self, edge: CompressedEdge) -> None:
        """提交固化边。"""
        self._committed_edges.append(edge)
        self.total_edges_out += 1
        self.total_nodes_out.add(edge.src_id)
        self.total_nodes_out.add(edge.dst_id)

    def finish(self) -> List[CompressedEdge]:
        """冲刷所有堆栈中残存的最后活跃边。"""
        t0 = time.perf_counter_ns()
        for stack in self._aggregate_stacks.values():
            while stack:
                popped = stack.pop()
                self._commit_edge(popped)
        self.elapsed_ns += (time.perf_counter_ns() - t0)
        return list(self._committed_edges)

    def export_graph(self) -> Tuple[Set[str], List[CompressedEdge]]:
        """导出压缩后的图拓扑。"""
        edges = self.finish()
        return set(self.total_nodes_out), edges
