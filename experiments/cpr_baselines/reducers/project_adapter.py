"""TraceSage 项目当前图构建与折叠算法适配器。

接入 TraceSage 主干规范 (docs/agents/graph-model.md 与 parser/README.md)：
1. 物理进程身份生命周期管理：
   - 维护 (host_id, pid) -> start_ns 出生时间戳；
   - execve 时进程重置身份并派生 (old_proc -> new_proc) 与 (image_file -> new_proc) 因果边；
2. 内容三元组与双轨因果聚合 (provenance/closure/fold.py)：
   - (causal_src, syscall, causal_dst, effect) 作为聚合主键；
   - 保留 members 进程集合与两端 identities 属性；
   - 严格隔离成功与失败调用 (ok / err 双轨并行)。
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from ..base_reducer import BaseGraphReducer
from ..event import ActionKind, CompressedEdge, EntityKind, TraceEvent


class ProjectCurrentReducer(BaseGraphReducer):
    """TraceSage 当前主干因果图构建与三元组折叠算法适配器。"""

    def __init__(self):
        super().__init__(name="TraceSage_Current")
        # 进程生命周期表: (host_id, pid_str) -> current_start_ns
        self._proc_start_ns: Dict[Tuple[str, str], int] = {}
        # 折叠边主键缓存: (src_key, syscall, dst_key, effect) -> CompressedEdge
        self._folded_edges: Dict[Tuple[str, str, str, str], CompressedEdge] = {}

    def reset(self) -> None:
        """重置状态。"""
        super().reset()
        self._proc_start_ns.clear()
        self._folded_edges.clear()

    def _resolve_process_key(self, host_id: str, raw_proc_id: str, ts_ns: int) -> str:
        """解析并返回符合主干规范的进程物理唯一主键 host:pid:start_ns。"""
        parts = raw_proc_id.split(":")
        if len(parts) >= 2:
            pid = parts[1]
        else:
            pid = raw_proc_id

        key = (host_id, pid)
        if key not in self._proc_start_ns:
            self._proc_start_ns[key] = ts_ns

        start_ns = self._proc_start_ns[key]
        return f"{raw_proc_id}:{start_ns}"

    def process_event(self, event: TraceEvent) -> Optional[CompressedEdge]:
        """在线消费一条事件并应用 TraceSage 主干建图与折叠规则。"""
        t0 = time.perf_counter_ns()
        self.record_input_event(event)

        sc = event.syscall.lower()
        host = event.host_id
        ts = event.ts_ns
        effect = "ok" if event.is_success else "err"

        # 1. 进程生命周期与 execve 映像替换处理 (主干规范)
        if sc in ("execve", "execveat") and event.src_kind == EntityKind.PROCESS:
            parts = event.src_id.split(":")
            pid = parts[1] if len(parts) >= 2 else event.src_id
            old_start = self._proc_start_ns.get((host, pid), ts)
            old_proc_key = f"{event.src_id}:{old_start}"

            # execve 演化为新进程身份
            new_start = ts
            self._proc_start_ns[(host, pid)] = new_start
            new_proc_key = f"{event.src_id}:{new_start}"

            # TraceSage 主干因果公理：execve 产生两端转移
            # (1) 旧进程 -> 新进程 ProcessToProcess
            fold_key_p2p = (old_proc_key, sc, new_proc_key, effect)
            if fold_key_p2p in self._folded_edges:
                edge = self._folded_edges[fold_key_p2p]
                edge.end_ns = max(edge.end_ns, ts)
                edge.instances += 1
            else:
                p2p_edge = CompressedEdge(
                    src_id=old_proc_key,
                    src_kind=EntityKind.PROCESS,
                    syscall=sc,
                    action=ActionKind.EXEC,
                    dst_id=new_proc_key,
                    dst_kind=EntityKind.PROCESS,
                    start_ns=ts,
                    end_ns=ts,
                    instances=1,
                    total_bytes=0,
                    success_count=1 if event.is_success else 0,
                    fail_count=0 if event.is_success else 1,
                    metadata={"members": {old_proc_key, new_proc_key}},
                )
                self._folded_edges[fold_key_p2p] = p2p_edge
                self._commit_edge(p2p_edge)

            # (2) 目标可执行文件 -> 新进程 FileToProcess
            fold_key_f2p = (event.dst_id, "exec", new_proc_key, effect)
            if fold_key_f2p in self._folded_edges:
                edge = self._folded_edges[fold_key_f2p]
                edge.end_ns = max(edge.end_ns, ts)
                edge.instances += 1
            else:
                f2p_edge = CompressedEdge(
                    src_id=event.dst_id,
                    src_kind=event.dst_kind,
                    syscall="exec",
                    action=ActionKind.EXEC,
                    dst_id=new_proc_key,
                    dst_kind=EntityKind.PROCESS,
                    start_ns=ts,
                    end_ns=ts,
                    instances=1,
                    total_bytes=event.bytes_count,
                    success_count=1 if event.is_success else 0,
                    fail_count=0 if event.is_success else 1,
                    metadata={"members": {new_proc_key}},
                )
                self._folded_edges[fold_key_f2p] = f2p_edge
                self._commit_edge(f2p_edge)

            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return None

        # 2. 常规系统调用：解析端点物理标识
        proc_identity: Optional[str] = None
        if event.causal_src_kind == EntityKind.PROCESS:
            c_src = self._resolve_process_key(host, event.causal_src_id, ts)
            proc_identity = c_src
        else:
            c_src = event.causal_src_id

        if event.causal_dst_kind == EntityKind.PROCESS:
            c_dst = self._resolve_process_key(host, event.causal_dst_id, ts)
            proc_identity = c_dst
        else:
            c_dst = event.causal_dst_id

        # 3. 双轨因果内容三元组折叠 (src, syscall, dst, effect)
        fold_key = (c_src, event.syscall, c_dst, effect)

        if fold_key in self._folded_edges:
            edge = self._folded_edges[fold_key]
            edge.end_ns = max(edge.end_ns, ts)
            edge.instances += 1
            edge.total_bytes += event.bytes_count
            if event.is_success:
                edge.success_count += 1
            else:
                edge.fail_count += 1
            if proc_identity and "members" in edge.metadata:
                edge.metadata["members"].add(proc_identity)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return None

        # 首次出现该内容三元组，建立新折叠边并记录多实例成员归属
        meta: Dict[str, Any] = {}
        if proc_identity:
            meta["members"] = {proc_identity}

        new_edge = CompressedEdge(
            src_id=c_src,
            src_kind=event.causal_src_kind,
            syscall=event.syscall,
            action=event.action_kind,
            dst_id=c_dst,
            dst_kind=event.causal_dst_kind,
            start_ns=ts,
            end_ns=ts,
            instances=1,
            total_bytes=event.bytes_count,
            success_count=1 if event.is_success else 0,
            fail_count=0 if event.is_success else 1,
            metadata=meta,
        )
        self._folded_edges[fold_key] = new_edge
        self._commit_edge(new_edge)

        self.elapsed_ns += (time.perf_counter_ns() - t0)
        return new_edge

    def _commit_edge(self, edge: CompressedEdge) -> None:
        """提交保留的边并更新输出统计。"""
        self.total_edges_out += 1
        self.total_nodes_out.add(edge.src_id)
        self.total_nodes_out.add(edge.dst_id)

    def finish(self) -> List[CompressedEdge]:
        """流结束冲刷。"""
        return list(self._folded_edges.values())

    def export_graph(self) -> Tuple[Set[str], List[CompressedEdge]]:
        """导出当前图。"""
        return set(self.total_nodes_out), list(self._folded_edges.values())
