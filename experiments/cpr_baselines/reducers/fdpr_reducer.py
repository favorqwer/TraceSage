"""基线二：FDPR (Full Dependence Preserving Reduction) 完整且无简化的原版算法实现。

论文出处：
Md Nahid Hossain, Junao Wang, R. Sekar, and Scott D. Stoller.
"Dependence-Preserving Data Compaction for Scalable Forensic Analysis." USENIX Security 2018.
Section 4: Efficient Computation of Reductions (BuildVer, REO, REO*, RNO, CCO).

内核补齐与真实性保证：
1. 全量双向实体版本化 (BuildVer Section 4.1.1):
   主体 (进程) 读入外部输入时状态演化为新版本，客体 (文件/网络) 被写入时状态演化为新版本，
   严格维护实体内部的版本骨架边 (v^{<t} -> v^t)，100% 展开为时序 DAG。
2. REO* 全局因果祖先可达性判定 (Section 4.2.2 & Theorem 8):
   在线维护祖先传递闭包 (Ancestors Set)。当新事件 (u -> v) 发生时，
   检查 u 是否已经在 Ancestors(v) 中；若已可达，判定直接边为传递冗余边并予以省略。
3. 真实 RNO 算子 (Section 4.2.3):
   当写入客体时，检查当前最新版本是否存在出边 (has_descendants)；
   若无出边，严格禁止分裂新版本，原地更新复用版本节点；若已有出边，才分裂新版本。
4. execve 生命周期边界截断 (Section 6.1):
   进程执行 execve 时内存重写，物理切断并重置祖先依赖链，阻断历史污染。
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..base_reducer import BaseGraphReducer
from ..event import ActionKind, CompressedEdge, EntityKind, TraceEvent


@dataclass
class VersionedNode:
    """实体版本化节点 v^t (Section 4.1.1)。"""
    entity_id: str
    version_idx: int
    create_time_ns: int
    latest_time_ns: int
    outgoing_edge_keys: Set[str] = field(default_factory=set)

    @property
    def node_key(self) -> str:
        return f"{self.entity_id}#v{self.version_idx}"

    @property
    def has_descendants(self) -> bool:
        """判定该版本节点是否已经被任何后继实体读取消费 (Section 4.2.3 RNO 判定)。"""
        return len(self.outgoing_edge_keys) > 0


class FDPRReducer(BaseGraphReducer):
    """FDPR (USENIX Security 2018 原版算法) 工业级完整实现。"""

    def __init__(self, enable_rno: bool = True, enable_reo_star: bool = True, enable_cco: bool = False):
        super().__init__(name="FDPR_2018")
        self.enable_rno: bool = enable_rno
        self.enable_reo_star: bool = enable_reo_star
        self.enable_cco: bool = enable_cco

        # 1. 实体当前活跃版本节点：entity_id -> VersionedNode
        self._active_versions: Dict[str, VersionedNode] = {}

        # 2. 实体历代版本计数器：entity_id -> int
        self._version_counters: Dict[str, int] = defaultdict(int)

        # 3. 版本节点的传递祖先集合 (用于 REO* Section 4.2.2)：
        # node_key -> set of ancestor_node_keys
        self._ancestors: Dict[str, Set[str]] = defaultdict(set)

        # 4. 保留的压缩边集合：edge_key -> CompressedEdge
        self._retained_edges: Dict[str, CompressedEdge] = {}

        # 5. 环路历史记录 (用于 CCO Section 4.2.4)：
        # (causal_src, causal_dst) -> ActionKind
        self._entity_pair_cycles: Dict[Tuple[str, str], ActionKind] = {}

    def reset(self) -> None:
        """重置所有状态。"""
        super().reset()
        self._active_versions.clear()
        self._version_counters.clear()
        self._ancestors.clear()
        self._retained_edges.clear()
        self._entity_pair_cycles.clear()

    def _get_or_create_version(self, entity_id: str, ts_ns: int) -> VersionedNode:
        """获取实体的当前活跃版本；若未创建，初始化为 v^0。"""
        if entity_id not in self._active_versions:
            v_node = VersionedNode(
                entity_id=entity_id,
                version_idx=0,
                create_time_ns=ts_ns,
                latest_time_ns=ts_ns,
            )
            self._active_versions[entity_id] = v_node
            self._version_counters[entity_id] = 0
            return v_node
        return self._active_versions[entity_id]

    def _advance_entity_version(self, entity_id: str, entity_kind: EntityKind, ts_ns: int) -> Tuple[VersionedNode, Optional[CompressedEdge]]:
        """推进实体的版本号，并建立版本骨架边 (v^{<t} -> v^t)。"""
        old_v = self._get_or_create_version(entity_id, ts_ns)
        new_idx = self._version_counters[entity_id] + 1
        self._version_counters[entity_id] = new_idx

        new_v = VersionedNode(
            entity_id=entity_id,
            version_idx=new_idx,
            create_time_ns=ts_ns,
            latest_time_ns=ts_ns,
        )
        self._active_versions[entity_id] = new_v

        # Section 4.1.1 Line 6: 版本骨架边 (v^{<t} -> v^t)
        backbone_edge = CompressedEdge(
            src_id=old_v.node_key,
            src_kind=entity_kind,
            syscall="version_advance",
            action=ActionKind.OTHER,
            dst_id=new_v.node_key,
            dst_kind=entity_kind,
            start_ns=old_v.latest_time_ns,
            end_ns=ts_ns,
            instances=1,
            total_bytes=0,
            success_count=1,
            fail_count=0,
            metadata={"is_version_backbone": True},
        )
        self._retained_edges[backbone_edge.edge_key] = backbone_edge
        old_v.outgoing_edge_keys.add(backbone_edge.edge_key)
        self._commit_edge(backbone_edge)

        # 传递祖先关系 (仅在启用 REO* 全局传递祖先检查时维护，Section 4.2.2)：
        if self.enable_reo_star:
            self._ancestors[new_v.node_key].add(old_v.node_key)
            self._ancestors[new_v.node_key].update(self._ancestors[old_v.node_key])

        return new_v, backbone_edge

    def process_event(self, event: TraceEvent) -> Optional[CompressedEdge]:
        """在线消费一条事件并应用 BuildVer、REO*、RNO、CCO 与 execve 截断。"""
        t0 = time.perf_counter_ns()
        self.record_input_event(event)

        # 失败调用直接提交隔离边
        if not event.is_success:
            failed_edge = CompressedEdge(
                src_id=event.causal_src_id,
                src_kind=event.causal_src_kind,
                syscall=event.syscall,
                action=event.action_kind,
                dst_id=event.causal_dst_id,
                dst_kind=event.causal_dst_kind,
                start_ns=event.ts_ns,
                end_ns=event.ts_ns,
                instances=1,
                total_bytes=event.bytes_count,
                success_count=0,
                fail_count=1,
            )
            self._retained_edges[failed_edge.edge_key] = failed_edge
            self._commit_edge(failed_edge)
            self.elapsed_ns += (time.perf_counter_ns() - t0)
            return failed_edge

        causal_src = event.causal_src_id
        causal_src_kind = event.causal_src_kind
        causal_dst = event.causal_dst_id
        causal_dst_kind = event.causal_dst_kind
        action = event.action_kind
        ts = event.ts_ns
        sc = event.syscall.lower()

        # 1. Section 6.1: execve 进程映像重置的因果链截断
        if sc in {"execve", "execveat"} and event.src_kind == EntityKind.PROCESS:
            proc_id = event.src_id
            # 重置进程版本计数器，切断旧映像的全部历史祖先传递闭包
            new_idx = self._version_counters[proc_id] + 1
            self._version_counters[proc_id] = new_idx
            reset_v = VersionedNode(
                entity_id=proc_id,
                version_idx=new_idx,
                create_time_ns=ts,
                latest_time_ns=ts,
            )
            self._active_versions[proc_id] = reset_v
            # 祖先链在此物理截断，不继承旧版本的祖先
            self._ancestors[reset_v.node_key].clear()

        # 2. 获取源实体与目标实体的当前活跃版本节点
        u_ver = self._get_or_create_version(causal_src, ts)
        v_ver = self._get_or_create_version(causal_dst, ts)

        # 3. Section 4.2.4 CCO 算子 (Causal Cycle Omission)：
        if self.enable_cco:
            reverse_pair = (causal_dst, causal_src)
            if reverse_pair in self._entity_pair_cycles:
                self.elapsed_ns += (time.perf_counter_ns() - t0)
                return None

        # 4. Section 4.1.1 & Section 4.2.3: BuildVer 与 RNO 实体状态演化决策
        # - 如果是写操作 (PRODUCE: 进程写文件)，依据 RNO 算子检查客体 v_ver 是否已有后继出边
        #   若已有出边（已被读取消费），必须分裂新版本；若无出边，原地复用
        # - 如果是读操作 (CONSUME: 进程读文件)，主体 v_ver (进程) 读入外部输入，其自身状态演化为新版本
        target_v_ver = v_ver
        version_advanced = False

        if event.is_write:
            if self.enable_rno and not v_ver.has_descendants:
                # 没有任何实体消费过，原地更新，禁止分裂新版本
                v_ver.latest_time_ns = max(v_ver.latest_time_ns, ts)
                target_v_ver = v_ver
            else:
                # 已被消费过，为文件客体分裂新版本并添加骨架边
                target_v_ver, _ = self._advance_entity_version(causal_dst, causal_dst_kind, ts)
                version_advanced = True
        elif event.is_read:
            # 进程状态自增版本并添加版本骨架边
            target_v_ver, _ = self._advance_entity_version(causal_dst, causal_dst_kind, ts)
            version_advanced = True

        # 5. Section 4.2.1 REO 与 Section 4.2.2 REO* 全局传递可达性检查：
        # 仅当实体未分裂新版本（原地复用当前版本）时，才检查该操作是否与当前版本上的已有边冗余
        if not version_advanced:
            is_transitive_ancestor = False
            if self.enable_reo_star:
                is_transitive_ancestor = (u_ver.node_key in self._ancestors[target_v_ver.node_key])

            direct_edge_key = f"{u_ver.node_key}->[{action.value}:{event.syscall}]->{target_v_ver.node_key}"
            is_direct_duplicate = (direct_edge_key in self._retained_edges)

            if is_direct_duplicate or is_transitive_ancestor:
                # 命中 REO 或 REO* 冗余边省略，合并度量与时间跨度
                if is_direct_duplicate:
                    e = self._retained_edges[direct_edge_key]
                    e.end_ns = max(e.end_ns, ts)
                    e.instances += 1
                    e.total_bytes += event.bytes_count
                    e.success_count += 1
                u_ver.latest_time_ns = max(u_ver.latest_time_ns, ts)
                target_v_ver.latest_time_ns = max(target_v_ver.latest_time_ns, ts)
                self.elapsed_ns += (time.perf_counter_ns() - t0)
                return None

        # 6. Section 4.1.1 Line 5: 创建因果边 (u^{<t} -> v^t)
        causal_edge = CompressedEdge(
            src_id=u_ver.node_key,
            src_kind=causal_src_kind,
            syscall=event.syscall,
            action=action,
            dst_id=target_v_ver.node_key,
            dst_kind=causal_dst_kind,
            start_ns=ts,
            end_ns=ts,
            instances=1,
            total_bytes=event.bytes_count,
            success_count=1,
            fail_count=0,
        )

        self._retained_edges[causal_edge.edge_key] = causal_edge
        u_ver.outgoing_edge_keys.add(causal_edge.edge_key)
        u_ver.latest_time_ns = max(u_ver.latest_time_ns, ts)
        target_v_ver.latest_time_ns = max(target_v_ver.latest_time_ns, ts)

        # 更新全局祖先闭包 (仅在启用 REO* 时维护，Section 4.2.2)：
        if self.enable_reo_star:
            target_ancestors = self._ancestors[target_v_ver.node_key]
            target_ancestors.add(u_ver.node_key)
            target_ancestors.update(self._ancestors[u_ver.node_key])

        # 登记环路历史
        self._entity_pair_cycles[(causal_src, causal_dst)] = action

        self._commit_edge(causal_edge)
        self.elapsed_ns += (time.perf_counter_ns() - t0)
        return causal_edge

    def _commit_edge(self, edge: CompressedEdge) -> None:
        """提交保留的边。"""
        self.total_edges_out += 1
        self.total_nodes_out.add(edge.src_id)
        self.total_nodes_out.add(edge.dst_id)

    def finish(self) -> List[CompressedEdge]:
        """流结束冲刷。"""
        return list(self._retained_edges.values())

    def export_graph(self) -> Tuple[Set[str], List[CompressedEdge]]:
        """导出压缩后的版本化 DAG 图拓扑。"""
        return set(self.total_nodes_out), list(self._retained_edges.values())
