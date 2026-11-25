"""研究点二第一阶段核心建图：按需最小版本分裂构建实体版本有向无环图（Versioned DAG）。

单遍严格全序扫描预处理后的事件集合，同时完成：
- 问题 2：实体按需升版本号（旧版本发出出边后冻结不再接收新入边）+ 外部网络拆向，数学保证 0 环；
- 问题 3：同一对版本节点间的连续重复同类调用自动折叠为 1 条逻辑操作边；
- 问题 4：同 event_id 成对双边（exec/rename）归组标注，同端点紧邻伴随调用（accept+recv、create+write、connect+send）归并；
- 问题 5：文件删除/截断断开状态延续边，随后从 poi 二次反向修剪清除不再通向 poi 的死端分支（常驻进程的时间跨度惩罚交由第三阶段贝叶斯网络按连续时间间隔特征建模，不在第一阶段使用固定秒数硬切断）。
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from attack_path.loader import EntityAttr, RawEvent
from attack_path.preprocess import PreprocessedScenario

# 同时间戳 / 同 event_id 的固定关系优先级：流入进程（n2p/f2p/p2p）排在流出进程（p2f/p2n）之前，
# 保证同 event_id 的 rename 严格按「旧文件 -> 进程 -> 新文件」顺序衔接。
_REL_RANK: dict[str, int] = {
    "n2p": 0,
    "f2p": 1,
    "p2p": 2,
    "p2f": 3,
    "p2n": 4,
}

# 紧邻伴随系统调用操作家族映射（问题 4）：仅在落入完全相同的 (源版本节点, 目标版本节点, rel) 时归并。
_COMPANION_FAMILY: dict[tuple[str, str], str] = {
    ("n2p", "accept"): "net_recv",
    ("n2p", "recv"): "net_recv",
    ("p2f", "create"): "file_write",
    ("p2f", "write"): "file_write",
    ("p2n", "connect"): "net_send",
    ("p2n", "send"): "net_send",
}

_FILE_RESET_ACTIONS = frozenset({"unlink", "truncate"})


@dataclass(frozen=True)
class DAGBuildConfig:
    """实体版本有向无环图构建配置。"""

    merge_parallel_edges: bool = True
    merge_companion_syscalls: bool = True
    fold_causal_equivalent_rounds: bool = True
    break_file_delete_carry: bool = True
    prune_after_breaks: bool = True
    verify_acyclic: bool = True


@dataclass(frozen=True)
class VersionNode:
    """实体状态版本节点（如 Process:h1|host|500|900@v1）。"""

    node_id: str
    entity_id: str
    kind: str
    key: str
    version: int
    first_ns: int
    last_ns: int
    is_poi_target: bool = False
    is_candidate_entry: bool = False
    entity_attr: Optional[EntityAttr] = None


@dataclass(frozen=True)
class LogicEdge:
    """压缩后的逻辑有向边（操作边 op 或同实体状态延续边 state_carry）。"""

    edge_id: str
    src_node_id: str
    dst_node_id: str
    edge_kind: str  # "op" | "state_carry"
    rel: str
    primary_action: str
    actions: tuple[str, ...]
    raw_event_ids: tuple[str, ...]
    kernel_event_ids: tuple[int, ...]
    paired_kernel_event_ids: tuple[int, ...]
    event_count: int
    start_ns: int
    end_ns: int
    is_poi: bool = False
    confirmed_count: int = 0
    unexcluded_count: int = 0
    verdicts: tuple[str, ...] = field(default_factory=tuple)
    bundle_triples: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DAGStats:
    """实体版本图规模、压缩效果与校验统计。"""

    input_pruned_events: int
    retained_raw_events: int
    unique_entities_before_versioning: int
    version_nodes: int
    op_edges: int
    carry_edges: int
    total_edges: int
    poi_edges: int
    candidate_entries: int
    max_in_degree: int
    max_out_degree: int
    parallel_events_folded: int
    causal_rounds_folded: int
    companion_edges_merged: int
    paired_kernel_groups: int
    file_carry_breaks: int
    secondary_pruned_nodes: int
    secondary_pruned_edges: int
    is_acyclic: bool

    @property
    def event_compression_ratio(self) -> float:
        if self.input_pruned_events <= 0:
            return 0.0
        return 1.0 - (self.op_edges / self.input_pruned_events)


@dataclass(frozen=True)
class VersionedDAG:
    """第一阶段最终产出的实体版本有向无环图（零环、全量可回溯至原始事件）。"""

    scenario: str
    database: str
    nodes: dict[str, VersionNode]
    edges: dict[str, LogicEdge]
    in_edges: dict[str, tuple[str, ...]]
    out_edges: dict[str, tuple[str, ...]]
    poi_edge_ids: tuple[str, ...]
    poi_node_ids: tuple[str, ...]
    candidate_entry_ids: tuple[str, ...]
    topo_order: tuple[str, ...]
    stats: DAGStats


@dataclass
class _MutableNode:
    node_id: str
    entity_id: str
    kind: str
    key: str
    version: int
    epoch: int
    first_ns: int
    last_ns: int
    entity_attr: Optional[EntityAttr]
    reach_mask: int = 0
    direct_in_mask: int = 0
    input_gen: int = 0
    has_outgoing: bool = False


@dataclass
class _MutableEdge:
    edge_id: str
    src_node_id: str
    dst_node_id: str
    edge_kind: str
    rel: str
    primary_action: str
    actions: list[str]
    raw_event_ids: list[str]
    kernel_event_ids: list[int]
    start_ns: int
    end_ns: int
    dst_input_gen: int = 0
    is_poi: bool = False
    confirmed_count: int = 0
    unexcluded_count: int = 0
    verdicts: set[str] = field(default_factory=set)
    bundle_triples: set[tuple[str, str, str]] = field(default_factory=set)


def _event_sort_key(ev: RawEvent) -> tuple[int, int, int, str, str]:
    ts = ev.start_ns if ev.start_ns is not None else -1
    return (ts, ev.event_id, _REL_RANK.get(ev.rel, 9), ev.action, ev.id)


def _action_family(rel: str, action: str, *, merge_companion: bool) -> str:
    if merge_companion:
        fam = _COMPANION_FAMILY.get((rel, action))
        if fam is not None:
            return fam
    return action


def _kahn_topological_sort(
    node_ids: set[str],
    edges: dict[str, LogicEdge],
) -> tuple[str, ...]:
    """Kahn 算法执行拓扑排序；若存在任意有向环则立即抛错。"""
    in_deg: dict[str, int] = {nid: 0 for nid in node_ids}
    adj: dict[str, list[str]] = defaultdict(list)
    for edge in edges.values():
        adj[edge.src_node_id].append(edge.dst_node_id)
        in_deg[edge.dst_node_id] += 1

    ready = deque(sorted(nid for nid, deg in in_deg.items() if deg == 0))
    order: list[str] = []
    while ready:
        nid = ready.popleft()
        order.append(nid)
        for nxt in adj.get(nid, ()):
            in_deg[nxt] -= 1
            if in_deg[nxt] == 0:
                ready.append(nxt)

    if len(order) != len(node_ids):
        remaining = sorted(nid for nid, deg in in_deg.items() if deg > 0)
        raise RuntimeError(
            f"版本图拓扑校验失败：存在有向环（未消解节点数={len(remaining)}，示例={remaining[:5]}）"
        )
    return tuple(order)


def build_versioned_dag(
    preprocessed: PreprocessedScenario,
    *,
    config: Optional[DAGBuildConfig] = None,
) -> VersionedDAG:
    """将预处理后的场景事件构建为严格无环的实体版本有向无环图。"""
    cfg = config or DAGBuildConfig()
    poi_set = set(preprocessed.poi_events)
    events = sorted(preprocessed.events, key=_event_sort_key)
    if not events:
        raise ValueError(f"场景 {preprocessed.scenario} 预处理后事件为空，无法构建有向无环图")

    # 识别同 event_id 出现多条边的成对内核操作（如 exec、rename）
    eid_counts = Counter(ev.event_id for ev in events)
    paired_eids = {eid for eid, cnt in eid_counts.items() if cnt > 1}

    nodes: dict[str, _MutableNode] = {}
    edges: dict[str, _MutableEdge] = {}
    edge_lookup: dict[tuple[str, str, str, str], _MutableEdge] = {}
    # 按 (源实体, 目标实体, rel, 动作家族, 源分代, 目标分代) 记录已有边，
    # 用于识别流式分块传输与同会话重复往返的因果等价折叠。
    epoch_edge_history: dict[tuple[str, str, str, str, int, int], _MutableEdge] = {}
    folded_from_nodes: dict[str, set[str]] = defaultdict(set)

    entity_bits: dict[str, int] = {}
    cur_version: dict[str, int] = {}
    cur_epoch: dict[str, int] = {}
    file_reset_pending: dict[str, bool] = {}

    file_carry_breaks = 0
    causal_rounds_folded = 0
    edge_seq = 0

    def entity_bit(eid: str) -> int:
        bit = entity_bits.get(eid)
        if bit is None:
            bit = 1 << len(entity_bits)
            entity_bits[eid] = bit
        return bit

    def get_or_create_current(eid: str, kind: str, key: str, ts: int) -> _MutableNode:
        ver = cur_version.get(eid)
        if ver is None:
            ver = 0
            cur_version[eid] = ver
            cur_epoch[eid] = 0
            nid = f"{eid}@v{ver}"
            node = _MutableNode(
                node_id=nid,
                entity_id=eid,
                kind=kind,
                key=key,
                version=ver,
                epoch=0,
                first_ns=ts,
                last_ns=ts,
                entity_attr=preprocessed.entities.get(eid),
                reach_mask=entity_bit(eid),
            )
            nodes[nid] = node
            return node
        node = nodes[f"{eid}@v{ver}"]
        if ts < node.first_ns:
            node.first_ns = ts
        if ts > node.last_ns:
            node.last_ns = ts
        return node

    def advance_version(
        eid: str,
        kind: str,
        key: str,
        ts: int,
        *,
        connect_carry: bool,
    ) -> _MutableNode:
        nonlocal edge_seq
        old_ver = cur_version[eid]
        old_nid = f"{eid}@v{old_ver}"
        old_node = nodes[old_nid]
        new_ver = old_ver + 1
        cur_version[eid] = new_ver
        if connect_carry:
            new_epoch = cur_epoch[eid]
            init_mask = old_node.reach_mask | entity_bit(eid)
            init_input_gen = old_node.input_gen
        else:
            new_epoch = cur_epoch[eid] + 1
            cur_epoch[eid] = new_epoch
            init_mask = entity_bit(eid)
            init_input_gen = 0
        new_nid = f"{eid}@v{new_ver}"
        new_node = _MutableNode(
            node_id=new_nid,
            entity_id=eid,
            kind=kind,
            key=key,
            version=new_ver,
            epoch=new_epoch,
            first_ns=ts,
            last_ns=ts,
            entity_attr=old_node.entity_attr,
            reach_mask=init_mask,
            input_gen=init_input_gen,
        )
        nodes[new_nid] = new_node
        if connect_carry:
            carry_id = f"carry:{edge_seq}"
            edge_seq += 1
            edges[carry_id] = _MutableEdge(
                edge_id=carry_id,
                src_node_id=old_nid,
                dst_node_id=new_nid,
                edge_kind="state_carry",
                rel="carry",
                primary_action="state_carry",
                actions=["state_carry"],
                raw_event_ids=[],
                kernel_event_ids=[],
                start_ns=old_node.last_ns,
                end_ns=ts,
            )
        return new_node

    def append_event_to_edge(target: _MutableEdge, ev: RawEvent, ts: int, end_ts: int, is_poi: bool) -> None:
        target.raw_event_ids.append(ev.id)
        target.kernel_event_ids.append(ev.event_id)
        if ev.action not in target.actions:
            target.actions.append(ev.action)
        if ts < target.start_ns:
            target.start_ns = ts
        if end_ts > target.end_ns:
            target.end_ns = end_ts
        if is_poi:
            target.is_poi = True
        if ev.report_status == "confirmed":
            target.confirmed_count += 1
        else:
            target.unexcluded_count += 1
        if ev.verdict:
            target.verdicts.add(ev.verdict)
        if any(ev.bundle_triple):
            target.bundle_triples.add(ev.bundle_triple)

    for ev in events:
        ts = ev.start_ns if ev.start_ns is not None else 0
        end_ts = ev.end_ns if ev.end_ns is not None else ts
        src_eid = ev.src_entity_id
        dst_eid = ev.dst_entity_id
        is_poi = ev.id in poi_set
        fam = _action_family(ev.rel, ev.action, merge_companion=cfg.merge_companion_syscalls)

        # 1. 获取源端点当前版本（先不急于标记 has_outgoing，若命中因果等价折叠则复用到既有边）
        src_node = get_or_create_current(src_eid, ev.src_kind, ev.src_key, ts)

        # 2. 判定目标文件是否发生物理删除或截断清零
        dst_exists = dst_eid in cur_version
        force_file_reset = False
        if dst_exists and ev.dst_kind == "File" and cfg.break_file_delete_carry:
            if file_reset_pending.get(dst_eid, False) or ev.action == "truncate":
                force_file_reset = True

        # 3. 因果等价流/多轮往返折叠检查：
        # 仅在同一未断开分代内、当前源节点全部传递祖先已包含于当前目标节点，
        # 且满足以下二选一防孤立条件时，才复用既有边：
        #   (a) 既有边两端就是当前源/目标版本节点且目标节点尚未冻结（流式分块传输）；
        #   (b) 当前源版本节点仅由目标实体的直接回边产生，且目标节点未引入独立外部输入（纯双向往返）。
        folded_edge: Optional[_MutableEdge] = None
        if (
            cfg.fold_causal_equivalent_rounds
            and cfg.merge_parallel_edges
            and dst_exists
            and not force_file_reset
            and src_eid != dst_eid
        ):
            cur_dst_node = nodes[f"{dst_eid}@v{cur_version[dst_eid]}"]
            hist_key = (src_eid, dst_eid, ev.rel, fam, src_node.epoch, cur_dst_node.epoch)
            prev_edge = epoch_edge_history.get(hist_key)
            if prev_edge is not None and (src_node.reach_mask & ~cur_dst_node.reach_mask) == 0:
                same_endpoints = (
                    prev_edge.src_node_id == src_node.node_id
                    and prev_edge.dst_node_id == cur_dst_node.node_id
                )
                pure_pingpong_src = (
                    src_node.direct_in_mask == entity_bit(dst_eid)
                    and cur_dst_node.input_gen == prev_edge.dst_input_gen
                )
                if same_endpoints or pure_pingpong_src:
                    folded_edge = prev_edge

        if folded_edge is not None:
            append_event_to_edge(folded_edge, ev, ts, end_ts, is_poi)
            if folded_edge.src_node_id != src_node.node_id:
                folded_from_nodes[folded_edge.edge_id].add(src_node.node_id)
            causal_rounds_folded += 1
            if ev.dst_kind == "File" and ev.action == "unlink" and cfg.break_file_delete_carry:
                file_reset_pending[dst_eid] = True
            continue

        # 4. 正常建边与按需最小版本分裂
        src_node.has_outgoing = True

        if not dst_exists:
            dst_node = get_or_create_current(dst_eid, ev.dst_kind, ev.dst_key, ts)
        else:
            cur_dst = nodes[f"{dst_eid}@v{cur_version[dst_eid]}"]
            need_split = cur_dst.has_outgoing
            connect_carry = True

            if force_file_reset:
                need_split = True
                connect_carry = False
                file_carry_breaks += 1
                file_reset_pending[dst_eid] = False

            # 自环防卫（同实体不会连回同版本）
            if src_node.node_id == cur_dst.node_id:
                need_split = True

            if need_split:
                dst_node = advance_version(dst_eid, ev.dst_kind, ev.dst_key, ts, connect_carry=connect_carry)
            else:
                dst_node = cur_dst
                if ts < dst_node.first_ns:
                    dst_node.first_ns = ts
                if end_ts > dst_node.last_ns:
                    dst_node.last_ns = end_ts

        # 目标节点此时尚未发出任何出边，可精确更新其传递祖先位图与直接入边实体位图
        if (src_node.reach_mask & entity_bit(dst_eid)) == 0:
            dst_node.input_gen += 1
        dst_node.reach_mask |= src_node.reach_mask
        dst_node.direct_in_mask |= entity_bit(src_eid)

        if ev.dst_kind == "File" and ev.action == "unlink" and cfg.break_file_delete_carry:
            file_reset_pending[dst_eid] = True

        # 5. 写入或合并到逻辑操作边（问题 3 + 问题 4）
        merge_key = (src_node.node_id, dst_node.node_id, ev.rel, fam) if cfg.merge_parallel_edges else (
            src_node.node_id, dst_node.node_id, ev.rel, ev.id
        )

        existing = edge_lookup.get(merge_key)
        if existing is None:
            eid_str = f"op:{edge_seq}"
            edge_seq += 1
            me = _MutableEdge(
                edge_id=eid_str,
                src_node_id=src_node.node_id,
                dst_node_id=dst_node.node_id,
                edge_kind="op",
                rel=ev.rel,
                primary_action=fam if cfg.merge_companion_syscalls else ev.action,
                actions=[ev.action],
                raw_event_ids=[ev.id],
                kernel_event_ids=[ev.event_id],
                start_ns=ts,
                end_ns=end_ts,
                dst_input_gen=dst_node.input_gen,
                is_poi=is_poi,
                confirmed_count=1 if ev.report_status == "confirmed" else 0,
                unexcluded_count=0 if ev.report_status == "confirmed" else 1,
                verdicts={ev.verdict} if ev.verdict else set(),
                bundle_triples={ev.bundle_triple} if any(ev.bundle_triple) else set(),
            )
            edges[eid_str] = me
            edge_lookup[merge_key] = me
            if cfg.fold_causal_equivalent_rounds and cfg.merge_parallel_edges and src_eid != dst_eid:
                hist_key = (src_eid, dst_eid, ev.rel, fam, src_node.epoch, dst_node.epoch)
                epoch_edge_history[hist_key] = me
        else:
            append_event_to_edge(existing, ev, ts, end_ts, is_poi)

    # 4. 二次轻量反向修剪：清理因断开守护进程/文件删除延续边而不再通向 poi 的节点和边
    total_nodes_before = len(nodes)
    total_edges_before = len(edges)
    if cfg.prune_after_breaks:
        in_map: dict[str, list[str]] = defaultdict(list)
        for edge_id, me in edges.items():
            in_map[me.dst_node_id].append(edge_id)

        poi_edge_list = [eid for eid, me in edges.items() if me.is_poi]
        if not poi_edge_list:
            raise RuntimeError(f"场景 {preprocessed.scenario} 建图后缺失 poi 边")

        keep_edges: set[str] = set(poi_edge_list)
        keep_nodes: set[str] = set()
        queue: deque[str] = deque()
        for peid in poi_edge_list:
            me = edges[peid]
            keep_nodes.add(me.dst_node_id)
            for req_nid in (me.src_node_id, *folded_from_nodes.get(peid, ())):
                if req_nid not in keep_nodes:
                    keep_nodes.add(req_nid)
                    queue.append(req_nid)

        while queue:
            nid = queue.popleft()
            for in_eid in in_map.get(nid, ()):
                keep_edges.add(in_eid)
                for req_nid in (edges[in_eid].src_node_id, *folded_from_nodes.get(in_eid, ())):
                    if req_nid not in keep_nodes:
                        keep_nodes.add(req_nid)
                        queue.append(req_nid)

        nodes = {nid: mn for nid, mn in nodes.items() if nid in keep_nodes}
        edges = {eid: me for eid, me in edges.items() if eid in keep_edges}

    secondary_pruned_nodes = total_nodes_before - len(nodes)
    secondary_pruned_edges = total_edges_before - len(edges)

    # 5. 冻结为不可变图对象、计算入度/出度、候选入口与 poi 集合
    in_adj: dict[str, list[str]] = {nid: [] for nid in nodes}
    out_adj: dict[str, list[str]] = {nid: [] for nid in nodes}
    frozen_edges: dict[str, LogicEdge] = {}
    poi_edge_ids: list[str] = []
    poi_node_set: set[str] = set()

    retained_raw_ids: set[str] = set()
    companion_edges_merged = 0
    op_edges_count = 0
    carry_edges_count = 0

    for eid, me in edges.items():
        in_adj[me.dst_node_id].append(eid)
        out_adj[me.src_node_id].append(eid)
        paired_in_edge = tuple(sorted({kid for kid in me.kernel_event_ids if kid in paired_eids}))
        if me.edge_kind == "op":
            op_edges_count += 1
            retained_raw_ids.update(me.raw_event_ids)
            if len(me.actions) > 1:
                companion_edges_merged += 1
        else:
            carry_edges_count += 1
        if me.is_poi:
            poi_edge_ids.append(eid)
            poi_node_set.add(me.dst_node_id)
        frozen_edges[eid] = LogicEdge(
            edge_id=me.edge_id,
            src_node_id=me.src_node_id,
            dst_node_id=me.dst_node_id,
            edge_kind=me.edge_kind,
            rel=me.rel,
            primary_action=me.primary_action,
            actions=tuple(me.actions),
            raw_event_ids=tuple(me.raw_event_ids),
            kernel_event_ids=tuple(me.kernel_event_ids),
            paired_kernel_event_ids=paired_in_edge,
            event_count=len(me.raw_event_ids),
            start_ns=me.start_ns,
            end_ns=me.end_ns,
            is_poi=me.is_poi,
            confirmed_count=me.confirmed_count,
            unexcluded_count=me.unexcluded_count,
            verdicts=tuple(sorted(me.verdicts)),
            bundle_triples=tuple(sorted(me.bundle_triples)),
        )

    missing_pois = sorted(poi_set - retained_raw_ids)
    if missing_pois:
        raise RuntimeError(f"场景 {preprocessed.scenario} 建图后告警终点丢失：{missing_pois[:5]}")

    candidate_entries = sorted(nid for nid in nodes if len(in_adj[nid]) == 0)
    candidate_entry_set = set(candidate_entries)

    frozen_nodes: dict[str, VersionNode] = {}
    for nid, mn in nodes.items():
        frozen_nodes[nid] = VersionNode(
            node_id=mn.node_id,
            entity_id=mn.entity_id,
            kind=mn.kind,
            key=mn.key,
            version=mn.version,
            first_ns=mn.first_ns,
            last_ns=mn.last_ns,
            is_poi_target=nid in poi_node_set,
            is_candidate_entry=nid in candidate_entry_set,
            entity_attr=mn.entity_attr,
        )

    topo_order: tuple[str, ...] = ()
    is_acyclic = True
    if cfg.verify_acyclic:
        topo_order = _kahn_topological_sort(set(frozen_nodes.keys()), frozen_edges)

    max_in = max((len(v) for v in in_adj.values()), default=0)
    max_out = max((len(v) for v in out_adj.values()), default=0)
    unique_entities = len({ev.src_entity_id for ev in events} | {ev.dst_entity_id for ev in events})
    retained_raw_count = len(retained_raw_ids)
    parallel_folded = max(0, retained_raw_count - op_edges_count)

    stats = DAGStats(
        input_pruned_events=len(events),
        retained_raw_events=retained_raw_count,
        unique_entities_before_versioning=unique_entities,
        version_nodes=len(frozen_nodes),
        op_edges=op_edges_count,
        carry_edges=carry_edges_count,
        total_edges=len(frozen_edges),
        poi_edges=len(poi_edge_ids),
        candidate_entries=len(candidate_entries),
        max_in_degree=max_in,
        max_out_degree=max_out,
        parallel_events_folded=parallel_folded,
        causal_rounds_folded=causal_rounds_folded,
        companion_edges_merged=companion_edges_merged,
        paired_kernel_groups=len(paired_eids),
        file_carry_breaks=file_carry_breaks,
        secondary_pruned_nodes=secondary_pruned_nodes,
        secondary_pruned_edges=secondary_pruned_edges,
        is_acyclic=is_acyclic,
    )

    return VersionedDAG(
        scenario=preprocessed.scenario,
        database=preprocessed.database,
        nodes=frozen_nodes,
        edges=frozen_edges,
        in_edges={k: tuple(v) for k, v in in_adj.items()},
        out_edges={k: tuple(v) for k, v in out_adj.items()},
        poi_edge_ids=tuple(sorted(poi_edge_ids)),
        poi_node_ids=tuple(sorted(poi_node_set)),
        candidate_entry_ids=tuple(candidate_entries),
        topo_order=topo_order,
        stats=stats,
    )
