"""研究点二第一阶段收口诊断：候选入口分类（问题 8）、物理断链体检（问题 7）与 10 场景只读汇总 CLI。

全程只读消费研究点一导出的 events_v2/*.events.json.gz，零 Neo4j 依赖，不修改任何正式基线文件。
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
import time
from typing import Any, Optional

from attack_path._bridge import available_scenarios, baseline_events_path
from attack_path.dag import DAGBuildConfig, DAGStats, VersionedDAG, build_versioned_dag
from attack_path.loader import EntityAttr, RawEvent, load_scenario_events
from attack_path.preprocess import PreprocessConfig, PreprocessStats, PreprocessedScenario, preprocess_scenario


@dataclass(frozen=True)
class CandidateEntry:
    """最终实体版本有向无环图中入度为 0 的候选攻击入口节点（问题 8）。"""

    node_id: str
    entity_id: str
    kind: str
    entry_category: str  # external_network | loopback_network | initial_process | static_file
    key: str
    label: str
    version: int
    first_ns: int
    out_degree: int
    out_confirmed_events: int
    out_actions: tuple[str, ...]


@dataclass(frozen=True)
class DisconnectedComponent:
    """研究点一已确认（confirmed）但在单机系统调用流中与 poi 物理断开的连通分支（问题 7）。"""

    component_id: int
    confirmed_event_count: int
    entity_count: int
    earliest_ns: int
    latest_ns: int
    relation_to_poi_time: str  # before_poi | during_poi | after_poi
    likely_cause: str  # post_poi | cross_container_boundary | disconnected_session_or_side_branch
    sample_entities: tuple[str, ...]
    sample_actions: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioDiagnosis:
    """单个场景的第一阶段完整体检报告。"""

    scenario: str
    database: str
    preprocess_stats: PreprocessStats
    dag_stats: DAGStats
    poi_node_ids: tuple[str, ...]
    poi_edge_ids: tuple[str, ...]
    poi_time_range_ns: tuple[int, int]
    candidate_entries: tuple[CandidateEntry, ...]
    entry_category_counts: dict[str, int]
    confirmed_total_cleaned: int
    confirmed_in_dag: int
    confirmed_unreachable: int
    disconnected_components: tuple[DisconnectedComponent, ...]
    build_seconds: float


def _entity_label(eid: str, ent: Optional[EntityAttr]) -> str:
    if ent is None:
        return eid
    if ent.kind == "Process":
        exe = ent.exe_path or ent.content or ent.key
        pid_part = f"pid={ent.pid}" if ent.pid is not None else ""
        return f"{exe} ({pid_part})" if pid_part else exe
    return ent.content or ent.key


def _classify_entry_category(kind: str) -> str:
    if kind == "NetworkIn":
        return "external_network"
    if kind == "Network":
        return "loopback_network"
    if kind == "Process":
        return "initial_process"
    return "static_file"


def _extract_candidate_entries(dag: VersionedDAG) -> tuple[CandidateEntry, ...]:
    entries: list[CandidateEntry] = []
    for nid in dag.candidate_entry_ids:
        node = dag.nodes[nid]
        out_eids = dag.out_edges.get(nid, ())
        out_conf = 0
        actions: set[str] = set()
        for eid in out_eids:
            edge = dag.edges[eid]
            out_conf += edge.confirmed_count
            actions.update(edge.actions)
        entries.append(
            CandidateEntry(
                node_id=nid,
                entity_id=node.entity_id,
                kind=node.kind,
                entry_category=_classify_entry_category(node.kind),
                key=node.key,
                label=_entity_label(node.entity_id, node.entity_attr),
                version=node.version,
                first_ns=node.first_ns,
                out_degree=len(out_eids),
                out_confirmed_events=out_conf,
                out_actions=tuple(sorted(actions)),
            )
        )
    # 优先展示外部网络入口，其次按发出确认事件数与时间排序
    prio = {"external_network": 0, "loopback_network": 1, "initial_process": 2, "static_file": 3}
    entries.sort(key=lambda e: (prio.get(e.entry_category, 9), -e.out_confirmed_events, e.first_ns, e.node_id))
    return tuple(entries)


def _container_of(eid: str, entities: dict[str, EntityAttr]) -> str:
    ent = entities.get(eid)
    if ent is not None and ent.container_id:
        return ent.container_id
    return "host"


def _diagnose_disconnected_confirmed(
    preprocessed: PreprocessedScenario,
    dag: VersionedDAG,
    poi_min_ns: int,
    poi_max_ns: int,
) -> tuple[int, int, int, tuple[DisconnectedComponent, ...]]:
    """对比清洗后全部 confirmed 事件与最终无环图覆盖的 confirmed 事件，按弱连通分量报告断链。"""
    dag_raw_ids: set[str] = set()
    for edge in dag.edges.values():
        if edge.edge_kind == "op":
            dag_raw_ids.update(edge.raw_event_ids)

    poi_set = set(preprocessed.poi_events)
    poi_containers: set[str] = set()
    for ev in preprocessed.cleaned_events:
        if ev.id in poi_set:
            poi_containers.add(_container_of(ev.src_entity_id, preprocessed.entities))
            poi_containers.add(_container_of(ev.dst_entity_id, preprocessed.entities))

    confirmed_cleaned = [ev for ev in preprocessed.cleaned_events if ev.report_status == "confirmed"]
    confirmed_in_dag = sum(1 for ev in confirmed_cleaned if ev.id in dag_raw_ids)
    unreachable: list[RawEvent] = [ev for ev in confirmed_cleaned if ev.id not in dag_raw_ids]

    if not unreachable:
        return len(confirmed_cleaned), confirmed_in_dag, 0, ()

    # 在未达 poi 的 confirmed 事件集合上按共享非枢纽实体划分子连通分量（严格线性 O(E) BFS：每个实体最多展开一次）
    ent_to_ev_idxs: dict[str, list[int]] = defaultdict(list)
    for idx, ev in enumerate(unreachable):
        if ev.src_entity_id not in preprocessed.blocked_hub_entity_ids:
            ent_to_ev_idxs[ev.src_entity_id].append(idx)
        if ev.dst_entity_id not in preprocessed.blocked_hub_entity_ids:
            ent_to_ev_idxs[ev.dst_entity_id].append(idx)

    visited = [False] * len(unreachable)
    visited_entities: set[str] = set()
    components: list[DisconnectedComponent] = []
    comp_seq = 0

    for start_idx in range(len(unreachable)):
        if visited[start_idx]:
            continue
        comp_idxs: list[int] = []
        queue: deque[int] = deque([start_idx])
        visited[start_idx] = True
        while queue:
            cur = queue.popleft()
            comp_idxs.append(cur)
            ev = unreachable[cur]
            for eid in (ev.src_entity_id, ev.dst_entity_id):
                if eid in preprocessed.blocked_hub_entity_ids or eid in visited_entities:
                    continue
                visited_entities.add(eid)
                for nxt in ent_to_ev_idxs.get(eid, ()):
                    if not visited[nxt]:
                        visited[nxt] = True
                        queue.append(nxt)

        comp_events = [unreachable[i] for i in comp_idxs]
        comp_entities: set[str] = set()
        comp_containers: set[str] = set()
        actions: Counter[str] = Counter()
        earliest = min(e.start_ns for e in comp_events if e.start_ns is not None)
        latest = max((e.end_ns if e.end_ns is not None else e.start_ns) for e in comp_events if e.start_ns is not None)

        for e in comp_events:
            comp_entities.add(e.src_entity_id)
            comp_entities.add(e.dst_entity_id)
            comp_containers.add(_container_of(e.src_entity_id, preprocessed.entities))
            comp_containers.add(_container_of(e.dst_entity_id, preprocessed.entities))
            actions[e.action] += 1

        if earliest > poi_max_ns:
            rel_time = "after_poi"
            likely = "post_poi"
        elif latest < poi_min_ns:
            rel_time = "before_poi"
            likely = (
                "cross_container_boundary"
                if poi_containers and comp_containers and comp_containers.isdisjoint(poi_containers)
                else "disconnected_session_or_side_branch"
            )
        else:
            rel_time = "during_poi"
            likely = (
                "cross_container_boundary"
                if poi_containers and comp_containers and comp_containers.isdisjoint(poi_containers)
                else "disconnected_session_or_side_branch"
            )

        # 按出现频次选前 5 个代表实体标签
        ent_freq: Counter[str] = Counter()
        for e in comp_events:
            ent_freq[e.src_entity_id] += 1
            ent_freq[e.dst_entity_id] += 1
        samples = tuple(_entity_label(eid, preprocessed.entities.get(eid)) for eid, _ in ent_freq.most_common(5))
        sample_actions = tuple(act for act, _ in actions.most_common(5))

        components.append(
            DisconnectedComponent(
                component_id=comp_seq,
                confirmed_event_count=len(comp_events),
                entity_count=len(comp_entities),
                earliest_ns=earliest,
                latest_ns=latest,
                relation_to_poi_time=rel_time,
                likely_cause=likely,
                sample_entities=samples,
                sample_actions=sample_actions,
            )
        )
        comp_seq += 1

    components.sort(key=lambda c: (-c.confirmed_event_count, c.earliest_ns))
    # 重排连续编号
    reindexed = tuple(
        DisconnectedComponent(
            component_id=i,
            confirmed_event_count=c.confirmed_event_count,
            entity_count=c.entity_count,
            earliest_ns=c.earliest_ns,
            latest_ns=c.latest_ns,
            relation_to_poi_time=c.relation_to_poi_time,
            likely_cause=c.likely_cause,
            sample_entities=c.sample_entities,
            sample_actions=c.sample_actions,
        )
        for i, c in enumerate(components)
    )
    return len(confirmed_cleaned), confirmed_in_dag, len(unreachable), reindexed


def diagnose_scenario(
    preprocessed: PreprocessedScenario,
    dag: VersionedDAG,
    *,
    build_seconds: float = 0.0,
) -> ScenarioDiagnosis:
    """基于预处理结果与最终无环图生成候选入口与物理断链诊断报告。"""
    poi_edges = [dag.edges[eid] for eid in dag.poi_edge_ids]
    poi_min_ns = min(e.start_ns for e in poi_edges)
    poi_max_ns = max(e.end_ns for e in poi_edges)

    entries = _extract_candidate_entries(dag)
    cat_counts = Counter(e.entry_category for e in entries)
    entry_category_counts = {
        "external_network": cat_counts.get("external_network", 0),
        "loopback_network": cat_counts.get("loopback_network", 0),
        "initial_process": cat_counts.get("initial_process", 0),
        "static_file": cat_counts.get("static_file", 0),
    }

    conf_total, conf_in_dag, conf_unreach, comps = _diagnose_disconnected_confirmed(
        preprocessed, dag, poi_min_ns, poi_max_ns
    )

    return ScenarioDiagnosis(
        scenario=dag.scenario,
        database=dag.database,
        preprocess_stats=preprocessed.stats,
        dag_stats=dag.stats,
        poi_node_ids=dag.poi_node_ids,
        poi_edge_ids=dag.poi_edge_ids,
        poi_time_range_ns=(poi_min_ns, poi_max_ns),
        candidate_entries=entries,
        entry_category_counts=entry_category_counts,
        confirmed_total_cleaned=conf_total,
        confirmed_in_dag=conf_in_dag,
        confirmed_unreachable=conf_unreach,
        disconnected_components=comps,
        build_seconds=build_seconds,
    )


def run_phase1_for_scenario(
    scenario: str,
    *,
    events_path: Optional[Path] = None,
    preprocess_config: Optional[PreprocessConfig] = None,
    dag_config: Optional[DAGBuildConfig] = None,
) -> tuple[PreprocessedScenario, VersionedDAG, ScenarioDiagnosis]:
    """对单个场景执行完整第一阶段（加载 -> 清洗裁剪 -> 实体版本无环图 -> 入口与断链诊断）。"""
    t0 = time.perf_counter()
    path = events_path if events_path is not None else baseline_events_path(scenario)
    ds = load_scenario_events(path)
    pre = preprocess_scenario(ds, config=preprocess_config)
    dag = build_versioned_dag(pre, config=dag_config)
    diag = diagnose_scenario(pre, dag, build_seconds=time.perf_counter() - t0)
    return pre, dag, diag


def format_diagnosis_table(results: list[ScenarioDiagnosis]) -> str:
    """格式化输出多场景第一阶段终端汇总表。"""
    lines: list[str] = []
    header = (
        f"{'Scenario':40s} {'RawIn':>7s} {'VNode':>5s} {'OpEdg':>5s} {'TotEdg':>6s} "
        f"{'Entry(Net/Proc/File)':>20s} {'ConfInDAG':>13s} {'DiscComp':>8s} {'DAG':>3s} {'Sec':>5s}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    tot_raw = tot_vn = tot_op = tot_edg = tot_conf_in = tot_conf_all = 0
    tot_sec = 0.0
    for r in results:
        ec = r.entry_category_counts
        net_cnt = ec["external_network"] + ec["loopback_network"]
        entry_str = f"{len(r.candidate_entries):4d} ({net_cnt}/{ec['initial_process']}/{ec['static_file']})"
        conf_str = f"{r.confirmed_in_dag}/{r.confirmed_total_cleaned}"
        tot_raw += r.preprocess_stats.input_events
        tot_vn += r.dag_stats.version_nodes
        tot_op += r.dag_stats.op_edges
        tot_edg += r.dag_stats.total_edges
        tot_conf_in += r.confirmed_in_dag
        tot_conf_all += r.confirmed_total_cleaned
        tot_sec += r.build_seconds
        lines.append(
            f"{r.scenario:40s} {r.preprocess_stats.input_events:7d} {r.dag_stats.version_nodes:5d} "
            f"{r.dag_stats.op_edges:5d} {r.dag_stats.total_edges:6d} {entry_str:>20s} "
            f"{conf_str:>13s} {len(r.disconnected_components):8d} "
            f"{'OK' if r.dag_stats.is_acyclic else 'NO':>3s} {r.build_seconds:5.2f}"
        )

    lines.append("-" * len(header))
    lines.append(
        f"{'TOTAL':40s} {tot_raw:7d} {tot_vn:5d} {tot_op:5d} {tot_edg:6d} "
        f"{'':>20s} {f'{tot_conf_in}/{tot_conf_all}':>13s} {'':>8s} {'OK':>3s} {tot_sec:5.2f}"
    )
    return "\n".join(lines)


def _to_jsonable(diag: ScenarioDiagnosis) -> dict[str, Any]:
    return {
        "scenario": diag.scenario,
        "database": diag.database,
        "build_seconds": round(diag.build_seconds, 3),
        "preprocess_stats": asdict(diag.preprocess_stats),
        "dag_stats": asdict(diag.dag_stats),
        "poi_node_ids": list(diag.poi_node_ids),
        "poi_edge_ids": list(diag.poi_edge_ids),
        "poi_time_range_ns": list(diag.poi_time_range_ns),
        "entry_category_counts": dict(diag.entry_category_counts),
        "top_candidate_entries": [asdict(e) for e in diag.candidate_entries[:20]],
        "confirmed_total_cleaned": diag.confirmed_total_cleaned,
        "confirmed_in_dag": diag.confirmed_in_dag,
        "confirmed_unreachable": diag.confirmed_unreachable,
        "disconnected_components": [asdict(c) for c in diag.disconnected_components[:20]],
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="研究点二第一阶段实体版本有向无环图构建与物理断链诊断（零 Neo4j）")
    parser.add_argument("--scenario", help="只运行指定场景名；省略则运行全部 10 个场景")
    parser.add_argument("--json-out", type=Path, help="可选：将结构化诊断报告写入指定 JSON 路径")
    args = parser.parse_args(argv)

    scenarios = [args.scenario] if args.scenario else available_scenarios()
    dag_cfg = DAGBuildConfig()

    results: list[ScenarioDiagnosis] = []
    total_sc = len(scenarios)
    for idx, sc_name in enumerate(scenarios, 1):
        _, _, diag = run_phase1_for_scenario(sc_name, dag_config=dag_cfg)
        results.append(diag)
        print(
            f"[第一阶段诊断 {idx}/{total_sc}] {sc_name}: "
            f"Raw={diag.preprocess_stats.input_events} -> VNode={diag.dag_stats.version_nodes} "
            f"OpEdg={diag.dag_stats.op_edges} TotEdg={diag.dag_stats.total_edges} "
            f"Entry={len(diag.candidate_entries)} DiscComp={len(diag.disconnected_components)} "
            f"({diag.build_seconds:.2f}s)",
            flush=True,
        )

    print(format_diagnosis_table(results))
    for r in results:
        cause_counts = Counter(c.likely_cause for c in r.disconnected_components)
        ext_entries = [e.key for e in r.candidate_entries if e.entry_category == "external_network"][:3]
        print(
            f"  [{r.scenario}] 外网入口数={r.entry_category_counts['external_network']} "
            f"示例={ext_entries} | 未达poi确认分量={len(r.disconnected_components)} 归因={dict(cause_counts)}"
        )

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {"scenarios": [_to_jsonable(r) for r in results]}
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n诊断 JSON 已写入：{args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
