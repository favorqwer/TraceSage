"""CDM18 管线编排：读 -> 解码 -> 索引 -> 派发 -> 结算 -> 产出 -> 报告。

为什么放在 adapters 而不是 runtime：架构依赖规则（tests/test_architecture.py）允许
``provenance.runtime`` 依赖 core/graph/runtime，而 ``provenance.adapters`` 只能依赖
core/adapters。本文件通过 ``CdmGraphSink`` 协议接收图出口（真实实现是
``provenance.graph.store.GraphStore``，由装配根 ``cdm_main.py`` 注入），
因此不需要 import provenance.graph。

与 sysdig 主干的差别：``runtime/runner.py`` 的核心是「进入行 + 退出行配对」，
CDM 一条记录就是一个完整事件；配对池、fd 表、容器元数据三块在这里都不存在，
硬套会把「不适用」写成 0。
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ...core.graph import Outcome
from ...core.kinds import Bucket
from ...core.options import EmitOptions, GraphLimits
from . import decode as D
from . import report as R
from .archive import iter_lines
from .emit import PATH_AUDIT, CdmEmitter, EventContext
from .mapping import EventTable
from .objects import ObjectIndex, parse_file, parse_netflow, parse_subject

#: 落 UNMAPPED 桶的 reason 前缀（表里 special=unmapped 的事件按事件类型记 reason）。
UNMAPPED_REASONS = frozenset({
    "EVENT_UNIT", "EVENT_UPDATE", "EVENT_OTHER", "EVENT_LOADLIBRARY",
    "EVENT_MODIFY_PROCESS", "EVENT_FLOWS_TO", "EVENT_LOGIN", "EVENT_LOGOUT",
    "EVENT_LOGCLEAR", "EVENT_SERVICEINSTALL", "EVENT_STARTSERVICE",
})

#: 不建顶点、但要按类型计数的对象记录（解释「事件远多于边」的原因）。
UNNAMED_RECORD_KINDS = {
    "MemoryObject": "memory",
    "SrcSinkObject": "srcsink",
    "UnnamedPipeObject": "pipe",
    "PacketSocketObject": "packet",
    "RegistryKeyObject": "registry",
}


class CdmGraphSink(Protocol):
    """图出口协议：只要实现 add/flush/snapshot 就能接（真实实现是 GraphStore）。"""

    nodes: dict

    def add(self, outcome: Outcome) -> None: ...

    def flush(self) -> None: ...

    def snapshot(self) -> Any: ...


@dataclass(frozen=True, slots=True)
class CdmRunOptions:
    scenario: str
    host_id: str
    archive: str
    database: str
    dry_run: bool = False
    member_from: int = 0
    member_to: int | None = None
    sort_members: bool = True
    time_from_ns: int | None = None
    time_to_ns: int | None = None
    progress_every_s: int = 10
    max_events: int = 0
    out_dir: str = ""
    event_log: bool = False
    write_csv: bool = True
    # 同一 host_id 上的多个时间窗追加到同一个库时，事件号必须全局不重叠：
    # Neo4j 关系唯一约束是 (event_id, action)，撞号会导致写库失败。
    event_id_base: int = 0


def run_cdm(
    options: CdmRunOptions,
    limits: GraphLimits,
    emit_options: EmitOptions,
    table: EventTable,
    graph: CdmGraphSink,
) -> dict[str, Any]:
    started = time.time()
    started_mono = time.monotonic()
    out_dir = (
        Path(options.out_dir) if options.out_dir
        else Path("output/parser-v2") / f"{options.scenario}-cdm"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    index = ObjectIndex()
    emitter = CdmEmitter(options.host_id, index, emit_options)

    if options.write_csv:
        edge_csv = R.EdgeCsv(out_dir / "edges.csv")
        event_csv = R.EventCsv(out_dir / "events.csv") if options.event_log else None
    else:
        edge_csv = R.NullCsv()
        event_csv = None

    records_total = 0
    bytes_read = 0
    records_by_type: Counter[str] = Counter()
    unnamed_records: Counter[str] = Counter()
    buckets: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    unmapped_types: Counter[str] = Counter()
    by_object_class: dict[str, Counter[str]] = {}
    result_present: Counter[str] = Counter()
    edges_by_class: Counter[str] = Counter()
    edges_by_action: Counter[str] = Counter()
    edges_by_syscall: Counter[str] = Counter()

    events_ingested = 0
    events_settled = 0
    events_out_of_window = 0
    event_id = options.event_id_base
    bad_records = 0
    edges_written = 0
    dangling = 0
    last_progress = time.monotonic()

    host_name = ""
    source_host = ""
    first_ts = 0
    last_ts = 0
    markers: Counter[str] = Counter()

    # 成员物理顺序 != 逻辑序号时（实测 THEIA 归档是 .1, .10, .11, .12, .2 …），
    # 流内时间戳不单调。这里显式告警并写进报告，不靠使用方自己发现。
    member_mode = "sorted" if options.sort_members else "tar"
    member_order_monotonic = True
    last_member_index = -1

    def settle(bucket: Bucket, reason: str) -> None:
        nonlocal events_settled
        buckets[bucket.value] += 1
        if reason:
            reasons[reason] += 1
        events_settled += 1

    for member_index, member_name, line_no, raw in iter_lines(
        options.archive, options.member_from, options.member_to, options.sort_members
    ):
        if member_index < last_member_index and member_order_monotonic:
            member_order_monotonic = False
            print(
                f"[warn] 成员物理顺序不是逻辑序：{last_member_index} -> {member_index}"
                f"（{member_name}）。事件时间戳将不单调；要单调请加 --sort-members。",
                flush=True,
            )
        last_member_index = max(last_member_index, member_index)
        records_total += 1
        bytes_read += len(raw)
        decoded = D.datum_of(raw)
        if decoded is None:
            bad_records += 1
            settle(Bucket.ABNORMAL, "record_decode_failed")
            continue
        kind, body = decoded
        records_by_type[kind] += 1

        if kind == "Subject":
            index.add_subject(parse_subject(body))
            continue
        if kind == "FileObject":
            index.add_file(parse_file(body))
            continue
        if kind == "NetFlowObject":
            index.add_netflow(parse_netflow(body))
            continue
        if kind == "Principal":
            index.add_principal(body)
            continue
        if kind == "Host":
            host_name = D.text(body.get("hostName"))
            source_host = D.text(body.get("uuid"))
            emitter.set_source_host(source_host)
            continue
        if kind in UNNAMED_RECORD_KINDS:
            unnamed_kind = UNNAMED_RECORD_KINDS[kind]
            unnamed_records[unnamed_kind] += 1
            index.add_unnamed(unnamed_kind, D.text(body.get("uuid")))
            continue
        if kind in ("TimeMarker", "StartMarker", "EndMarker"):
            markers[kind] += 1
            marker_ts = D.number(body.get("tsNanos"))
            if marker_ts:
                first_ts = marker_ts if not first_ts else min(first_ts, marker_ts)
                last_ts = max(last_ts, marker_ts)
            continue
        if kind != "Event":
            continue

        # ---- 事件 ----------------------------------------------------
        event_id += 1
        ts_ns = D.number(body.get("timestampNanos")) or 0
        uuid_text = D.text(body.get("uuid"))
        etype = D.text(body.get("type"))
        if ts_ns:
            first_ts = ts_ns if not first_ts else min(first_ts, ts_ns)
            last_ts = max(last_ts, ts_ns)

        if options.time_from_ns is not None and ts_ns < options.time_from_ns:
            events_out_of_window += 1
            continue
        if options.time_to_ns is not None and ts_ns > options.time_to_ns:
            events_out_of_window += 1
            continue

        events_ingested += 1
        if event_csv is not None:
            event_csv.write(event_id, member_name, line_no, uuid_text, etype, ts_ns)

        subject_uuid = D.uuid(body.get("subject"))
        subject = index.subjects.get(subject_uuid) if subject_uuid else None

        props = D.mapping(body.get("properties"))
        pred_uuid = D.uuid(body.get("predicateObject"))
        pred_uuid_present = bool(pred_uuid)
        obj = index.get(pred_uuid)
        obj2 = index.get(D.uuid(body.get("predicateObject2")))
        obj_kind = obj[0] if obj else ""
        # 查不到分两种：predicateObject 是全零/缺失（none），或索引里没有该 uuid
        # （unresolved：可能是有名字但未索引的对象，也可能是无名对象
        # MemoryObject / SrcSinkObject / UnnamedPipeObject，后者按 R3 不建顶点）。
        if obj_kind:
            object_label = obj_kind
        elif pred_uuid_present:
            unnamed_kind = index.unnamed_kind(pred_uuid)
            object_label = unnamed_kind or "unresolved"
        else:
            object_label = "none"
        by_object_class.setdefault(etype, Counter())[object_label] += 1

        rc = D.number(props.get("rc"))
        size = D.number(body.get("size"))
        if rc is not None:
            result_present["rc"] += 1
        elif size is not None:
            result_present["size_only"] += 1
        else:
            result_present["absent"] += 1

        rule = table.get(etype)
        if rule is None:
            unmapped_types[etype] += 1
            settle(Bucket.UNMAPPED, f"unmapped_event:{etype}")
        elif subject is None and getattr(rule, "needs_subject", True):
            settle(Bucket.NO_OWNER, "subject_unseen")
        else:
            context = EventContext(
                event_id=event_id,
                ts_ns=ts_ns,
                etype=etype,
                body=body,
                props=props,
                subject=subject,
                obj_kind=obj_kind,
                obj=obj[1] if obj else None,
                obj2_kind=obj2[0] if obj2 else "",
                obj2=obj2[1] if obj2 else None,
                result_raw=rc,
                obj_label=object_label,
            )
            outcome, bucket, reason = emitter.apply(rule, context)
            settle(bucket, reason)
            for edge in outcome.edges:
                edge_csv.write(edge, etype)
                edges_by_class[edge.cls.value] += 1
                edges_by_action[edge.action] += 1
                edges_by_syscall[edge.syscall] += 1
                edges_written += 1
            graph.add(outcome)
            # 端点不变量：graph.add 之后，每条边的两端都必须在节点表里，
            # 否则写库时 MATCH 不到会把整条边静默跳过（dry-run 看不出来）。
            for edge in outcome.edges:
                for endpoint in (edge.src, edge.dst):
                    if endpoint not in graph.nodes:
                        dangling += 1

        if options.max_events and events_ingested >= options.max_events:
            break

        now = time.monotonic()
        if now - last_progress >= max(1, options.progress_every_s):
            last_progress = now
            elapsed = max(0.001, now - started_mono)
            print(
                f"[progress] events={events_ingested:,} edges={edges_written:,} "
                f"nodes={len(graph.nodes):,} {events_ingested / elapsed:,.0f} events/s "
                f"elapsed={elapsed:.0f}s",
                flush=True,
            )

    edge_csv.close()
    if event_csv is not None:
        event_csv.close()

    graph.flush()
    elapsed = time.time() - started
    snapshot = graph.snapshot()
    nodes_csv_rows = (
        R.write_nodes_csv(out_dir / "nodes.csv", graph.nodes.values())
        if options.write_csv else 0
    )

    payload: dict[str, Any] = {
        "scenario": options.scenario,
        "host_id": options.host_id,
        "host_name": host_name,
        "source_host_uuid": source_host,
        "archive": options.archive,
        "json_gb": round(bytes_read / 1e9, 2),
        "member_order": {"mode": member_mode, "time_monotonic": member_order_monotonic},
        "event_id_base": options.event_id_base,
        "event_id_range": [options.event_id_base + 1, event_id],
        "members_used": str(options.member_from)
        + (f"..{options.member_to}" if options.member_to is not None else "..end")
        + (" (sorted)" if options.sort_members else " (tar order)"),
        "window": {
            "from": D.iso_from_ns(options.time_from_ns),
            "to": D.iso_from_ns(options.time_to_ns),
            "data_first": D.iso_from_ns(first_ts),
            "data_last": D.iso_from_ns(last_ts),
        },
        "dry_run": options.dry_run,
        "database": options.database,
        "elapsed_s": round(elapsed, 2),
        "records_total": records_total,
        "records": dict(records_by_type.most_common()),
        "unnamed_objects": dict(unnamed_records.most_common()),
        "markers": dict(markers),
        "events": {
            "ingested": events_ingested,
            "settled": events_settled,
            "out_of_window": events_out_of_window,
            "bad_records": bad_records,
            "balanced": events_ingested == events_settled,
            "buckets": dict(buckets.most_common()),
            "top_reasons": reasons.most_common(20),
            "unmapped_table_missing": dict(unmapped_types.most_common()),
            "unmapped_by_reason": {
                reason: count for reason, count in reasons.most_common()
                if reason in UNMAPPED_REASONS
            },
            "object_class": {
                name: dict(counter) for name, counter in by_object_class.items()
            },
            "result_present": dict(result_present),
        },
        "graph": {
            "nodes": snapshot.total,
            "by_label": dict(snapshot.by_label),
            "edges": edges_written,
            "by_class": dict(edges_by_class.most_common()),
            "by_action": dict(edges_by_action.most_common()),
            "by_syscall": dict(edges_by_syscall.most_common()),
            "written_nodes": snapshot.written_nodes,
            "written_edges": snapshot.written_edges,
        },
        "gaps": {
            "result_absent": result_present["absent"],
            "payload_absent": events_ingested,
            "fd_table_absent": events_ingested,
            "process_unseen": emitter.counts["process_unseen"],
            "start_ns_zero": emitter.counts["start_ns_zero"],
            "path_missing": emitter.counts["path_missing"],
            "path_dirty": PATH_AUDIT["dirty"],
            "endpoints_missing": emitter.counts["endpoints_missing"],
            "self_loop": emitter.counts["self_loop"],
            "parent_by_ppid": emitter.counts["parent_by_ppid"],
            "parent_unresolved": emitter.counts["parent_unresolved"],
            "dangling_endpoints": dangling,
            "exec_file_unresolved": emitter.counts["exec_file_unresolved"],
            "result_absent_edges": emitter.counts["result_absent_edges"],
            "host_mismatch": emitter.counts["host_mismatch"],
        },
        "objects": index.counts(),
        "nodes_csv_rows": nodes_csv_rows,
        "csv_written": options.write_csv,
        "node_registry_max": limits.node_registry_max,
        "report_dir": str(out_dir),
    }
    R.write_json(out_dir / "report.json", payload)
    R.write_markdown(out_dir / "report.md", payload)
    return payload
