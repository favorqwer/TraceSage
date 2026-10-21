"""report.json payload 构造。"""

from __future__ import annotations

from ...core.options import ReportOptions
from ...core.snapshots import RunSnapshot
from .blocks import boundaries, collector_blind, no_edge_block, result_block
from .tables import degree_rows, process_coverage


def build_payload(snapshot: RunSnapshot, options: ReportOptions) -> dict:
    stats = snapshot.stats
    gaps = dict(snapshot.ledger.gaps)
    # 主趟使用 *：字段缺失只产生 <NA>，不会整行消失。
    # 因此缺号全部是“文件内确实不存在”的事件号，而不是采集端丢行。
    gaps["collector_unprintable"] = 0
    gaps["absent_from_file"] = gaps["missing_numbers"]

    payload = {
        "scenario": snapshot.scenario,
        "host_id": snapshot.host_id,
        "scap": snapshot.scap,
        "backend": snapshot.backend,
        "dry_run": snapshot.dry_run,
        "database": snapshot.database,
        "elapsed_s": round(snapshot.elapsed_s, 2),
        "format": {"star": True},
        "coverage": snapshot.coverage,
        "ledger": {
            "buckets": snapshot.ledger.buckets,
            "equation": snapshot.ledger.equation,
            "top_reasons": snapshot.ledger.top_reasons,
        },
        "gaps": gaps,
        "placeholder_by_field": stats.missing_by_field,
        "param_availability": {
            name: {
                "events": v[0],
                "result_observed": v[1],
                "result_from_rawres": stats.result_source.get(name, {}).get("rawres", 0),
                "result_from_args_fallback": stats.result_source.get(name, {}).get("args", 0),
                "object_resolved": v[2],
            }
            for name, v in sorted(stats.param.items(), key=lambda kv: -kv[1][0])
        },
        "unclassified": dict(sorted(stats.unmapped.items(), key=lambda kv: -kv[1])),
        "containers": snapshot.state.containers,
        "edges": {
            "total": stats.edge_rows,
            "by_action": stats.edges_by_action,
            "by_syscall": stats.edges_by_syscall,
            "by_class": stats.edges_by_class,
            "result": result_block(stats),
            "top_out": degree_rows(snapshot.graph.top_out),
            "top_in": degree_rows(snapshot.graph.top_in),
        },
        "registered_without_edge": no_edge_block(stats),
        "capability_gaps": [
            {"call": name, "value": value, "calls": count}
            for name, (count, value) in sorted(
                stats.capability_gaps.items(), key=lambda kv: -kv[1][0]
            )
        ],
        "collector_blind": {
            **collector_blind(options.data_dir),
            "unknown_rows": snapshot.ledger.buckets.get("采集端盲区", 0),
        },
        "endpoint_visibility": {
            "total": stats.endpoint_total,
            "with_edge": stats.endpoint_with_edge,
            "ratio": (round(stats.endpoint_with_edge / stats.endpoint_total, 3)
                      if stats.endpoint_total else None),
            "note": "bind 与 TCP listen 的数据源不提供 addr；unix 域 listen 可经 fd.name 可见",
        },
        "nodes": {
            "total": snapshot.graph.total,
            "by_label": snapshot.graph.by_label,
        },
        "born": snapshot.state.proc,
        "process_coverage": process_coverage(snapshot.graph.nodes),
        "process_identity": {
            "unique_pids": snapshot.state.proc.get("unique_pids", 0),
            "segments": snapshot.state.proc.get("segments", 0),
            "multi_node_groups": snapshot.state.proc.get("multi_node_groups", 0),
            "extra_segments": snapshot.state.proc.get("extra_segments", 0),
            "extra_with_exec": snapshot.state.proc.get("extra_with_exec", 0),
            "extra_with_clone": snapshot.state.proc.get("extra_with_clone", 0),
            "late_clone_placeholders": snapshot.state.proc.get("late_clone_placeholders", 0),
            "unexplained_segments": snapshot.state.proc.get("unexplained_segments", 0),
            "thread_clone": snapshot.state.proc.get("thread_clone", 0),
            "thread_exit": snapshot.state.proc.get("thread_exit", 0),
            "thread_untracked": snapshot.state.proc.get("thread_untracked", 0),
            "exit_no_segment": snapshot.state.proc.get("exit_no_segment", 0),
            "exit_tid_missing": snapshot.state.proc.get("exit_tid_missing", 0),
            "late_event_after_exit": snapshot.state.proc.get("late_event_after_exit", 0),
        },
        "fds": snapshot.state.fds,
        "pairing": {
            "enter_rows": stats.enter_rows,
            "exit_rows": stats.exit_rows,
            "single_line_rows": stats.single_line_rows,
            "logical_calls": stats.exit_rows + stats.single_line_rows,
            "no_owner_rows": stats.no_owner_rows,
            "pid_present_rows": stats.pid_present_rows,
            "outcomes": dict(snapshot.pairing),
        },
        "bad_rows": stats.bad,
        "bad_samples": stats.bad_samples,
        "written": {
            "nodes": snapshot.graph.written_nodes,
            "edges": snapshot.graph.written_edges,
        },
        "boundaries": boundaries(snapshot.node_registry_max),
    }
    return payload
