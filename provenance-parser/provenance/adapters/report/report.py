"""报告落盘：只读 RunSnapshot，写 4 个 CSV + report.json + report.md。"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ...core.kinds import FileKey, ProcKey, key_cells
from ...core.options import ReportOptions
from ...core.snapshots import RunSnapshot

_NODE_HEADER = [
    "label", "host_id", "container_id", "pid", "born_ns", "path", "tuple",
    "born_src", "exe", "cmdline", "ppid", "ruid", "privileged", "host_root_rw",
    "kind", "proto",
]


def _node_rows(nodes: dict) -> list[list[str]]:
    rows: list[list[str]] = []
    for key, node in nodes.items():
        if isinstance(key, ProcKey):
            p = node.props
            rows.append(["Process", key.host_id, key.container_id, str(key.pid),
                         str(key.born_ns), "", "", p.get("born_src") or "",
                         p.get("exe") or "", p.get("cmdline") or "",
                         "" if p.get("ppid") is None else str(p.get("ppid")),
                         p.get("ruid") or "",
                         "" if p.get("privileged") is None else str(p.get("privileged")).lower(),
                         "" if p.get("host_root_rw") is None else str(p.get("host_root_rw")).lower(),
                         "", ""])
        elif isinstance(key, FileKey):
            rows.append(["File", key.host_id, key.container_id, "", "", key.path, "", "",
                         "", "", "", "", "", "", node.props.get("kind") or "", ""])
        else:
            rows.append(["Network", key.host_id, "", "", "", "", key.tuple, "", "", "",
                         "", "", "", "", "", node.props.get("proto") or ""])
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]))
    return rows


def _degree_rows(items) -> list[dict[str, str]]:
    out = []
    for key, degree in items:
        cells = key_cells(key)
        out.append({"label": cells[0], "pid": cells[3], "path": cells[5], "degree": degree})
    return out


class ReportWriter:
    def __init__(self, options: ReportOptions) -> None:
        self.options = options

    def write(self, snapshot: RunSnapshot) -> dict:
        report_dir = self.options.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)

        # nodes.csv
        rows = _node_rows(snapshot.graph.nodes)
        with (report_dir / "nodes.csv").open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_NODE_HEADER)
            writer.writerows(rows)

        self._write_ops(snapshot)
        self._write_attempts(snapshot)

        stats = snapshot.stats
        audit = snapshot.audit
        transport = {
            "main_rows": snapshot.ledger.ingested,
            "audit_pid_rows": None,
            "ok": None,
            "type_diff": [],
        }
        collector = {
            "total_rows": None,
            "pid_rows": None,
            "dropped_by_type": {},
            "dropped_total": 0,
        }
        if audit is not None:
            transport["audit_pid_rows"] = audit.pid_rows
            transport["decoded_rows"] = snapshot.ledger.ingested - snapshot.ledger.abnormal
            transport["ok"] = transport["decoded_rows"] == audit.pid_rows
            for name, count in audit.pid_by_type.items():
                diff = count - stats.by_type.get(name, 0)
                if diff:
                    transport["type_diff"].append(
                        {"type": name, "audit": count, "main": stats.by_type.get(name, 0)}
                    )
            dropped = audit.dropped_by_type()
            collector = {
                "total_rows": audit.total_rows,
                "pid_rows": audit.pid_rows,
                "dropped_by_type": dropped,
                "dropped_total": sum(dropped.values()),
            }

        gaps = dict(snapshot.ledger.gaps)
        if audit is not None:
            gaps["collector_unprintable"] = collector["dropped_total"]
            gaps["absent_from_file"] = max(
                0, gaps["missing_numbers"] - collector["dropped_total"]
            )

        payload = {
            "scenario": snapshot.scenario,
            "host_id": snapshot.host_id,
            "scap": snapshot.scap,
            "backend": snapshot.backend,
            "dry_run": snapshot.dry_run,
            "database": snapshot.database,
            "elapsed_s": round(snapshot.elapsed_s, 2),
            "coverage": snapshot.coverage,
            "ledger": {
                "buckets": snapshot.ledger.buckets,
                "equation": snapshot.ledger.equation,
                "top_reasons": snapshot.ledger.top_reasons,
            },
            "gaps": gaps,
            "transport": transport,
            "collector": collector,
            "param_availability": {
                name: {"events": v[0], "res_present": v[1], "object_resolved": v[2]}
                for name, v in sorted(stats.param.items(), key=lambda kv: -kv[1][0])
            },
            "unclassified": dict(sorted(stats.unmapped.items(), key=lambda kv: -kv[1])),
            "containers": snapshot.state.containers,
            "edges": {
                "total": stats.edge_rows,
                "by_action": stats.edges_by_action,
                "by_class": stats.edges_by_class,
                "top_out": _degree_rows(snapshot.graph.top_out),
                "top_in": _degree_rows(snapshot.graph.top_in),
            },
            "nodes": {
                "total": snapshot.graph.total,
                "by_label": snapshot.graph.by_label,
            },
            "born": snapshot.state.proc,
            "fds": snapshot.state.fds,
            "pairing": {
                "enter_rows": stats.enter_rows,
                "exit_rows": stats.exit_rows,
                "single_line_rows": stats.single_line_rows,
                "logical_calls": stats.exit_rows + stats.single_line_rows,
                "no_owner_rows": stats.no_owner_rows,
            },
            "bad_rows": stats.bad,
            "bad_samples": stats.bad_samples,
            "written": {
                "nodes": snapshot.graph.written_nodes,
                "edges": snapshot.graph.written_edges,
            },
            "boundaries": _boundaries(snapshot.node_registry_max, collector),
        }

        (report_dir / "report.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _write_markdown(report_dir / "report.md", payload)
        return payload

    def _write_ops(self, snapshot: RunSnapshot) -> None:
        path = self.options.report_dir / "ops.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "container", "pid", "born_ns", "name", "count",
                             "first_ns", "last_ns"])
            for (proc, name), (count, first, last) in sorted(
                snapshot.stats.ops.items(), key=lambda kv: -kv[1][0]
            ):
                writer.writerow([proc.host_id, proc.container_id, proc.pid, proc.born_ns,
                                 name, count, first, last])

    def _write_attempts(self, snapshot: RunSnapshot) -> None:
        path = self.options.report_dir / "attempts.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "container", "pid", "born_ns", "verb", "target",
                             "errno", "count", "first_ns", "last_ns"])
            for (proc, verb, target, errno), (count, first, last) in sorted(
                snapshot.stats.attempts.items(), key=lambda kv: -kv[1][0]
            ):
                writer.writerow([proc.host_id, proc.container_id, proc.pid, proc.born_ns,
                                 verb, target, errno, count, first, last])


def _boundaries(node_registry_max: int, collector: dict) -> list[str]:
    items = [
        "事件号缺号同时包含采集丢失与采集端不可打印，二者比例无法从输出流区分，"
        "按类型量化见 collector.dropped_by_type。",
        "`%proc.duration` 只在 execve 行可打印；本版未启用第三趟，born_src=duration 不产出。",
        "fd 名字/类型/返回值从 evt.args 解，不使用 %fd.name / %fd.type / %evt.rawres"
        "（进模板会成行丢失，实测 34.7% / 34.6% / 26.1%）。",
        "edge.head 是采集端对载荷的可打印渲染（不可打印字节为 '.'），不是 base64。",
        "Network.proto 只在 fd token 带 t/u 时有值（accept 侧通常有，connect 进入行通常没有）。",
        "未连接 UDP 的 sendto 目的地不在参数里（tuple=NULL），该 fd 无客体 -> 未知句柄。",
        "PID 命名空间未做翻译：syscall 的 pid 参数是调用者命名空间内的号，命中不到时计"
        " target_unresolved；若该 pid 在别的容器存在，另计 target_pid_other_ns。",
        "rename/link 切断客体历史：新路径是新节点，旧路径的历史不迁移（五边约束）。",
        "同路径删除后重建视为同一节点（数据源无 inode/版本号进键）。",
        "节点登记表上限 %d；超过即阻断（内存纪律）。" % node_registry_max,
        "edges.csv 按事件顺序写出（确定性），未做全局排序。",
    ]
    if collector.get("dropped_by_type"):
        top = ", ".join(f"{k}={v}" for k, v in sorted(
            collector["dropped_by_type"].items(), key=lambda kv: -kv[1])[:3])
        items.append(f"采集端丢弃最多的事件类型：{top}。")
    return items


def _write_markdown(path: Path, p: dict) -> None:
    led = p["ledger"]
    eq = led["equation"]
    lines = [
        f"# {p['scenario']} 解析报告",
        "",
        f"- 主机：`{p['host_id']}`　后端：`{p['backend']}`　耗时：{p['elapsed_s']}s",
        f"- 数据库：`{p['database']}`　dry-run：{p['dry_run']}",
        f"- 动词表：{p['coverage']['verbs']} 个（另有 {p['coverage']['deferred_verbs']} 个按约定延后）",
        "",
        "## 账本（行）",
        "",
        f"- 接入 {eq['ingested']} = 已结算 {eq['settled']} + 异常 {eq['abnormal']}，平衡：{eq['balanced']}",
        "",
        "| 桶 | 行数 |",
        "|---|---|",
    ]
    for bucket, count in sorted(led["buckets"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {bucket} | {count} |")

    gaps = p["gaps"]
    lines += [
        "",
        "## 事件号",
        "",
        f"- 实存 {gaps['ingested_rows']} 行，末号 {gaps['max_event_num']}，"
        f"缺号 {gaps['missing_numbers']}（{gaps['gap_segments']} 段，最大 {gaps['max_gap']}）",
    ]
    if p["collector"]["dropped_total"]:
        dropped = ", ".join(f"{k}={v}" for k, v in p["collector"]["dropped_by_type"].items())
        lines.append(f"- 采集端对模板不可打印：{p['collector']['dropped_total']} 行（{dropped}）")
    if "absent_from_file" in gaps:
        lines.append(f"- 文件内确实不存在的事件号：{gaps['absent_from_file']}")

    edges = p["edges"]
    lines += [
        "",
        "## 图",
        "",
        f"- 节点 {p['nodes']['total']}：{p['nodes']['by_label']}",
        f"- 边 {edges['total']}：{edges['by_class']}",
        f"- 动作分布：" + ", ".join(f"{k}={v}" for k, v in sorted(
            edges["by_action"].items(), key=lambda kv: -kv[1])),
    ]

    lines += ["", "## 最热未归类", ""]
    if p["unclassified"]:
        for name, count in list(p["unclassified"].items())[:15]:
            lines.append(f"- `{name}` {count}")
    else:
        lines.append("- 无")

    lines += ["", "## 边界", ""]
    lines += [f"- {item}" for item in p["boundaries"]]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
