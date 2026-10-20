"""报告落盘：只读 RunSnapshot，写 4 个 CSV + report.json + report.md。"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ...core.kinds import FileKey, ProcKey, key_cells
from ...core.options import ReportOptions
from ...core.results import res_semantic
from ...core.snapshots import RunSnapshot

_NODE_HEADER = [
    "label", "host_id", "container_id", "pid", "born_ns", "path", "tuple",
    "exe", "args", "ppid", "ruid", "uid", "privileged",
    "host_root_rw", "kind", "proto",
]


def _node_rows(nodes: dict) -> list[list[str]]:
    rows: list[list[str]] = []
    for key, node in nodes.items():
        if isinstance(key, ProcKey):
            p = node.props
            rows.append(["Process", key.host_id, key.container_id, str(key.pid),
                         str(key.born_ns), "", "", p.get("exe") or "",
                         p.get("args") or "",
                         "" if p.get("ppid") is None else str(p.get("ppid")),
                         p.get("ruid") or "",
                         "" if p.get("uid") is None else str(p.get("uid")),
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


def _process_coverage(nodes: dict) -> dict[str, int | float]:
    total = exe_present = args_present = 0
    both = exe_only = args_only = neither = 0
    for key, node in nodes.items():
        if not isinstance(key, ProcKey):
            continue
        total += 1
        has_exe = bool(node.props.get("exe"))
        has_args = bool(node.props.get("args"))
        if has_exe:
            exe_present += 1
        if has_args:
            args_present += 1
        if has_exe and has_args:
            both += 1
        elif has_exe:
            exe_only += 1
        elif has_args:
            args_only += 1
        else:
            neither += 1

    def pct(value: int) -> float:
        return round(100.0 * value / total, 2) if total else 0.0

    return {
        "total": total,
        "exe_present": exe_present,
        "exe_pct": pct(exe_present),
        "args_present": args_present,
        "args_pct": pct(args_present),
        "both": both,
        "exe_only": exe_only,
        "args_only": args_only,
        "neither": neither,
    }


def _degree_rows(items) -> list[dict[str, str]]:
    out = []
    for key, degree in items:
        cells = key_cells(key)
        out.append({"label": cells[0], "pid": cells[3], "path": cells[5], "degree": degree})
    return out


# 客体来自上下文或返回值、不靠参数的调用：不参与「登记但不产边」披露
_CONTEXT_OBJ = frozenset({"exit", "exit_group", "procexit"})


def _no_edge_block(stats) -> list[dict]:
    """「登记但不产边」：动词表声明建边，本批却一条边也没产出的调用。

    这不是「覆盖」，必须在报告里逐名披露；否则下游会以为这些边存在。
    客体来自上下文/返回值的调用（exit 族）不计入。
    每条带上零边的主因，区分「数据源不给客体」与「本批调用全失败」
    「目标 pid 解析不到」——三者含义完全不同，不能混在一起。
    """
    out = []
    for name, calls in stats.emit_calls.items():
        if name in _CONTEXT_OBJ:
            continue
        if stats.emit_calls_with_edge.get(name, 0) == 0:
            out.append({
                "call": name,
                "calls": calls,
                "reason": stats.emit_no_edge_reason.get(name, "unknown"),
            })
    return sorted(out, key=lambda x: -x["calls"])


def _res_block(stats) -> dict:
    """每个 action 的 res 语义与四分类（null/negative/zero/positive）。

    这张表是 res 口径的常驻哨兵：比如 ``create`` 一旦出现 ``positive``，
    就说明文件描述符号泄漏到 res 了。
    """
    bins: dict[str, dict[str, object]] = {}
    for action, b in sorted(stats.edge_res.items(), key=lambda kv: -sum(kv[1])):
        bins[action] = {
            "semantic": res_semantic(action),
            "null": b[0],
            "negative": b[1],
            "zero": b[2],
            "positive": b[3],
        }
    return {
        "bins": bins,
        "with_res": sum(b[1] + b[2] + b[3] for b in stats.edge_res.values()),
        "without_res": sum(b[0] for b in stats.edge_res.values()),
    }


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
            "main_pid_present_rows": stats.pid_present_rows,
            "audit_total_rows": None,
            "audit_pid_rows": None,
            "audit_skipped": audit is None,
            "ok": None,
            "type_diff": [],
            "pid_type_diff": [],
        }
        collector = {
            "total_rows": None,
            "pid_rows": None,
            "dropped_by_type": {},
            "dropped_total": 0,
            "missing_pid_by_type": dict(stats.missing_by_field.get("proc.pid", {})),
        }
        if audit is not None:
            transport["audit_total_rows"] = audit.total_rows
            transport["audit_pid_rows"] = audit.pid_rows
            transport["decoded_rows"] = snapshot.ledger.ingested - snapshot.ledger.abnormal
            transport["ok"] = (
                snapshot.ledger.ingested == audit.total_rows
                and stats.pid_present_rows == audit.pid_rows
            )
            for name, count in audit.total_by_type.items():
                main_count = stats.by_type.get(name, 0)
                if count != main_count:
                    transport["type_diff"].append(
                        {"type": name, "audit": count, "main": main_count}
                    )
            for name, count in audit.pid_by_type.items():
                main_count = stats.pid_present_by_type.get(name, 0)
                if count != main_count:
                    transport["pid_type_diff"].append(
                        {"type": name, "audit": count, "main": main_count}
                    )
            missing_pid = {
                name: total - audit.pid_by_type.get(name, 0)
                for name, total in audit.total_by_type.items()
                if total - audit.pid_by_type.get(name, 0) > 0
            }
            collector = {
                "total_rows": audit.total_rows,
                "pid_rows": audit.pid_rows,
                "dropped_by_type": {},
                "dropped_total": 0,
                "missing_pid_by_type": missing_pid,
            }

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
            "format": {"star": True, "audit": audit is not None},
            "coverage": snapshot.coverage,
            "ledger": {
                "buckets": snapshot.ledger.buckets,
                "equation": snapshot.ledger.equation,
                "top_reasons": snapshot.ledger.top_reasons,
            },
            "gaps": gaps,
            "transport": transport,
            "collector": collector,
            "placeholder_by_field": stats.missing_by_field,
            "param_availability": {
                name: {
                    "events": v[0],
                    "res_observed": v[1],
                    "res_from_rawres": stats.res_source.get(name, {}).get("rawres", 0),
                    "res_from_args_fallback": stats.res_source.get(name, {}).get("args", 0),
                    "object_resolved": v[2],
                }
                for name, v in sorted(stats.param.items(), key=lambda kv: -kv[1][0])
            },
            "unclassified": dict(sorted(stats.unmapped.items(), key=lambda kv: -kv[1])),
            "containers": snapshot.state.containers,
            "edges": {
                "total": stats.edge_rows,
                "by_action": stats.edges_by_action,
                "by_class": stats.edges_by_class,
                "res": _res_block(stats),
                "top_out": _degree_rows(snapshot.graph.top_out),
                "top_in": _degree_rows(snapshot.graph.top_in),
            },
            "registered_without_edge": _no_edge_block(stats),
            "capability_gaps": [
                {"call": name, "value": value, "calls": count}
                for name, (count, value) in sorted(
                    stats.capability_gaps.items(), key=lambda kv: -kv[1][0]
                )
            ],
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
            "process_coverage": _process_coverage(snapshot.graph.nodes),
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
        "主趟使用格式串最前面的 `*`：条件字段缺失输出 `<NA>` 占位，不会整行消失；"
        "缺号是文件内确实不存在的事件号，字段缺失统计见 placeholder_by_field。",
        "`%proc.duration` 只在 execve 行可打印；本版未启用第三趟，born_src=duration 不产出。",
        "fd 名字/类型/返回值从 evt.args 解，不使用 %fd.name / %fd.type / %evt.rawres；"
        "当前模板保持窄列，避免增加每行体积。",
        "edge.head 是 %evt.buffer -b 的前 payload_max_bytes 字节再 base64 编码，不是可打印文本；"
        "完整载荷需回原始 .scap。",
        "边的 res 只表达结果：数据类=字节数、失败=负错误码、零=实测零；未观测时不写属性"
        "（Neo4j 里属性不存在，edges.csv 里为空串）。",
        "open 家族与 accept 成功时返回的是文件描述符、mmap 成功时返回的是内存地址，"
        "这两类成功值不进 res（fd 号与地址不是结果，仅在失败时写负错误码）。",
        "结果缺失（退出行无 %evt.rawres 且参数里无 res=）不伪造 0：落“其他”桶的"
        " result_unobserved:<动词>，不进 attempts.csv。",
        "「登记但不产边」= 动词表声明建边、本批零客体零边的调用（见 registered_without_edge）；"
        "保留登记是为了换采集端后重测，但报告中不得把它当成已覆盖。",
        "「能力缺口」= 设计等级 L1/L2、却因数据源不给客体而归入记账/丢弃的调用"
        "（见 capability_gaps）；它们是换采集端后必须重测的清单。",
        "param_availability 是调用级口径，edges.res 是边级口径：两者不能互推"
        "（一个调用可能不建边或建多条边），报告中不得用其互校。",
        "res_from_rawres 是 %evt.rawres 直接提供的条数；res_from_args_fallback 只在"
        " %evt.rawres 缺失时兜底，两者之和 = res_observed。",
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
        f"- 格式：star　审计：{'开启' if p['format']['audit'] else '跳过'}",
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

    cov = p["process_coverage"]
    lines += [
        "",
        "## Process 属性覆盖",
        "",
        f"- Process 节点 {cov['total']}",
        f"- `exe` 有值 {cov['exe_present']} / {cov['total']} = {cov['exe_pct']}%（程序识别）",
        f"- `args` 有值 {cov['args_present']} / {cov['total']} = {cov['args_pct']}%（参数细节）",
        f"- `exe` 有、`args` 空：{cov['exe_only']}；两者都有：{cov['both']}；"
        f"`exe` 空、`args` 有：{cov['args_only']}；两者都空：{cov['neither']}",
    ]

    res = edges["res"]
    lines += [
        "",
        f"- res：有值 {res['with_res']}，无值 {res['without_res']}",
        "",
        "| action | res 语义 | null | 负 | 零 | 正 |",
        "|---|---|---|---|---|---|",
    ]
    for action, b in res["bins"].items():
        lines.append(
            f"| {action} | {b['semantic']} | {b['null']} | {b['negative']} | "
            f"{b['zero']} | {b['positive']} |"
        )

    lines += ["", "## 最热未归类", ""]
    if p["unclassified"]:
        for name, count in list(p["unclassified"].items())[:15]:
            lines.append(f"- `{name}` {count}")
    else:
        lines.append("- 无")

    no_edge = p["registered_without_edge"]
    lines += ["", "## 登记但不产边（声明建边、实际零边）", ""]
    if no_edge:
        lines += ["| 调用 | 调用次数 | 零边主因 |", "|---|---|---|"]
        for item in no_edge:
            lines.append(f"| `{item['call']}` | {item['calls']:,} | {item['reason']} |")
    else:
        lines.append("- 无")

    gaps = p["capability_gaps"]
    lines += ["", "## 能力缺口（设计 L1/L2，因无客体降级为记账）", ""]
    if gaps:
        lines += ["| 调用 | 设计等级 | 调用次数 |", "|---|---|---|"]
        for item in gaps:
            lines.append(f"| `{item['call']}` | {item['value']} | {item['calls']:,} |")
    else:
        lines.append("- 无")

    ep = p["endpoint_visibility"]
    lines += [
        "",
        "## 监听端点可见性",
        "",
        f"- bind/listen 调用 {ep['total']:,} 次，产出监听端点边的 {ep['with_edge']:,} 次"
        + (f"（{ep['ratio']:.1%}）" if ep["ratio"] is not None else ""),
        f"- {ep['note']}",
    ]

    lines += ["", "## 边界", ""]
    lines += [f"- {item}" for item in p["boundaries"]]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
