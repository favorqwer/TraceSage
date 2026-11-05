"""report.md 渲染。"""

from __future__ import annotations

from pathlib import Path


def write_markdown(path: Path, p: dict) -> None:
    led = p["ledger"]
    eq = led["equation"]
    lines = [
        f"# {p['scenario']} 解析报告",
        "",
        f"- 主机：`{p['host_id']}`　后端：`{p['backend']}`　耗时：{p['elapsed_s']}s",
        f"- 数据库：`{p['database']}`　dry-run：{p['dry_run']}",
        f"- 格式：star",
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
        f"- 系统调用分布：" + ", ".join(f"{k}={v}" for k, v in sorted(
            edges.get("by_syscall", {}).items(), key=lambda kv: -kv[1])[:20]),
    ]

    cov = p["process_coverage"]
    lines += [
        "",
        "## Process 属性覆盖",
        "",
        f"- Process 节点 {cov['total']}",
        f"- `exe_path` 有值 {cov['exe_path_present']} / {cov['total']} = {cov['exe_path_pct']}%（程序识别）",
        f"- `cmdline` 有值 {cov['cmdline_present']} / {cov['total']} = {cov['cmdline_pct']}%（参数细节）",
        f"- `exe_path` 有、`cmdline` 空：{cov['exe_path_only']}；两者都有：{cov['both']}；"
        f"`exe_path` 空、`cmdline` 有：{cov['cmdline_only']}；两者都空：{cov['neither']}",
    ]

    result = edges["result"]
    lines += [
        "",
        f"- result：有值 {result['with_result']}，无值 {result['without_result']}",
        "",
        "| action | result 语义 | null | 负 | 零 | 正 |",
        "|---|---|---|---|---|---|",
    ]
    for action, b in result["bins"].items():
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
    cb = p["collector_blind"]
    lines += ["", "## 采集端盲区（调用名都没有）", ""]
    if cb.get("available"):
        counts = cb.get("counts", {})
        lines += [
            f"- sysdig 定义事件 {counts.get('defined_events', '?')} 个，"
            f"实际出现 {counts.get('observed_event_types', '?')} 种",
            f"- 盲区系统调用 **{counts.get('count', '?')}** 个；"
            f"本次落「采集端盲区」桶 {cb.get('unknown_rows', 0):,} 行",
            "- 关键盲区：" + ", ".join(f"`{x}`" for x in cb.get("critical", [])),
        ]
    else:
        lines.append(f"- {cb.get('note', '不可用')}")

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
