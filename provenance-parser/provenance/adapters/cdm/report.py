"""CDM 运行的报告与 CSV 落地。

为什么不复用 ``adapters/report``：那套报告有 14 个 sysdig 专属小节
（配对池、fd 表、born 时间、容器元数据、evt.type 分布……）。CDM 数据没有
进入/退出配对、没有 fd 表、没有容器维度，硬套会把「不适用」写成 0，读报告的人
无法区分「实测为 0」和「该数据源没有这个概念」。因此这里另起一份字段集合，
只保留 CDM 上真实可测的量。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from ...core.graph import Edge
from ...core.kinds import key_cells, label_of


class EdgeCsv:
    """边流水（边在 GraphStore 里只缓冲一批就写库，不长期保留，因此必须边产边落）。"""

    HEADER = [
        "edge_class", "action", "syscall", "src_label", "src_host", "src_container",
        "src_pid", "src_start_ns", "src_path", "dst_label", "dst_host", "dst_container",
        "dst_pid", "dst_start_ns", "dst_path", "event_id", "cdm_event",
        "start_ns", "result", "to_path", "mode",
    ]

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = open(path, "w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._handle)
        self._writer.writerow(self.HEADER)
        self.rows = 0

    def write(self, edge: Edge, event_type: str = "") -> None:
        src = key_cells(edge.src)
        dst = key_cells(edge.dst)
        self._writer.writerow([
            edge.cls.value, edge.action, edge.syscall, *src, *dst,
            edge.event_id, event_type, edge.start_ns,
            "" if edge.result is None else edge.result,
            edge.to_path or "", edge.mode or "",
        ])
        self.rows += 1

    def close(self) -> None:
        self._handle.close()


class NullCsv:
    """空写出器：只做规模普查（不要边明细）时用，避免写数 GB 的 CSV。"""

    rows = 0

    def write(self, *args, **kwargs) -> None:
        return None

    def close(self) -> None:
        return None


class EventCsv:
    """event_id -> 原始记录定位（成员, 行号, uuid），供标准答案回查。

    ``event_id`` 是「第 N 条被扫描到的 Event」的序号（从 1 起，跨成员连续），
    因此同一份归档、同一组成员参数下可复现。
    """

    HEADER = ["event_id", "member", "line_no", "uuid", "type", "timestamp_ns"]

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = open(path, "w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._handle)
        self._writer.writerow(self.HEADER)
        self.rows = 0

    def write(self, event_id: int, member: str, line_no: int, uuid: str,
              etype: str, ts_ns: int) -> None:
        self._writer.writerow([event_id, member, line_no, uuid, etype, ts_ns])
        self.rows += 1

    def close(self) -> None:
        self._handle.close()


def write_nodes_csv(path: Path, nodes: Iterable) -> int:
    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "label", "host_id", "container_id", "pid", "start_ns", "path",
            "exe_path", "cmdline", "ppid", "uid", "euid", "file_type", "proto",
        ])
        for node in nodes:
            key = key_cells(node.key)
            props = node.props or {}
            writer.writerow([
                *key,
                props.get("exe_path") or "", props.get("cmdline") or "",
                props.get("ppid", ""), props.get("uid") or "", props.get("euid", ""),
                props.get("file_type") or "", props.get("proto") or "",
            ])
            rows += 1
    return rows


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    led = payload["events"]
    graph = payload["graph"]
    gaps = payload["gaps"]
    lines: list[str] = []
    add = lines.append
    add(f"# CDM 解析报告：{payload['scenario']}")
    add("")
    add(f"- 归档：`{payload['archive']}`（窗口内 JSON {payload['json_gb']:.2f} GB）")
    order = payload.get("member_order", {})
    add(f"- 成员：{payload['members_used']}；模式={order.get('mode')}；时间单调={order.get('time_monotonic')}")
    add(f"- 时间窗：{payload['window']['from'] or '-'} .. {payload['window']['to'] or '-'}")
    add(f"- 主机：`{payload['host_id']}`")
    add(f"- 数据库：`{payload['database']}`（dry_run={payload['dry_run']}）")
    add(f"- 耗时：{payload['elapsed_s']:.1f} s")
    add("")
    add("## 记录与事件")
    add("")
    add(f"- 扫描记录 {payload['records_total']:,} 条")
    add(f"- Event {led['ingested']:,} 条已接入；窗口外跳过 {led['out_of_window']:,} 条")
    add(f"- 账本：接入 {led['ingested']:,} = 已结算 {led['settled']:,}（平衡={led['balanced']}）")
    add("")
    add("| 桶 | 条数 |")
    add("|---|---|")
    for bucket, count in led["buckets"].items():
        add(f"| {bucket} | {count:,} |")
    add("")
    add("## 图")
    add("")
    add(f"- 顶点 {graph['nodes']:,}：{graph['by_label']}")
    add(f"- 边 {graph['edges']:,}：{graph['by_class']}")
    add("")
    add("| action | 边数 |")
    add("|---|---|")
    for action, count in graph["by_action"].items():
        add(f"| {action} | {count:,} |")
    add("")
    add("## CDM 口径缺口")
    add("")
    for key, value in gaps.items():
        add(f"- `{key}`: {value}")
    add("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
