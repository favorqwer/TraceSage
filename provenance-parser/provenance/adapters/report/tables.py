"""报告表格：nodes.csv / ops.csv / attempts.csv 与度数/覆盖统计。"""

from __future__ import annotations

import csv
from pathlib import Path

from ...core.kinds import FileKey, ProcKey, key_cells
from ...core.snapshots import RunSnapshot

NODE_HEADER = [
    "label", "host_id", "container_id", "pid", "start_ns", "path", "endpoints",
    "exe_path", "cmdline", "ppid", "uid", "euid", "container_privileged",
    "container_host_root_rw", "file_type", "proto",
]


def node_rows(nodes: dict) -> list[list[str]]:
    rows: list[list[str]] = []
    for key, node in nodes.items():
        if isinstance(key, ProcKey):
            p = node.props
            rows.append(["Process", key.host_id, key.container_id, str(key.pid),
                         str(key.start_ns), "", "", p.get("exe_path") or "",
                         p.get("cmdline") or "",
                         "" if p.get("ppid") is None else str(p.get("ppid")),
                         p.get("uid") or "",
                         "" if p.get("euid") is None else str(p.get("euid")),
                         "" if p.get("container_privileged") is None else str(p.get("container_privileged")).lower(),
                         "" if p.get("container_host_root_rw") is None else str(p.get("container_host_root_rw")).lower(),
                         "", ""])
        elif isinstance(key, FileKey):
            rows.append(["File", key.host_id, key.container_id, "", "", key.path, "", "",
                         "", "", "", "", "", "", node.props.get("file_type") or "", ""])
        else:
            rows.append(["Network", key.host_id, "", "", "", "", key.endpoints, "", "", "",
                         "", "", "", "", "", node.props.get("proto") or ""])
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]))
    return rows


def process_coverage(nodes: dict) -> dict[str, int | float]:
    total = exe_present = cmdline_present = 0
    both = exe_only = cmdline_only = neither = 0
    for key, node in nodes.items():
        if not isinstance(key, ProcKey):
            continue
        total += 1
        has_exe = bool(node.props.get("exe_path"))
        has_cmdline = bool(node.props.get("cmdline"))
        if has_exe:
            exe_present += 1
        if has_cmdline:
            cmdline_present += 1
        if has_exe and has_cmdline:
            both += 1
        elif has_exe:
            exe_only += 1
        elif has_cmdline:
            cmdline_only += 1
        else:
            neither += 1

    def pct(value: int) -> float:
        return round(100.0 * value / total, 2) if total else 0.0

    return {
        "total": total,
        "exe_path_present": exe_present,
        "exe_path_pct": pct(exe_present),
        "cmdline_present": cmdline_present,
        "cmdline_pct": pct(cmdline_present),
        "both": both,
        "exe_path_only": exe_only,
        "cmdline_only": cmdline_only,
        "neither": neither,
    }


def degree_rows(items) -> list[dict[str, str]]:
    out = []
    for key, degree in items:
        cells = key_cells(key)
        out.append({"label": cells[0], "pid": cells[3], "path": cells[5], "degree": degree})
    return out


def write_nodes_csv(report_dir: Path, snapshot: RunSnapshot) -> None:
    rows = node_rows(snapshot.graph.nodes)
    with (report_dir / "nodes.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(NODE_HEADER)
        writer.writerows(rows)


def write_ops_csv(report_dir: Path, snapshot: RunSnapshot) -> None:
    path = report_dir / "ops.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "container", "pid", "start_ns", "name", "count",
                         "first_ns", "last_ns"])
        for (proc, name), (count, first, last) in sorted(
            snapshot.stats.ops.items(), key=lambda kv: -kv[1][0]
        ):
            writer.writerow([proc.host_id, proc.container_id, proc.pid, proc.start_ns,
                             name, count, first, last])


def write_attempts_csv(report_dir: Path, snapshot: RunSnapshot) -> None:
    path = report_dir / "attempts.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "container", "pid", "start_ns", "verb", "target",
                         "errno", "count", "first_ns", "last_ns"])
        for (proc, verb, target, errno), (count, first, last) in sorted(
            snapshot.stats.attempts.items(), key=lambda kv: -kv[1][0]
        ):
            writer.writerow([proc.host_id, proc.container_id, proc.pid, proc.start_ns,
                             verb, target, errno, count, first, last])
