"""步骤摘要（第 2 层内部）：给模型看的判断依据（命令行、时间、读写清单、系统调用分布）。"""

from __future__ import annotations

from typing import Any, Iterable

from ..l1_reach import Step, process_info

# 摘要里最多列几个文件 / 网络端点（只是给模型看的清单，不影响候选集与上限）
_MAX_LIST = {"files": 40, "networks": 20}


def _dedup(seq: Iterable[str], cap: int) -> list[str]:
    seen: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.append(item)
            if len(seen) >= cap:
                break
    return seen


def summarize(graph: Any, step: Step, *, with_event_ids: bool = False) -> dict[str, Any]:
    info = process_info(graph, step.process_id)
    syscalls: dict[str, int] = {}
    wrote: list[str] = []
    read: list[str] = []
    nets: list[str] = []
    bytes_out = 0
    bytes_in = 0
    for row in step.rows:
        syscalls[row["syscall"]] = syscalls.get(row["syscall"], 0) + 1
        rel, other = row["rel"], row["other"]
        if rel == "p2f":
            wrote.append(other)
            bytes_out += max(0, int(row.get("bytes") or 0))
        elif rel == "p2n":
            nets.append(other)
            bytes_out += max(0, int(row.get("bytes") or 0))
        elif rel == "f2p":
            read.append(other)
            bytes_in += max(0, int(row.get("bytes") or 0))
        elif rel == "n2p":
            nets.append(other)
            bytes_in += max(0, int(row.get("bytes") or 0))
    out: dict[str, Any] = {
        "step_key": step.key,
        "process_id": step.process_id,
        "owner": step.owner,
        "owner_args": info.get("args") or "",
        "owner_pid": info.get("pid") or "",
        "cwd": info.get("cwd") or "",
        "t0": step.t0,
        "t1": step.t1,
        "duration_ms": round((step.t1 - step.t0) / 1e6, 3),
        "n_edges": step.n_edges,
        "syscalls": dict(sorted(syscalls.items(), key=lambda kv: (-kv[1], kv[0]))),
        "wrote_files": _dedup(wrote, _MAX_LIST["files"]),
        "read_files": _dedup(read, _MAX_LIST["files"]),
        "networks": _dedup(nets, _MAX_LIST["networks"]),
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
    }
    if with_event_ids:
        out["event_ids"] = [int(r["event_id"]) for r in step.rows]
    return out
