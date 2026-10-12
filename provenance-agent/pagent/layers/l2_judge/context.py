"""进程上下文（判定层内部）：把每个进程的判定依据整理成模型能读的一份身份摘要。

分组单位就是**边的归属进程**（进程标识 = 编号 + 程序名）：进程写文件 / 网络归源进程，
文件 / 网络被进程读写归目标进程，进程派生归子进程。**没有"步骤 / 实例"这一层**——一个进程
一张身份行，边行直接引用进程标识；"同进程前后活动"与"同一对象上的接触者"是渲染时
（`batching.py`）从候选边里现算的，不在这里做。

身份摘要的内容：命令行、工作目录、来源（父进程、执行新程序还是派生、时刻）、活动时间范围与边数。
摘要的消费者只有判定时的渲染（本层 `batching.py`）。**本模块必须在闭包刚跑完、事件行还在手上时调用**（行在展开结束就释放）。
"""

from __future__ import annotations

from typing import Any

from ...core import graph_facts
from ..l1_reach import process_info


def _origins(by_process: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """进程标识 -> 来源（执行新程序 / 派生 / 无记录），取时间最早的那条派生边。

    派生边的另一端就是父进程：记下父进程标识与内容、派生条数，供渲染使用（不再查库）。
    """
    out: dict[str, dict[str, Any]] = {}
    for pid, rows in by_process.items():
        exec_t = spawn_t = None
        exec_p = spawn_p = exec_pc = spawn_pc = ""
        n = 0
        for row in rows:
            if not graph_facts.is_derivation(str(row.get("rel") or "")):
                continue
            t = int(row.get("starttime") or 0)
            other = str(row.get("other_process_id") or "")
            content = str(row.get("other") or "")
            n += 1
            if str(row.get("syscall") or "") == "execve":
                if exec_t is None or t < exec_t:
                    exec_t, exec_p, exec_pc = t, other, content
            elif spawn_t is None or t < spawn_t:
                spawn_t, spawn_p, spawn_pc = t, other, content
        if exec_t is not None:
            out[pid] = {"kind": "exec", "parent": exec_p, "parent_content": exec_pc, "t": exec_t, "n": n}
        elif spawn_t is not None:
            out[pid] = {"kind": "spawn", "parent": spawn_p, "parent_content": spawn_pc, "t": spawn_t, "n": n}
        else:
            out[pid] = {"kind": "none", "parent": "", "parent_content": "", "t": 0, "n": 0}
    return out


def summarize_process(graph: Any, process_id: str, owner: str,
                      rows: list[dict[str, Any]]) -> dict[str, Any]:
    """一个进程的身份摘要（命令行、工作目录、时间范围、边数）。"""
    info = process_info(graph, process_id)
    return {
        "process_id": process_id,
        "owner": owner,
        "owner_args": info.get("args") or "",
        "owner_pid": info.get("pid") or "",
        "cwd": info.get("cwd") or "",
        "t0": min(int(r["starttime"]) for r in rows),
        "t1": max(int(r.get("endtime") or r["starttime"]) for r in rows),
        "n_edges": len(rows),
    }


def build_process_context(graph: Any, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """从闭包产出的事件行生成每个进程的身份摘要（按进程标识去重）。

    `rows` 已经按（开始时刻, 事件编号）排好序（闭包引擎排的），分组是顺序遍历，
    因此每个进程的边清单天然有序，这里不再逐个进程重排一遍。
    """
    by_process: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_process.setdefault(str(row["process_id"]), []).append(row)

    origins = _origins(by_process)
    metas: dict[str, dict[str, Any]] = {}
    for pid, process_rows in by_process.items():
        meta = summarize_process(graph, pid, str(process_rows[0]["owner"]), process_rows)
        meta["origin"] = origins.get(pid) or {"kind": "none", "parent": "", "parent_content": "",
                                              "t": 0, "n": 0}
        metas[pid] = meta
    return metas
