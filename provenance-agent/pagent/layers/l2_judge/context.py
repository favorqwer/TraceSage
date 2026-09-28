"""进程上下文（判定层内部）：把每个进程的判定依据整理成模型能读的一份身份摘要。

分组单位就是**边的归属进程**（进程标识 = 编号 + 程序名）：进程写文件 / 网络归源进程，
文件 / 网络被进程读写归目标进程，进程派生归子进程。**没有"步骤 / 实例"这一层**——一个进程
一张身份行，边行直接引用进程标识；"同进程前后活动"与"同一对象上的接触者"是渲染时
（`batching.py`）从候选边里现算的，不在这里做。

身份摘要的内容：命令行、工作目录、来源（父进程、执行新程序还是派生、时刻）、活动时间范围与边数。
摘要有两个消费者：判定时的渲染（本层 `batching.py`）与报告的相位推导（`l3_express/phases.py`
读摘要里的命令行去认关键词）。**本模块必须在闭包刚跑完、事件行还在手上时调用**（行在展开结束就释放）。
"""

from __future__ import annotations

from typing import Any

from ...core import settings
from ..l1_reach import process_info


def _origins(by_process: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """进程标识 -> 来源（执行新程序 / 派生 / 无记录），取时间最早的那条派生边。

    派生边的另一端就是父进程：记下父进程标识与内容、派生条数，供渲染与命令表使用（不再查库）。
    """
    out: dict[str, dict[str, Any]] = {}
    for pid, rows in by_process.items():
        exec_t = spawn_t = None
        exec_p = spawn_p = exec_pc = spawn_pc = ""
        n = 0
        for row in rows:
            if str(row.get("rel") or "") != "p2p":
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


def _resolve_parent(graph: Any, origins: dict[str, dict[str, Any]], pid: str, *, limit: int,
                    seen: set[str]) -> tuple[str, list[str], str, bool]:
    """沿派生链往上找命令行，返回（值, 找过的祖先链, 结束原因, 是否遇到过歧义）。

    `pid` 是直接父进程；返回的链从它上面一代开始、到“命令行取自哪一代”为止（找到值的那一代在链末尾）。
    只往上找、不猜：父进程没有派生边、或它的命令行也是空，就停在那里并记原因。
    """
    chain: list[str] = []
    cur = pid
    ambiguous = False
    for _ in range(limit):
        info = process_info(graph, cur) or {}
        args = str(info.get("args") or "")
        origin = origins.get(cur) or {}
        kind = str(origin.get("kind") or "none")
        parent = str(origin.get("parent") or "")
        if int(origin.get("n") or 0) > 1:
            ambiguous = True
        if args:
            return args, chain, "graph", ambiguous
        if kind == "spawn" and parent and parent not in seen:
            seen.add(parent)
            chain.append(parent)
            cur = parent
            continue
        return "", chain, ("chain_broken" if kind == "spawn" and parent else "no_parent"), ambiguous
    return "", chain, "too_deep", ambiguous


def attach_commands(graph: Any, by_process: dict[str, list[dict[str, Any]]],
                    metas: dict[str, dict[str, Any]], *, limit: int = 5) -> dict[str, int]:
    """给每个进程算命令行与来源（开关打开时才调；纯代码、确定性）。

    取值优先级：图顶点非空就用图顶点；空则只在“这个进程是派生出来的、未执行新程序”时
    沿派生链往上找父进程的命令行；其余情况保留空值并写明原因。结果写进 meta 的 command 字段
    （值 / 来源 / 父链 / 原因），供渲染与日志使用；不改 meta 里的 owner_args（报告的相位推导仍读它）。
    """
    origins = _origins(by_process)
    counts = {"graph": 0, "inherited": 0, "none_exec": 0, "none_no_derivation": 0,
              "none_chain_broken": 0, "none_no_parent": 0, "none_too_deep": 0,
              "ambiguous": 0}
    for pid, meta in metas.items():
        value = str(meta.get("owner_args") or "")
        if value:
            meta["command"] = {"line": value, "source": "graph", "via": [], "reason": ""}
            counts["graph"] += 1
            continue
        origin = origins.get(pid) or {}
        kind = str(origin.get("kind") or "none")
        parent = str(origin.get("parent") or "")
        if kind == "spawn" and parent:
            found, chain, reason, ambiguous = _resolve_parent(
                graph, origins, parent, limit=limit, seen={pid})
            if found:
                meta["command"] = {"line": found, "source": "inherited",
                                   "via": [parent] + list(chain), "reason": ""}
                counts["inherited"] += 1
            else:
                meta["command"] = {"line": "", "source": "none",
                                   "via": chain or [parent], "reason": reason}
                key = f"none_{reason}"
                counts[key] = counts.get(key, 0) + 1
            if ambiguous:
                counts["ambiguous"] += 1
            continue
        where = "none_exec" if kind == "exec" else "none_no_derivation"
        meta["command"] = {"line": "", "source": "none", "via": [], "reason": where}
        counts[where] += 1
    return counts


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
    # 命令表：图顶点为空时沿派生链往上找（默认关；关时不产生任何额外查询）
    if settings.command_table_enabled():
        attach_commands(graph, by_process, metas, limit=settings.command_inherit_depth())
    return metas
