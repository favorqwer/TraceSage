"""会话命令活动（第 1 层末尾）：给"某次服务会话"里的候选记录附上一个数字。

**会话**＝一个进程接受一次连接。**会话命令活动**＝这次会话里由**非服务进程**（shell、命令等，
不含登录服务自己）在本次候选表里留下了多少条记录；0 表示这次会话除连接本身与自身的读写之外
没有命令活动。

**用途**：判定时告诉模型"这次会话到底有没有干过活"。攻击者的会话要拿到 shell 才能跑命令
（枚举、打包、外传），而失败的登录、扫描探测、别的用户的连接在图上就没有命令记录。
同一个服务进程可能接受很多次连接（场景 3 实测 95 次），只有其中少数几次接上了攻击链；
只看"对端地址是不是攻击者"区分不了它们，这个数字可以。

**它不参与任何收边判定、也不过滤任何候选**：只是渲染给模型看的一句事实，判断仍然由模型做。
口径与实测：真会话 28 条 / 其余 94 次全是 0 条；场景 4 的 3 次会话 7 / 10 / 76 条。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from ...contracts import triple
from ...core import graph_facts, vertices


def _subtree(pid: str, children: dict[str, set[str]]) -> set[str]:
    """这个进程加上它派生出的全部进程（子、孙……）。"""
    out, todo = {pid}, [pid]
    while todo:
        cur = todo.pop()
        for child in children.get(cur, ()):
            if child not in out:
                out.add(child)
                todo.append(child)
    return out


def session_tables(rows: Iterable[dict[str, Any]], records: list[dict[str, Any]],
                  ) -> tuple[dict[tuple[str, str, str], int], dict[str, int],
                             dict[str, str], dict[tuple[str, str, str], str]]:
    """会话四张表（本模块其它函数共用的底盘，在闭包收尾处只算一次）。

    返回（候选记录 -> 命令活动条数, 连接端点 -> 命令活动条数, 连接端点 -> 服务进程内容,
    候选记录 -> 属于哪次会话）：第一张只包含确实属于某次服务会话的候选记录，
    第二张覆盖全部被接受过的连接，第三张取接受这条连接的那个进程在事件行里的内容。
    """
    children: dict[str, set[str]] = defaultdict(set)
    on_network: dict[str, set[str]] = defaultdict(set)      # 网络端点 -> 在它上面出现过的进程
    accept_owners: dict[str, set[str]] = defaultdict(set)   # 网络端点 -> 接受这条连接的进程
    accept_content: dict[str, str] = {}                     # 网络端点 -> 接受这条连接的进程内容
    for row in rows:
        pid = str(row.get("process_id") or "")
        if graph_facts.is_derivation(str(row.get("rel") or "")) and row.get("other_process_id"):
            children[str(row["other_process_id"])].add(pid)
        if str(row.get("other_label") or "") == "Network" and pid:
            on_network[str(row.get("other") or "")].add(pid)
            if str(row.get("syscall") or "") == "accept":
                conn = str(row.get("other") or "")
                accept_owners[conn].add(pid)
                accept_content.setdefault(conn, str(row.get("owner") or ""))

    owned: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for record in records:
        key = triple(record)
        for pid in record.get("member_processes") or ():
            owned[str(pid)].add(key)

    session_pids: dict[str, set[str]] = {}
    for conn, accepters in accept_owners.items():
        member: set[str] = set()
        for pid in on_network.get(conn, set()) - accepters:
            member |= _subtree(pid, children)
        session_pids[conn] = member

    activity: dict[str, int] = {}
    for conn, pids in session_pids.items():
        produced: set[tuple[str, str, str]] = set()
        for pid in pids:
            if vertices.process_class(pid) == "resident":     # 服务进程自己不算"干活"
                continue
            produced |= owned.get(pid, set())
        activity[conn] = len(produced)

    pid_sessions: dict[str, list[str]] = defaultdict(list)
    for conn, pids in session_pids.items():
        for pid in pids:
            pid_sessions[pid].append(conn)

    out: dict[tuple[str, str, str], int] = {}
    conn_of: dict[tuple[str, str, str], str] = {}
    for record in records:
        conn = record["src"] if record.get("src_label") == "Network" else (
            record["dst"] if record.get("dst_label") == "Network" else "")
        if conn not in activity:
            found = set()
            for pid in record.get("member_processes") or ():
                sessions = pid_sessions.get(str(pid))
                if sessions and len(sessions) == 1:
                    found.add(sessions[0])
            if len(found) != 1:
                continue
            conn = next(iter(found))
        out[triple(record)] = activity[conn]
        conn_of[triple(record)] = conn
    return out, activity, accept_content, conn_of


def session_command_activity(rows: Iterable[dict[str, Any]], records: list[dict[str, Any]],
                             ) -> dict[tuple[str, str, str], int]:
    """算出每个"被服务进程接受过的连接"那一次会话的命令活动条数。

    返回 {内容三元组: 条数}，只包含属于某次服务会话的记录（连接本身的记录，以及这次会话里
    各进程拥有的记录）。不在任何服务会话里的记录不出现在结果里。
    """
    out, _by_conn, _content, _conn_of = session_tables(rows, records)
    return out


def session_overview(rows: Iterable[dict[str, Any]], records: list[dict[str, Any]],
                     tables: Any = None) -> list[dict[str, Any]]:
    """服务会话一览：每次被服务进程接受过的连接一行（判定时的上下文，不参与收边）。

    一行 = 连接端点、服务进程内容、这次会话的命令活动条数、属于这次会话的候选记录条数。
    按命令活动从多到少排（相同则按连接端点），确定性。
    `tables` 可由调用方传入（`session_tables` 的结果），避免同一个场景算两遍。
    """
    _out, by_conn, accept_content, conn_of = tables if tables else session_tables(rows, records)
    counts: dict[str, int] = defaultdict(int)
    for conn in conn_of.values():
        counts[conn] += 1
    rows_out = [{"conn": conn, "service": accept_content.get(conn, ""),
                 "activity": int(act), "candidates": counts.get(conn, 0)}
                for conn, act in by_conn.items()]
    rows_out.sort(key=lambda item: (-item["activity"], item["conn"]))
    return rows_out


def attach_session_activity(rows: Iterable[dict[str, Any]], records: list[dict[str, Any]],
                           tables: Any = None) -> int:
    """把命令活动与所属会话写进候选记录（`session_activity` / `session_conn`）；返回条数。

    `tables` 可由调用方传入（见 `session_overview`），避免重复计算。
    """
    activity, _by_conn, _content, conn_of = tables if tables else session_tables(rows, records)
    tagged = 0
    for record in records:
        key = triple(record)
        value = activity.get(key)
        if value is not None:
            record["session_activity"] = value
            record["session_conn"] = conn_of.get(key, "")
            tagged += 1
    return tagged
