"""数据库直查来源（参照实现，只给单测用）：不进生产包。

正式流程只有一种取数方式——读本地顶点-时间索引（`closure/snapshot.py` 的
`SnapshotReader`）。这里保留直查版本，只为了让单测拿它和索引来源逐条对拍：索引构建错了要能发现。
"""

from __future__ import annotations

from typing import Any, Optional

import closure.policy as _rules_table
from closure.policy import object_ruling
from closure.storage import process_info_query
from closure.traversal import Event

# 表里全部带 not_delivery 后果的事件判据的操作名（与索引来源同一份判据）
_NOT_DELIVERY = sorted({
    str(syscall)
    for rule in _rules_table.load().of("event") if "not_delivery" in rule.effects
    for syscall in rule.match.get("syscalls") or ()
})

# 数据库直查（参考实现）
# --------------------------------------------------------------------------- #

# 进程展开的四段，合并成一次查询（"父进程那一侧也收"是机制，不是开关）：
#   1. 进程在源侧：它写出的边（p2f / p2n）
#   2. 进程在目标侧：它读入的边（f2p / n2p）
#   3. 进程是子进程：派生它的那条边（"我被谁启动"）
#   4. 进程是父进程：它派生出去的全部派生边（"我启动过谁"——同主体派生的其它子进程也算上游）
_EXPAND_PROCESS_OWN_EDGES = """
UNWIND $items AS it
MATCH (p:Process {process_id: it.key})
WITH it, p, coalesce(p.exepath, p.name) AS owner
MATCH (p)-[e:p2f|p2n]->(x)
WHERE e.starttime > it.lo AND e.starttime <= it.hi
RETURN p.process_id AS pid, owner, e.event_id AS event_id, e.starttime AS starttime,
       e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes, type(e) AS rel,
       coalesce(x.path, x.network_id) AS other, labels(x)[0] AS other_label, '' AS other_process_id
UNION ALL
UNWIND $items AS it
MATCH (p:Process {process_id: it.key})
WITH it, p, coalesce(p.exepath, p.name) AS owner
MATCH (x)-[e:f2p|n2p]->(p)
WHERE e.starttime > it.lo AND e.starttime <= it.hi
RETURN p.process_id AS pid, owner, e.event_id AS event_id, e.starttime AS starttime,
       e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes, type(e) AS rel,
       coalesce(x.path, x.network_id) AS other, labels(x)[0] AS other_label, '' AS other_process_id
"""
_EXPAND_PROCESS_AS_CHILD = """
UNION ALL
UNWIND $items AS it
MATCH (p:Process {process_id: it.key})
WITH it, p, coalesce(p.exepath, p.name) AS owner
MATCH (q:Process)-[e:p2p]->(p)
WHERE e.starttime > it.lo AND e.starttime <= it.hi
RETURN p.process_id AS pid, owner, e.event_id AS event_id, e.starttime AS starttime,
       e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes, type(e) AS rel,
       coalesce(q.exepath, q.name) AS other, 'Process' AS other_label, q.process_id AS other_process_id
"""
_EXPAND_PROCESS_AS_PARENT = """
UNION ALL
UNWIND $items AS it
MATCH (p:Process {process_id: it.key})
MATCH (p)-[e:p2p]->(c:Process)
WHERE e.starttime > it.lo AND e.starttime <= it.hi
RETURN c.process_id AS pid, coalesce(c.exepath, c.name) AS owner, e.event_id AS event_id,
       e.starttime AS starttime, e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes,
       type(e) AS rel, coalesce(p.exepath, p.name) AS other, 'Process' AS other_label,
       p.process_id AS other_process_id
"""
_EXPAND_PROCESS = (_EXPAND_PROCESS_OWN_EDGES + _EXPAND_PROCESS_AS_CHILD
                   + _EXPAND_PROCESS_AS_PARENT)

_EXPAND_OBJECT = {
    "File": """
UNWIND $items AS it
MATCH (p:Process)-[e:p2f]->(f:File {file_id: it.key})
WHERE e.starttime > it.lo AND e.starttime <= it.hi AND NOT e.syscall IN $not_delivery
RETURN p.process_id AS pid, coalesce(p.exepath, p.name) AS owner, e.event_id AS event_id,
       e.starttime AS starttime, e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes,
       type(e) AS rel, f.path AS other, 'File' AS other_label, '' AS other_process_id
""",
    "Network": """
UNWIND $items AS it
MATCH (p:Process)-[e:p2n]->(n:Network {network_id: it.key})
WHERE e.starttime > it.lo AND e.starttime <= it.hi AND NOT e.syscall IN $not_delivery
RETURN p.process_id AS pid, coalesce(p.exepath, p.name) AS owner, e.event_id AS event_id,
       e.starttime AS starttime, e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes,
       type(e) AS rel, n.network_id AS other, 'Network' AS other_label, '' AS other_process_id
""",
}

# 进程读写过的对象端点已随「子进程把关」一起删除（那个判定不再存在）。

def _event(row: dict[str, Any]) -> Event:
    start = int(row.get("starttime") or 0)
    rel = str(row["rel"])
    syscall = str(row.get("syscall") or "")
    owner = str(row.get("owner") or "")
    other = str(row.get("other") or "")
    other_label = str(row.get("other_label") or "Process")
    return Event(event_id=int(row["event_id"]), rel=rel, syscall=syscall,
                 bytes=int(row.get("bytes") or 0), start=start,
                 end=int(row.get("endtime") or start), pid=str(row.get("pid") or ""),
                 owner=owner, other=other, other_label=other_label,
                 other_process_id=str(row.get("other_process_id") or ""))


class DbSource:
    """数据库直查来源：**只用于单测与一次性对照**，正式流程不走这条路。"""

    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self.database = graph.database
        self.queries = 0
        self.rows = 0
        self.nondelivery_not_expanded: dict[str, int] = {}   # 被跳过的非交付通道顶点展开次数（不是边数）
        self._ppid_map: Optional[dict[tuple[str, int], list[tuple[int, str]]]] = None
        self._ppid_of: dict[str, int] = {}
        self._process_info: dict[str, dict[str, Any]] = {}

    def _load_ppid(self) -> None:
        """记录到的父子关系（与索引来源同一口径）：(容器, pid) → [(出生时刻, 进程键)]。"""
        if self._ppid_map is not None:
            return
        mapping: dict[tuple[str, int], list[tuple[int, str]]] = {}
        rows = self.graph.run(
            "MATCH (p:Process) RETURN p.host_id AS host, p.container_id AS ctr, p.pid AS pid, "
            "p.start_ns AS st, coalesce(p.ppid, 0) AS ppid"
        )
        self.queries += 1
        self.rows += len(rows)
        for row in rows:
            container = str(row.get("ctr") or "host")
            key = f"{row.get('host') or ''}|{container}|{row.get('pid')}|{row.get('st') or 0}"
            mapping.setdefault((container, int(row.get("pid") or 0)), []).append(
                (int(row.get("st") or 0), key))
            if row.get("ppid"):
                self._ppid_of[key] = int(row["ppid"])
        self._ppid_map = mapping

    def parent_of_process(self, key: str) -> Optional[str]:
        self._load_ppid()
        ppid = self._ppid_of.get(str(key))
        if not ppid:
            return None
        parts = str(key).split("|")
        if len(parts) < 4:
            return None
        container, start = (parts[1] or "host"), int(parts[3])
        candidates = [(st, pkey) for st, pkey in (self._ppid_map or {}).get((container, ppid), ())
                      if st <= start]
        if not candidates:
            return None
        parent = max(candidates)[1]
        return parent if parent != key else None

    def birth_of_process(self, key: str) -> int:
        parts = str(key).split("|")
        return int(parts[3]) if len(parts) >= 4 else 0

    def _run(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        out = self.graph.run(cypher, params)
        self.queries += 1
        self.rows += len(out)
        return out

    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        if not items:
            return []
        params = {"items": [{"key": k, "lo": lo, "hi": hi} for k, lo, hi in items]}
        rows = self._run(_EXPAND_PROCESS, params)
        if seen is None:
            return [_event(row) for row in rows]
        return [_event(row) for row in rows
                if (int(row["event_id"]), str(row["rel"])) not in seen]

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        if not items:
            return []
        if kind == "File":
            kept: list[tuple[str, int, int]] = []
            for key, lo, hi in items:
                ruling = object_ruling(key)
                if "no_expand" in ruling.effects:
                    # 非交付通道：只收边、不展开（与索引来源同一判据）
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = \
                        self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
                kept.append((key, lo, hi))
            items = kept
            if not items:
                return []
        params = {"items": [{"key": k, "lo": lo, "hi": hi} for k, lo, hi in items],
                  "not_delivery": _NOT_DELIVERY}
        rows = self._run(_EXPAND_OBJECT[kind], params)
        if seen is None:
            return [_event(row) for row in rows]
        return [_event(row) for row in rows
                if (int(row["event_id"]), str(row["rel"])) not in seen]

    def process_info(self, process_id: str) -> dict[str, Any]:
        """进程静态属性（直查版本，只给单测用；按进程缓存一次）。"""
        cached = self._process_info.get(process_id)
        if cached is not None:
            return cached
        rows = self._run(process_info_query(many=False), {"pid": process_id})
        info = rows[0] if rows else {}
        self._process_info[process_id] = info
        return info

    def close(self) -> None:
        return None

    def stats(self) -> dict[str, Any]:
        return {"source": "db", "queries": self.queries, "rows": self.rows,
                "nondelivery_not_expanded": dict(sorted(self.nondelivery_not_expanded.items()))}


# --------------------------------------------------------------------------- #
