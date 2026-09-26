"""取边来源（第 1 层内部）。

正式流程只有一种取数方式：读顶点-时间索引快照（`SnapshotReader`，零数据库查询）。
`DbSource`（把同类型顶点的展开合并成一次批量查询）不再被正式流程使用，留作**参考实现**：
单测（`tests/unit/test_snapshot.py`）拿它对同一批顶点、同一批门限逐条比对，
需要整库级的一次性对照时也用它（两个类必须给出**完全相同**的事件）。
"""

from __future__ import annotations

import json
import struct
from typing import Any, Optional

from . import snapshot as snap
from .closure import Event, rule_code_of
from .steps import cache_process_info, has_process_info

# --------------------------------------------------------------------------- #
# 数据库直查
# --------------------------------------------------------------------------- #

_EXPAND_PROCESS_HEADS = """
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

# 旧实现的"同一脚本的其它子进程"：把本进程派生出去的每个子进程也按本进程的门限收进来。
# 这是**超集**口径（子进程的活动只要在父进程门限之前就全收），默认关闭，只用于消融对照。
_EXPAND_CHILDREN = """
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

# 连接建立类操作（connect / bind）不传递内容：只把两端接起来，不往顶点里写数据，
# 因此不算“往这个顶点交付了内容”。实测与改动记录见 CHANGELOG。
_SETUP_SYSCALLS = ["connect", "bind"]

_EXPAND_OBJECT = {
    "File": """
UNWIND $items AS it
MATCH (p:Process)-[e:p2f]->(f:File {file_id: it.key})
WHERE e.starttime > it.lo AND e.starttime <= it.hi AND NOT e.syscall IN $setup
RETURN p.process_id AS pid, coalesce(p.exepath, p.name) AS owner, e.event_id AS event_id,
       e.starttime AS starttime, e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes,
       type(e) AS rel, f.path AS other, 'File' AS other_label, '' AS other_process_id
""",
    "Network": """
UNWIND $items AS it
MATCH (p:Process)-[e:p2n]->(n:Network {network_id: it.key})
WHERE e.starttime > it.lo AND e.starttime <= it.hi AND NOT e.syscall IN $setup
RETURN p.process_id AS pid, coalesce(p.exepath, p.name) AS owner, e.event_id AS event_id,
       e.starttime AS starttime, e.endtime AS endtime, e.syscall AS syscall, e.bytes AS bytes,
       type(e) AS rel, n.network_id AS other, 'Network' AS other_label, '' AS other_process_id
""",
}

_PROCESS_INFO_MANY = """
UNWIND $pids AS pid
MATCH (p:Process {process_id: pid})
RETURN p.process_id AS process_id, p.pid AS pid, p.name AS name, p.exepath AS exepath,
       p.args AS args, p.cwd AS cwd
"""


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
                 other_process_id=str(row.get("other_process_id") or ""),
                 # 直查来源自己算规则编码（参考实现不舍预先算好的索引）：与索引快照逐条可比
                 rule_code=rule_code_of(rel, syscall, owner, other, other_label))


class DbSource:
    """数据库直查来源：**只用于单测与一次性对照**，正式流程不走这条路。

    把同类型顶点的展开合并成一次批量查询（每轮 3~4 次查询），而不是"每个顶点一次查询"。
    """

    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self.database = graph.database
        self.queries = 0
        self.rows = 0

    def _run(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        out = self.graph.run(cypher, params)
        self.queries += 1
        self.rows += len(out)
        return out

    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        if not items:
            return []
        cypher = _EXPAND_PROCESS_HEADS + _EXPAND_CHILDREN
        params = {"items": [{"key": k, "lo": lo, "hi": hi} for k, lo, hi in items]}
        rows = self._run(cypher, params)
        if seen is None:
            return [_event(row) for row in rows]
        return [_event(row) for row in rows if int(row["event_id"]) not in seen]

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        if not items:
            return []
        cypher = _EXPAND_OBJECT[kind]
        params = {"items": [{"key": k, "lo": lo, "hi": hi} for k, lo, hi in items],
                  "setup": _SETUP_SYSCALLS}
        rows = self._run(cypher, params)
        if seen is None:
            return [_event(row) for row in rows]
        return [_event(row) for row in rows if int(row["event_id"]) not in seen]

    def process_info_many(self, pids: list[str]) -> None:
        missing = [pid for pid in pids if not has_process_info(self.database, pid)]
        for chunk in (missing[i:i + 5000] for i in range(0, len(missing), 5000)):
            if not chunk:
                continue
            for row in self._run(_PROCESS_INFO_MANY, {"pids": chunk}):
                cache_process_info(self.database, str(row["process_id"]), row)

    def close(self) -> None:
        return None

    def stats(self) -> dict[str, Any]:
        return {"source": "db", "queries": self.queries, "rows": self.rows}


# --------------------------------------------------------------------------- #
# 索引快照来源
# --------------------------------------------------------------------------- #

_CHUNK_RECORDS = 4096


class SnapshotReader:
    """读顶点-时间索引：零数据库查询。展开语义与 `DbSource` 逐条一致。"""

    def __init__(self, database: str) -> None:
        meta = snap.read_meta(database)
        if meta is None:
            raise RuntimeError(f"索引不存在或格式不符：{snap.meta_path(database)}")
        self.database = database
        self.meta = meta
        self.dir = snap.snapshot_dir(database)
        self._adj: Optional[Any] = None
        self.vertices: list[dict[str, Any]] = json.loads(
            (self.dir / "vertices.json").read_text(encoding="utf-8"))
        self._id_of: dict[tuple[str, str], int] = {}
        for vid, item in enumerate(self.vertices):
            self._id_of[(str(item["kind"]), str(item["key"]))] = vid
        raw = json.loads((self.dir / "offsets.json").read_text(encoding="utf-8"))
        self._offsets: dict[int, tuple[int, int]] = {
            int(k): (int(v[0]), int(v[1])) for k, v in raw.items()}
        self._syscalls: list[str] = list(meta.get("syscalls") or [])
        self.queries = 0
        self.rows = 0
        self.skipped = 0            # 因已收进闭包而跳过的记录数（含在 rows 里，只影响快慢）
        self._adj = (self.dir / "adj.bin").open("rb")

    # --- 内部 ---
    def _block(self, vid: int) -> tuple[int, int]:
        return self._offsets.get(vid, (0, 0))

    def _record(self, index: int) -> tuple:
        self._adj.seek(index * snap._FINAL.size)
        return snap._FINAL.unpack(self._adj.read(snap._FINAL.size))

    def _iter_block(self, vid: int, lo: int, hi: int):
        """块内取 (lo, hi] 的记录：先二分找起点，再按块读，不整块解码。"""
        off, count = self._block(vid)
        if count <= 0:
            return
        # 二分：第一条第 start > lo 的记录
        left, right = 0, count
        while left < right:
            mid = (left + right) // 2
            if self._record(off + mid)[4] <= lo:
                left = mid + 1
            else:
                right = mid
        index = off + left
        remaining = count - left
        while remaining > 0:
            take = min(_CHUNK_RECORDS, remaining)
            self._adj.seek(index * snap._FINAL.size)
            raw = self._adj.read(take * snap._FINAL.size)
            for rec in struct.iter_unpack(snap._FINAL.format, raw):
                if rec[4] > hi:
                    return
                yield rec
            index += take
            remaining -= take

    def _syscall_of(self, rec: tuple) -> str:
        sid = int(rec[3])
        return str(self._syscalls[sid]) if sid < len(self._syscalls) else ""

    def _event(self, rec: tuple) -> Event:
        owner_id, other_id, rel_code, sid, start, end, event_id, nbytes, rule_code = rec
        owner_vertex = self.vertices[owner_id]
        other_vertex = self.vertices[other_id]
        other_kind = other_vertex["kind"]
        other = other_vertex["key"] if other_kind in ("File", "Network") else other_vertex["content"]
        return Event(event_id=event_id, rel=snap._REL_BY_CODE[rel_code],
                     syscall=self._syscalls[sid] if sid < len(self._syscalls) else "",
                     bytes=nbytes, start=start, end=end,
                     pid=owner_vertex["key"], owner=owner_vertex["content"], other=other,
                     other_label=other_kind,
                     other_process_id=other_vertex["key"] if other_kind == "Process" else "",
                     rule_code=rule_code)

    # --- GraphSource ---
    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get(("Process", key))
            if vid is None:
                continue
            for rec in self._iter_block(vid, lo, hi):
                # 派生边在两端顶点的块里各有一条入射记录：子进程侧是"它自己被谁启动"，
                # 父进程侧是"它启动过谁"，两条都要（同一主体子进程算上游，见 `closure.py`）
                self.rows += 1
                if seen is not None and rec[6] in seen:
                    self.skipped += 1          # 已经收进闭包：不重造内部表示
                    continue
                out.append(self._event(rec))
        return out

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        for key, lo, hi in items:
            vid = self._id_of.get((kind, key))
            if vid is None:
                continue
            for rec in self._iter_block(vid, lo, hi):
                rel_code = rec[2]
                if rel_code not in (0, 2):  # p2f / p2n
                    continue                # 只回溯写入侧：读不会把内容送回顶点
                if self._syscall_of(rec) in _SETUP_SYSCALLS:
                    continue
                self.rows += 1
                if seen is not None and rec[6] in seen:
                    self.skipped += 1
                    continue
                out.append(self._event(rec))
        return out

    def process_info_many(self, pids: list[str]) -> None:
        for pid in pids:
            vertex = self.vertices[self._id_of[("Process", pid)]] if ("Process", pid) in self._id_of else None
            if vertex is None:
                continue
            cache_process_info(self.database, pid, {
                "process_id": pid, "pid": vertex.get("pid"), "name": vertex.get("name"),
                "exepath": vertex.get("exepath"), "args": vertex.get("args"), "cwd": vertex.get("cwd"),
            })

    def close(self) -> None:
        if self._adj is not None:
            self._adj.close()
            self._adj = None

    def stats(self) -> dict[str, Any]:
        return {"source": "snapshot", "queries": 0, "rows": self.rows,
                "skipped_already_included": self.skipped,
                "index_dir": str(self.dir), "index_edges": self.meta.get("edges")}


def open_source(graph: Any, *, log: Any = print) -> SnapshotReader:
    """打开取边来源：确保索引存在且不过期（否则重建），然后读它。没有别的取数方式。"""
    snap.ensure_snapshot(graph, log=log)
    return SnapshotReader(graph.database)
