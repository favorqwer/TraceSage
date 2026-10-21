"""顶点-时间索引快照（第 1 层唯一的取数方式）：把"每个顶点 -> 按时间排序的事件表"落成紧凑文件。

**为什么要它**：闭包本身的工作量与闭包大小同阶，但每次展开都要向数据库问一次"这个顶点上不晚于
某时刻的边有哪些"。把整库导成按顶点分块、块内按时间排序的定长记录文件后，闭包变成纯内存操作，
不再依赖数据库往返；索引可重建、可校验（与直查结果逐条比对，见 `tests/unit/test_snapshot.py`）。

## 文件格式（v5，目录 `tmp/provenance-navigator/l1-index/<库名>/`）

- `meta.json`：格式版本、库名、边数、最大事件编号、顶点数、入射记录数、构建时间、语句表。
  它是**唯一的"这份索引可用"标记**。
- `vertices.json`：顶点表（按编号索引）：类型、键、内容；进程还带静态属性（摘要要用），
  网络顶点带传输层协议 `protocol`（日志有记录才写）。
- `offsets.json`：顶点编号 -> [起始记录下标, 记录数]（记录定长，可直接定位）。
- `adj.bin`：定长 43 字节记录数组，按顶点编号分块，块内按（开始时刻, 事件编号）排序。

一条**入射**记录 = 一条边在一个端点上的出现（一条边有两个端点，因此写两条入射记录）：

    owner_id(4) other_id(4) rel(1) syscall_id(2) start(8) end(8) event_id(8) bytes(8)

`owner` 是按归属规则拥有这条边的进程（写文件归源进程、被读写归目标进程、派生归子进程），
`other` 是另一个端点。索引里**不存任何规则判定结果**：顶点角色与剔除都在遍历时按当前规则表现算，
所以规则表怎么改都不需要重建索引（失效判据只有边数与最大事件编号）。构建时用 64 个桶做外部排序，
内存占用与桶大小同阶（不随库规模增长）。

用法（建/重建索引，命令行在 `tools/l1_index.py`）：

    python tools/l1_index.py --database attack-3-phishing-beacon-cryptomining [--force]
"""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path
from typing import Any, Optional

from ...core import graph_facts, settings

FORMAT_VERSION = 5
BUCKET_COUNT = 64

# 定长记录：'<' 无对齐填充
RECORD = struct.Struct("<IIBHqqqq")        # 43 字节（一条入射记录）
_BUCKET = struct.Struct("<IIIBHqqqq")     # 47 字节（多一个 block_id）

# 关系类型 -> 两端标签与归属端由 `core/graph_facts.py` 唯一决定（这里不再各写一份）

_REL_CODE = {"p2f": 0, "f2p": 1, "p2n": 2, "n2p": 3, "p2p": 4}
REL_BY_CODE = {v: k for k, v in _REL_CODE.items()}   # 公开：取数来源按编号还原关系名

_VERTEX_QUERIES = {
    "Process": (
        "MATCH (p:Process) RETURN "
        "coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS key, "
        "coalesce(p.exe_path, p.exepath, p.name) AS content, "
        "p.pid AS pid, coalesce(p.name, '') AS name, "
        "coalesce(p.exe_path, p.exepath, p.name) AS exepath, "
        "coalesce(p.cmdline, p.args, '') AS args, "
        "coalesce(p.cwd, '') AS cwd"
    ),
    "File": (
        "MATCH (f:File) RETURN "
        "coalesce(f.file_id, CASE WHEN f.container_id IS NOT NULL AND f.container_id <> 'host' THEN f.container_id + '|' + f.path ELSE f.path END) AS key, "
        "f.path AS content"
    ),
    "Network": (
        "MATCH (n:Network) RETURN "
        "coalesce(n.network_id, n.endpoints) AS key, "
        "coalesce(n.endpoints, n.network_id) AS content, "
        "coalesce(n.proto, n.protocol, '') AS protocol"
    ),
}

_EDGE_QUERIES = {
    "p2f": (
        "MATCH (a:Process)-[e:ProcessToFile|p2f]->(b:File) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.file_id, CASE WHEN b.container_id IS NOT NULL AND b.container_id <> 'host' THEN b.container_id + '|' + b.path ELSE b.path END) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "f2p": (
        "MATCH (a:File)-[e:FileToProcess|f2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.file_id, CASE WHEN a.container_id IS NOT NULL AND a.container_id <> 'host' THEN a.container_id + '|' + a.path ELSE a.path END) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "p2n": (
        "MATCH (a:Process)-[e:ProcessToNetwork|p2n]->(b:Network) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.network_id, b.endpoints) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "n2p": (
        "MATCH (a:Network)-[e:NetworkToProcess|n2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.network_id, a.endpoints) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
    "p2p": (
        "MATCH (a:Process)-[e:ProcessToProcess|p2p]->(b:Process) WHERE e.event_id > $last "
        "RETURN e.event_id AS event_id, "
        "coalesce(e.start_ns, e.starttime) AS starttime, "
        "coalesce(e.end_ns, e.endtime) AS endtime, "
        "coalesce(e.syscall, e.action) AS syscall, "
        "CASE WHEN e.result > 0 THEN e.result WHEN e.bytes IS NOT NULL THEN e.bytes ELSE 0 END AS bytes, "
        "coalesce(a.process_id, coalesce(a.host_id, '') + '|' + coalesce(a.container_id, '') + '|' + toString(a.pid) + '|' + toString(a.start_ns)) AS a_key, "
        "coalesce(b.process_id, coalesce(b.host_id, '') + '|' + coalesce(b.container_id, '') + '|' + toString(b.pid) + '|' + toString(b.start_ns)) AS b_key "
        "ORDER BY e.event_id LIMIT $limit"
    ),
}

PAGE = 20000


def snapshot_dir(database: str) -> Path:
    safe = database.replace("/", "_").replace("\\", "_")
    return settings.L1_INDEX_DIR / safe


def meta_path(database: str) -> Path:
    return snapshot_dir(database) / "meta.json"


def read_meta(database: str) -> Optional[dict[str, Any]]:
    path = meta_path(database)
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - 缺失/损坏一律当作没有索引
        return None
    if int(meta.get("format", 0)) != FORMAT_VERSION:
        return None
    return meta


def db_fingerprint(graph: Any) -> dict[str, Any]:
    """索引失效判据：边数与最大事件编号（任一变化就重建）。"""
    rows = graph.run("MATCH ()-[e]->() RETURN count(e) AS edges, max(e.event_id) AS max_event_id")
    row = rows[0] if rows else {}
    return {"edges": int(row.get("edges") or 0), "max_event_id": int(row.get("max_event_id") or 0)}


def build_snapshot(graph: Any, *, log: Any = print) -> dict[str, Any]:
    """把整库导成快照。内存占用与"桶大小"同阶，不随库规模增长。

    **写入是"可中断不损坏"的**：开建第一件事是把描述文件（`meta.json`）撤掉；记录文件、顶点表、
    位置表都先写成同目录下的临时文件，再逐个原子改名替换；最后才写描述文件（提交）。因此任何一步
    中断，下一次运行只会看到"没有索引"并重建，绝不会读到半成品；中途失败（含 Ctrl-C）会清掉本次的
    临时文件（分桶文件与三份 `*.tmp`）。

    **同一个库不能同时跑两个构造**：临时文件名固定，两个构造会互相干扰（未加锁）。
    """
    database = graph.database
    out_dir = snapshot_dir(database)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    buckets = [out_dir / f"bucket-{i:02d}.tmp" for i in range(BUCKET_COUNT)]
    tmp_adj = out_dir / "adj.bin.tmp"
    tmp_vertices = out_dir / "vertices.json.tmp"
    tmp_offsets = out_dir / "offsets.json.tmp"
    commit = meta_path(database)
    commit.unlink(missing_ok=True)          # 先撤掉提交标记：之后的中断只会让下一次重跑

    try:
        # --- 1) 顶点表 ---
        vertex_ids: dict[tuple[str, str], int] = {}
        vertices: list[dict[str, Any]] = []
        for kind, cypher in _VERTEX_QUERIES.items():
            for row in graph.run(cypher):
                key = str(row.get("key") or "")
                if not key:
                    continue
                vertex_ids[(kind, key)] = len(vertices)
                item = {"kind": kind, "key": key, "content": str(row.get("content") or key)}
                for extra in ("pid", "name", "exepath", "args", "cwd", "protocol"):
                    if row.get(extra) is not None:
                        item[extra] = row[extra]
                vertices.append(item)
        log(f"[snapshot] 顶点 {len(vertices)} 个（{time.time() - t0:.1f}s）")

        # --- 2) 边 -> 桶文件（外部排序的第一趟） ---
        handles: list[Any] = []
        syscall_ids: dict[str, int] = {}
        incidences = 0
        edge_count = 0
        max_event_id = 0
        try:
            for path in buckets:
                handles.append(path.open("wb"))
            for rel, cypher in _EDGE_QUERIES.items():
                kind_a, kind_b = graph_facts.labels_of(rel)
                owner_side = "a" if graph_facts.owner_is_source(rel) else "b"
                other_side = "b" if owner_side == "a" else "a"
                last = 0
                while True:
                    rows = graph.run(cypher, {"last": last, "limit": PAGE})
                    if not rows:
                        break
                    for row in rows:
                        event_id = int(row["event_id"])
                        last = max(last, event_id)
                        max_event_id = max(max_event_id, event_id)
                        edge_count += 1
                        keys = {"a": (kind_a, str(row["a_key"] or "")),
                                "b": (kind_b, str(row["b_key"] or ""))}
                        owner_id = vertex_ids.get(keys[owner_side])
                        other_id = vertex_ids.get(keys[other_side])
                        if owner_id is None or other_id is None:
                            # 端点不在顶点表里（顶点表与边是同一个库的两次查询，理论上不该发生）：
                            # 这条边进不了索引；发生时会体现在下面的"边数 / 入射数"日志里。
                            continue
                        syscall = str(row.get("syscall") or "")
                        sid = syscall_ids.get(syscall)
                        if sid is None:
                            sid = syscall_ids[syscall] = len(syscall_ids)
                        start = int(row.get("starttime") or 0)
                        end = int(row.get("endtime") or start)
                        for block_id in (owner_id, other_id):
                            handles[block_id % BUCKET_COUNT].write(_BUCKET.pack(
                                block_id, owner_id, other_id, _REL_CODE[rel], sid, start, end,
                                event_id, int(row.get("bytes") or 0)))
                            incidences += 1
                    log(f"[snapshot] {rel} 已导 {last}（边 {edge_count} 条 / 入射 {incidences} 条）")
        finally:
            for fh in handles:
                fh.close()

        # --- 3) 逐桶排序后顺序写出（先写临时文件，成功后才替换正式文件） ---
        offsets: dict[int, list[int]] = {}
        record_index = 0
        with tmp_adj.open("wb") as out:
            for path in buckets:
                raw = path.read_bytes()
                records = [_BUCKET.unpack_from(raw, i) for i in range(0, len(raw), _BUCKET.size)]
                records.sort(key=lambda r: (r[0], r[5], r[7]))      # (block, start, event_id)
                for rec in records:
                    block_id, owner_id, other_id, rel_code, sid, start, end, event_id, nbytes = rec
                    if offsets.get(block_id) is None:
                        offsets[block_id] = [record_index, 0]
                    offsets[block_id][1] += 1
                    out.write(RECORD.pack(owner_id, other_id, rel_code, sid, start, end, event_id,
                                          nbytes))
                    record_index += 1
                path.unlink(missing_ok=True)

        tmp_vertices.write_text(json.dumps(vertices, ensure_ascii=False), encoding="utf-8")
        tmp_offsets.write_text(json.dumps({str(k): v for k, v in offsets.items()}), encoding="utf-8")
        syscalls = [""] * len(syscall_ids)
        for name, sid in syscall_ids.items():
            syscalls[sid] = name
        meta = {"format": FORMAT_VERSION, "database": database, "edges": edge_count,
                "max_event_id": max_event_id, "vertices": len(vertices), "incidences": incidences,
                "syscalls": syscalls, "built_at": int(time.time()),
                "build_seconds": round(time.time() - t0, 1)}

        # --- 4) 提交：三份数据文件原子替换，最后写描述文件 ---
        os.replace(tmp_adj, out_dir / "adj.bin")
        os.replace(tmp_vertices, out_dir / "vertices.json")
        os.replace(tmp_offsets, out_dir / "offsets.json")
        commit.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    except BaseException:
        for path in (*buckets, tmp_adj, tmp_vertices, tmp_offsets):
            path.unlink(missing_ok=True)
        raise

    log(f"[snapshot] 完成：边 {edge_count} 条 / 入射 {incidences} 条 / "
        f"{(out_dir / 'adj.bin').stat().st_size / 1048576:.1f} MB / {meta['build_seconds']}s -> {out_dir}")
    return meta


def ensure_snapshot(graph: Any, *, log: Any = print) -> dict[str, Any]:
    """确保索引可用：缺失、损坏、过期（库的边总数/最大事件编号变了）就重建。

    索引里不存规则判定结果，所以规则表怎么改都不用重建（失效判据只有库本身）。

    索引建不出来（磁盘、权限等）就报错停下——**不做隐式降级**：慢与快两种取数方式
    混在一起会让"这次到底读了什么"变得不可确认。
    """
    meta = read_meta(graph.database)
    if meta is not None:
        fingerprint = db_fingerprint(graph)
        if ((meta.get("edges"), meta.get("max_event_id"))
                == (fingerprint["edges"], fingerprint["max_event_id"])):
            return meta
    return build_snapshot(graph, log=log)


