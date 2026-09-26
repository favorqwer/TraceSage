"""顶点-时间索引快照（第 1 层唯一的取数方式）：把"每个顶点 -> 按时间排序的事件表"落成紧凑文件。

**为什么要它**：闭包本身的工作量与闭包大小同阶，但每次展开都要向数据库问一次"这个顶点上不晚于
某时刻的边有哪些"。把整库导成按顶点分块、块内按时间排序的定长记录文件后，闭包变成纯内存操作，
不再依赖数据库往返；索引可重建、可校验（与直查结果逐条比对，见 `tests/unit/test_snapshot.py`）。

## 文件格式（v3，目录 `tmp/provenance-agent/l1-index/<库名>/`）

- `meta.json`：格式版本、库名、边数、最大事件编号、顶点数、入射记录数、规则表校核值、
  构建时间、语句表。它是**唯一的"这份索引可用"标记**。
- `vertices.json`：顶点表（按编号索引）：类型、键、内容；进程还带静态属性（摘要要用），
  文件顶点若属共享 / 虚拟通道则带 `shared`（值是该通道的类别名，见 `core/edge_rules.py`）。
- `offsets.json`：顶点编号 -> [起始记录下标, 记录数]（记录定长，可直接定位）。
- `adj.bin`：定长 45 字节记录数组，按顶点编号分块，块内按（开始时刻, 事件编号）排序。

一条**入射**记录 = 一条边在一个端点上的出现（一条边有两个端点，因此写两条入射记录）：

    owner_id(4) other_id(4) rel(1) syscall_id(2) start(8) end(8) event_id(8) bytes(8) rule_code(1)

`owner` 是按归属规则拥有这条边的进程（写文件归源进程、被读写归目标进程、派生归子进程），
`other` 是另一个端点。`rule_code` 是这条边的结构性伪边判定结果（`edge_rules.RULE_CODE_OF`）：
它只由这条边的静态内容（源内容、操作名、目标内容、源标签）决定，所以在建索引时算一次写进记录，
遍历时只看这个整数、不再重算。规则表一改，上面的校核值就对不上，索引会被当作过期重建，
因此不会拿旧规则算出来的标记去遍历。构建时用 64 个桶做外部排序，内存占用与桶大小同阶
（不随库规模增长）。

用法：

    python -m pagent.layers.l1_reach.snapshot --database tracesage-3-ssh-spray
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Optional

from ...core import edge_rules, settings
from .closure import rule_code_of

FORMAT_VERSION = 3
BUCKET_COUNT = 64

# 定长记录：'<' 无对齐填充；最后一字节是建索引时算好的规则编码（见文件头格式说明）
_FINAL = struct.Struct("<IIBHqqqqxB")     # 45 字节
_BUCKET = struct.Struct("<IIIBHqqqqxB")   # 49 字节（多一个 block_id）

# 关系类型 -> (拥有者所在的端点, 另一端所在的端点)
_SIDES = {"p2f": ("a", "b"), "f2p": ("b", "a"), "p2n": ("a", "b"), "n2p": ("b", "a"),
          "p2p": ("b", "a")}

_KIND_BY_REL_SIDE = {"p2f": ("Process", "File"), "f2p": ("File", "Process"),
                     "p2n": ("Process", "Network"), "n2p": ("Network", "Process"),
                     "p2p": ("Process", "Process")}

_REL_CODE = {"p2f": 0, "f2p": 1, "p2n": 2, "n2p": 3, "p2p": 4}
_REL_BY_CODE = {v: k for k, v in _REL_CODE.items()}

_VERTEX_QUERIES = {
    "Process": ("MATCH (p:Process) RETURN p.process_id AS key, coalesce(p.exepath, p.name) AS content, "
                "p.pid AS pid, p.name AS name, p.exepath AS exepath, p.args AS args, p.cwd AS cwd"),
    "File": "MATCH (f:File) RETURN f.file_id AS key, f.path AS content",
    "Network": "MATCH (n:Network) RETURN n.network_id AS key, n.network_id AS content",
}

_EDGE_QUERIES = {
    "p2f": ("MATCH (a:Process)-[e:p2f]->(b:File) WHERE e.event_id > $last "
            "RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime, "
            "e.syscall AS syscall, e.bytes AS bytes, a.process_id AS a_key, b.file_id AS b_key "
            "ORDER BY e.event_id LIMIT $limit"),
    "f2p": ("MATCH (a:File)-[e:f2p]->(b:Process) WHERE e.event_id > $last "
            "RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime, "
            "e.syscall AS syscall, e.bytes AS bytes, a.file_id AS a_key, b.process_id AS b_key "
            "ORDER BY e.event_id LIMIT $limit"),
    "p2n": ("MATCH (a:Process)-[e:p2n]->(b:Network) WHERE e.event_id > $last "
            "RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime, "
            "e.syscall AS syscall, e.bytes AS bytes, a.process_id AS a_key, b.network_id AS b_key "
            "ORDER BY e.event_id LIMIT $limit"),
    "n2p": ("MATCH (a:Network)-[e:n2p]->(b:Process) WHERE e.event_id > $last "
            "RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime, "
            "e.syscall AS syscall, e.bytes AS bytes, a.network_id AS a_key, b.process_id AS b_key "
            "ORDER BY e.event_id LIMIT $limit"),
    "p2p": ("MATCH (a:Process)-[e:p2p]->(b:Process) WHERE e.event_id > $last "
            "RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime, "
            "e.syscall AS syscall, e.bytes AS bytes, a.process_id AS a_key, b.process_id AS b_key "
            "ORDER BY e.event_id LIMIT $limit"),
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
                for extra in ("pid", "name", "exepath", "args", "cwd"):
                    if row.get(extra) is not None:
                        item[extra] = row[extra]
                if kind == "File":
                    # 共享 / 虚拟通道的标记在这里算一次（遍历时只看这个字段，不再重算路径前缀）
                    shared = edge_rules.shared_channel_label(key)
                    if shared:
                        item["shared"] = shared
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
                owner_side, other_side = _SIDES[rel]
                kind_a, kind_b = _KIND_BY_REL_SIDE[rel]
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
                        # 规则判定只看这条边的静态内容：在这里算一次写进两条入射记录，
                        # 遍历时不再重算（内容取值口径与 `sources.SnapshotReader._event` 一致）
                        other_vertex = vertices[other_id]
                        other_kind = other_vertex["kind"]
                        rule_code = rule_code_of(
                            rel, syscall, vertices[owner_id]["content"],
                            other_vertex["key"] if other_kind in ("File", "Network")
                            else other_vertex["content"], other_kind)
                        for block_id in (owner_id, other_id):
                            handles[block_id % BUCKET_COUNT].write(_BUCKET.pack(
                                block_id, owner_id, other_id, _REL_CODE[rel], sid, start, end,
                                event_id, int(row.get("bytes") or 0), rule_code))
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
                    block_id, owner_id, other_id, rel_code, sid, start, end, event_id, nbytes, rule = rec
                    if offsets.get(block_id) is None:
                        offsets[block_id] = [record_index, 0]
                    offsets[block_id][1] += 1
                    out.write(_FINAL.pack(owner_id, other_id, rel_code, sid, start, end, event_id,
                                          nbytes, rule))
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
                "rules": edge_rules.rules_fingerprint(),
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
    """确保索引可用：缺失、损坏、过期（库的边总数/最大事件编号变了）或规则表换过就重建。

    规则表也在过期判据里：记录里的规则编码是建索引时按当时的规则表算的，规则一改就得重建，
    否则会拿旧标记当判定结果。

    索引建不出来（磁盘、权限等）就报错停下——**不做隐式降级**：慢与快两种取数方式
    混在一起会让"这次到底读了什么"变得不可确认。
    """
    meta = read_meta(graph.database)
    if meta is not None:
        fingerprint = db_fingerprint(graph)
        same_db = ((meta.get("edges"), meta.get("max_event_id"))
                   == (fingerprint["edges"], fingerprint["max_event_id"]))
        if same_db and meta.get("rules") == edge_rules.rules_fingerprint():
            return meta
    return build_snapshot(graph, log=log)


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="构建第 1 层的顶点-时间索引快照")
    parser.add_argument("--database", required=True, help="Neo4j 库名（见 config/scenarios.json）")
    parser.add_argument("--force", action="store_true", help="已存在也重建")
    args = parser.parse_args(argv)

    settings.load_dotenv()
    settings.ensure_work_dirs()
    settings.ensure_index_dir()
    sys.path.insert(0, str(settings.AGENT_DIR))
    from ...core.db import ReadOnlyGraph

    if not args.force:
        meta = read_meta(args.database)
        if meta is not None:
            print(f"索引已存在：{meta_path(args.database)}（--force 可重建）")
            return 0
    graph = ReadOnlyGraph(args.database, run_id=f"snapshot-{os.getpid()}")
    try:
        build_snapshot(graph, log=print)
    finally:
        graph.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
