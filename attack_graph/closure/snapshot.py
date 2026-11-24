"""顶点-时间索引：构建、失效判定、读取。

索引是正式流程唯一的取数方式：把整个库按顶点分块排好，闭包按 (lo, hi] 顺序读块，运行期零数据库查询。
本文件只负责索引的 IO 与顶点表；二进制布局和 Cypher 文本在 `closure.storage`，判据在 `closure.policy`。
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Optional

import settings as cfg
if str(cfg.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(cfg.REPO_ROOT))
from tsg.format import (
    EFFECT_NAMES as TSG_EFFECT_NAMES,
    FLAG_EFFECT_MASK as TSG_FLAG_EFFECT_MASK,
    FLAG_EFFECT_SHIFT as TSG_FLAG_EFFECT_SHIFT,
    FLAG_END_OVERFLOW as TSG_FLAG_END_OVERFLOW,
    FLAG_HAS_END as TSG_FLAG_HAS_END,
    FLAG_HAS_RESULT as TSG_FLAG_HAS_RESULT,
    FLAG_HAS_START as TSG_FLAG_HAS_START,
    FLAG_IS_OUT as TSG_FLAG_IS_OUT,
    FLAG_LEGACY_BYTES as TSG_FLAG_LEGACY_BYTES,
    KIND_BY_CODE as TSG_KIND_BY_CODE,
    PRODUCER_REL_CODES,
    REL_BY_CODE as TSG_REL_BY_CODE,
    TSGReader,
)
from domain.edge import labels_of, owner_is_source
from domain.keys import split_process_key
from closure.policy import event_ruling, object_ruling
from closure.storage import (
    BUCKET_COUNT,
    BUCKET_RECORD,
    CHUNK_RECORDS,
    CONSUMER_CODES,
    EDGE_QUERIES,
    FLAG_HAS_END,
    FLAG_HAS_RESULT,
    FLAG_HAS_START,
    FORMAT_VERSION,
    PAGE,
    PRODUCER_CODES,
    RECORD,
    REL_BY_CODE,
    REL_CODES,
    VERTEX_QUERIES,
    effect_code,
    effect_name,
)
from closure.traversal import Event


def snapshot_dir(database: str) -> Path:
    safe = database.replace("/", "_").replace("\\", "_")
    return cfg.L1_INDEX_DIR / safe


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
        for kind, cypher in VERTEX_QUERIES.items():
            for row in graph.run(cypher):
                key = str(row.get("key") or "")
                if not key:
                    continue
                vertex_ids[(kind, key)] = len(vertices)
                item = {"kind": kind, "key": key, "content": str(row.get("content") or key)}
                for extra in (
                    "host_id", "container_id", "pid", "name", "exepath", "args",
                    "protocol", "ppid", "uid", "euid", "file_type",
                    "container_privileged", "container_host_root_rw",
                ):
                    if row.get(extra) is not None:
                        item[extra] = row[extra]
                vertices.append(item)
        log(f"[snapshot] 顶点 {len(vertices)} 个（{time.time() - t0:.1f}s）")

        # --- 2) 边 -> 桶文件（外部排序的第一趟） ---
        handles: list[Any] = []
        syscall_ids: dict[str, int] = {}
        action_ids: dict[str, int] = {}
        incidences = 0
        edge_count = 0
        max_event_id = 0
        try:
            for path in buckets:
                handles.append(path.open("wb"))
            for rel, cypher in EDGE_QUERIES.items():
                kind_a, kind_b = labels_of(rel)
                owner_side = "a" if owner_is_source(rel) else "b"
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
                        action = str(row.get("action") or "")
                        aid = action_ids.get(action)
                        if aid is None:
                            aid = action_ids[action] = len(action_ids)
                        raw_start = row.get("starttime")
                        raw_end = row.get("endtime")
                        raw_res = row.get("res")
                        flags = 0
                        if raw_start is not None:
                            flags |= FLAG_HAS_START
                            start = int(raw_start)
                        else:
                            start = 0
                        if raw_end is not None:
                            flags |= FLAG_HAS_END
                            end = int(raw_end)
                        else:
                            end = start
                        if raw_res is not None:
                            flags |= FLAG_HAS_RESULT
                            res_val = int(raw_res)
                        else:
                            res_val = 0
                        code = effect_code(raw_res)
                        for block_id in (owner_id, other_id):
                            handles[block_id % BUCKET_COUNT].write(BUCKET_RECORD.pack(
                                block_id, owner_id, other_id, REL_CODES[rel], sid, aid,
                                start, end, event_id, int(row.get("bytes") or 0), res_val,
                                code, flags))
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
                records = [BUCKET_RECORD.unpack_from(raw, i)
                           for i in range(0, len(raw), BUCKET_RECORD.size)]
                records.sort(key=lambda r: (r[0], r[6], r[8]))      # (block, start, event_id)
                for rec in records:
                    (block_id, owner_id, other_id, rel_code, sid, aid, start, end,
                     event_id, nbytes, res_val, code, flags) = rec
                    if offsets.get(block_id) is None:
                        offsets[block_id] = [record_index, 0]
                    offsets[block_id][1] += 1
                    out.write(RECORD.pack(owner_id, other_id, rel_code, sid, aid, start, end,
                                          event_id, nbytes, res_val, code, flags))
                    record_index += 1
                path.unlink(missing_ok=True)

        tmp_vertices.write_text(json.dumps(vertices, ensure_ascii=False), encoding="utf-8")
        tmp_offsets.write_text(json.dumps({str(k): v for k, v in offsets.items()}), encoding="utf-8")
        syscalls = [""] * len(syscall_ids)
        for name, sid in syscall_ids.items():
            syscalls[sid] = name
        actions = [""] * len(action_ids)
        for name, aid in action_ids.items():
            actions[aid] = name
        meta = {"format": FORMAT_VERSION, "database": database, "edges": edge_count,
                "max_event_id": max_event_id, "vertices": len(vertices), "incidences": incidences,
                "syscalls": syscalls, "actions": actions, "built_at": int(time.time()),
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


class SnapshotReader:
    """读顶点-时间索引：零数据库查询。

    取数时执行两条判据（都走 `closure.policy`）：对象类的 `no_expand`（非交付通道不展开）
    与事件类的 `not_delivery`（连接建立类不算交付）。
    """

    def __init__(self, database: str) -> None:
        meta = read_meta(database)
        if meta is None:
            raise RuntimeError(f"索引不存在或格式不符：{meta_path(database)}")
        self.database = database
        self.meta = meta
        self.dir = snapshot_dir(database)
        self.vertices: list[dict[str, Any]] = json.loads(
            (self.dir / "vertices.json").read_text(encoding="utf-8"))
        self._id_of: dict[tuple[str, str], int] = {}
        for vid, item in enumerate(self.vertices):
            self._id_of[(str(item["kind"]), str(item["key"]))] = vid
        # 记录到的父子关系（进程顶点上的 ppid）：闭包除了沿边回溯，也按它上溯父进程。
        # 只在本容器内解析；容器进程的 ppid 属于宿主命名空间，本版不处理。
        self._ppid_of: dict[str, int] = {}
        self._by_pid: dict[tuple[str, int], list[tuple[int, str]]] = {}
        for item in self.vertices:
            if item["kind"] != "Process":
                continue
            parsed = split_process_key(item["key"])
            if not parsed:
                continue
            _host, container, pid, start = parsed
            self._by_pid.setdefault((container, pid), []).append((start, str(item["key"])))
            ppid = item.get("ppid")
            if ppid:
                self._ppid_of[str(item["key"])] = int(ppid)
        raw = json.loads((self.dir / "offsets.json").read_text(encoding="utf-8"))
        self._offsets: dict[int, tuple[int, int]] = {
            int(k): (int(v[0]), int(v[1])) for k, v in raw.items()}
        self._syscalls: list[str] = list(meta.get("syscalls") or [])
        self._actions: list[str] = list(meta.get("actions") or [])
        self._process_info: dict[str, dict[str, Any]] = {}
        self.queries = 0
        self.rows = 0
        self.skipped = 0            # 因已收进闭包而跳过的记录数（含在 rows 里，只影响快慢）
        self.nondelivery_not_expanded: dict[str, int] = {}   # 被跳过的非交付通道顶点展开次数（不是边数）
        self._adj = (self.dir / "adj.bin").open("rb")

    # --- 内部 ---
    def _block(self, vid: int) -> tuple[int, int]:
        return self._offsets.get(vid, (0, 0))

    def _record(self, index: int) -> tuple:
        self._adj.seek(index * RECORD.size)
        return RECORD.unpack(self._adj.read(RECORD.size))

    def _iter_block(self, vid: int, lo: int, hi: int):
        """块内取 (lo, hi] 的记录：先二分找起点，再按块读，不整块解码。"""
        off, count = self._block(vid)
        if count <= 0:
            return
        # 二分：第一条第 start > lo 的记录
        left, right = 0, count
        while left < right:
            mid = (left + right) // 2
            if self._record(off + mid)[5] <= lo:
                left = mid + 1
            else:
                right = mid
        index = off + left
        remaining = count - left
        while remaining > 0:
            take = min(CHUNK_RECORDS, remaining)
            self._adj.seek(index * RECORD.size)
            raw = self._adj.read(take * RECORD.size)
            for rec in struct.iter_unpack(RECORD.format, raw):
                if rec[5] > hi:
                    return
                yield rec
            index += take
            remaining -= take

    def _event(self, rec: tuple) -> Event:
        (owner_id, other_id, rel_code, sid, aid, start, end,
         event_id, nbytes, res_val, code, flags) = rec
        owner_vertex = self.vertices[owner_id]
        other_vertex = self.vertices[other_id]
        rel = REL_BY_CODE[rel_code]
        other_kind = other_vertex["kind"]
        other = other_vertex["key"] if other_kind in ("File", "Network") else other_vertex["content"]
        if owner_is_source(rel):
            src_vertex, dst_vertex = owner_vertex, other_vertex
        else:
            src_vertex, dst_vertex = other_vertex, owner_vertex
        return Event(
            event_id=event_id,
            rel=rel,
            syscall=self._syscalls[sid] if sid < len(self._syscalls) else "",
            bytes=nbytes,
            start=start,
            end=end,
            effect=effect_name(code),
            pid=owner_vertex["key"],
            owner=owner_vertex["content"],
            other=other,
            other_label=other_kind,
            other_process_id=other_vertex["key"] if other_kind == "Process" else "",
            action=self._actions[aid] if aid < len(self._actions) else "",
            result=res_val if (flags & FLAG_HAS_RESULT) else None,
            has_start=bool(flags & FLAG_HAS_START),
            has_end=bool(flags & FLAG_HAS_END),
            src_host=str(src_vertex.get("host_id") or ""),
            dst_host=str(dst_vertex.get("host_id") or ""),
            src_kind=src_vertex.get("file_type"),
            dst_kind=dst_vertex.get("file_type"),
        )

    # --- 记录到的父子关系（ppid）---
    def parent_of_process(self, key: str) -> Optional[str]:
        """按进程节点上记录的 ppid 找父进程：同容器、pid 相等、出生不晚于子进程，取最近的一个。"""
        ppid = self._ppid_of.get(str(key))
        if not ppid:
            return None
        parsed = split_process_key(key)
        if not parsed:
            return None
        _host, container, _pid, start = parsed
        candidates = [(st, pkey) for st, pkey in self._by_pid.get((container, ppid), ()) if st <= start]
        if not candidates:
            return None
        parent = max(candidates)[1]
        return parent if parent != key else None

    def birth_of_process(self, key: str) -> int:
        parsed = split_process_key(key)
        return parsed[3] if parsed else 0

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
                # 父进程侧是"它启动过谁"，两条都要（同一主体子进程算上游，见 `run_closure`）
                self.rows += 1
                rel = REL_BY_CODE[rec[2]]
                if seen is not None and (rec[7], rel) in seen:
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
            if kind == "File":
                ruling = object_ruling(key)
                if "no_expand" in ruling.effects:
                    # 非交付通道：只收边、不展开（判据现算，索引里不存标记）
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = \
                        self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
            for rec in self._iter_block(vid, lo, hi):
                rel_code = rec[2]
                if rel_code not in PRODUCER_CODES:  # p2f / p2n
                    continue                # 只回溯写入侧：读不会把内容送回顶点
                rel = REL_BY_CODE[rel_code]
                syscall = self._syscalls[rec[3]] if rec[3] < len(self._syscalls) else ""
                if "not_delivery" in event_ruling(rel, syscall, rec[8]).effects:
                    continue                # 连接建立类操作不传递内容
                self.rows += 1
                if seen is not None and (rec[7], rel) in seen:
                    self.skipped += 1
                    continue
                out.append(self._event(rec))
        return out

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """某个文件 / 网络顶点在 (lo, hi] 里**被读走**的事件（前向补链用：写下的东西后来被谁读走）。

        `lo` 一般是该对象被写入的最早时刻、`hi` 是锚点时刻。只取读取侧（对象 -> 进程）。
        这里不套用对象侧的交付判据：那些判据（非交付通道、不算交付的操作）管的是「往回找写入者」，
        与「往前找读者」是两件事。
        """
        out: list[Event] = []
        vid = self._id_of.get((kind, key))
        if vid is None:
            return out
        for rec in self._iter_block(vid, lo, hi):
            if rec[2] not in CONSUMER_CODES:
                continue
            self.rows += 1
            out.append(self._event(rec))
        return out

    def process_info(self, process_id: str) -> dict[str, Any]:
        """进程静态属性（索引顶点表里已有的字段；同一进程只查一次）。"""
        cached = self._process_info.get(process_id)
        if cached is not None:
            return cached
        vid = self._id_of.get(("Process", str(process_id)))
        if vid is None:
            info: dict[str, Any] = {}
        else:
            vertex = self.vertices[vid]
            info = {"process_id": process_id, "pid": vertex.get("pid"),
                    "name": vertex.get("name"), "exepath": vertex.get("exepath"),
                    "args": vertex.get("args")}
        self._process_info[process_id] = info
        return info

    def vertex_attr(self, kind: str, key: str) -> dict[str, Any]:
        """按 (顶点类型, 顶点键) 返回索引顶点表中的静态属性副本（不存在时返回最小键信息）。"""
        vid = self._id_of.get((str(kind), str(key)))
        if vid is None:
            return {"kind": str(kind), "key": str(key)}
        return dict(self.vertices[vid])

    def network_protocols(self) -> dict[str, str]:
        """网络端点标识 -> 传输层协议（索引顶点表里有的才收录；空值不写）。"""
        out: dict[str, str] = {}
        for vertex in self.vertices:
            if vertex.get("kind") != "Network":
                continue
            protocol = str(vertex.get("protocol") or "").strip()
            if protocol:
                out[str(vertex.get("key") or "")] = protocol
        return out

    def close(self) -> None:
        if self._adj is not None:
            self._adj.close()
            self._adj = None

    def stats(self) -> dict[str, Any]:
        return {"source": "snapshot", "queries": 0, "rows": self.rows,
                "skipped_already_included": self.skipped,
                "nondelivery_not_expanded": dict(sorted(self.nondelivery_not_expanded.items())),
                "index_dir": str(self.dir), "index_edges": self.meta.get("edges")}


class TSGSource:
    """基于单文件 .tsg 的零拷贝 GraphSource 实现（零数据库连接，热路径直接解包构造 Event）。"""

    def __init__(self, path: str | Path, *, database: str = "") -> None:
        self.path = Path(path)
        self._reader = TSGReader(self.path)
        self.meta = self._reader.meta
        self.database = database or str(self.meta.get("database") or "")
        self.scenario = str(self.meta.get("scenario") or self.path.stem)
        self._process_info: dict[str, dict[str, Any]] = {}
        # 热路径顶点轻量缓存：vid -> (kind, key, content, host_id, file_type)
        self._vfast: dict[int, tuple[str, str, str, str, Optional[str]]] = {}
        self._syscalls = self._reader._syscalls
        self._actions = self._reader._actions
        self._hosts = self._reader._hosts
        self._file_types = self._reader._file_types
        self.queries = 0
        self.rows = 0
        self.skipped = 0
        self.nondelivery_not_expanded: dict[str, int] = {}

    def _vinfo(self, vid: int) -> tuple[str, str, str, str, Optional[str]]:
        cached = self._vfast.get(vid)
        if cached is not None:
            return cached
        reader = self._reader
        vp = reader.vertex_props(vid)
        _, _, _, _, kc, ftc, hc, _, _ = reader._vdir_entry(vid)
        kind = TSG_KIND_BY_CODE[kc]
        key = str(vp["key"])
        content = str(vp.get("content") or key)
        host_id = self._hosts[hc] if hc < len(self._hosts) else ""
        ft = (self._file_types[ftc] or None) if ftc < len(self._file_types) else None
        val = (kind, key, content, host_id, ft)
        self._vfast[vid] = val
        return val

    def _event_from_rec(self, block_vid: int, rec: tuple) -> Event:
        peer_vid, event_id, start_ns, res_val, dur_ns, extra_off, sid, aid, rel_code, flags = rec
        if flags & TSG_FLAG_IS_OUT:
            src_vid, dst_vid = block_vid, peer_vid
        else:
            src_vid, dst_vid = peer_vid, block_vid
        src_kind, src_key, src_content, src_host, src_ft = self._vinfo(src_vid)
        dst_kind, dst_key, dst_content, dst_host, dst_ft = self._vinfo(dst_vid)
        rel = TSG_REL_BY_CODE[rel_code]
        if rel_code in PRODUCER_REL_CODES:
            pid = src_key
            owner = src_content
            other_label = dst_kind
            other = dst_key
            other_process_id = ""
        else:
            pid = dst_key
            owner = dst_content
            other_label = src_kind
            if src_kind == "Process":
                other = src_content
                other_process_id = src_key
            else:
                other = src_key
                other_process_id = ""
        has_start = bool(flags & TSG_FLAG_HAS_START)
        has_end = bool(flags & TSG_FLAG_HAS_END)
        has_result = bool(flags & TSG_FLAG_HAS_RESULT)
        if has_end:
            if flags & TSG_FLAG_END_OVERFLOW:
                end_val = int(self._reader.read_edge_extras(extra_off)["end_ns"])
            else:
                end_val = start_ns + dur_ns
        else:
            end_val = start_ns if has_start else 0
        if has_result:
            result = res_val
            nbytes = res_val if res_val > 0 else 0
        else:
            result = None
            nbytes = res_val if (flags & TSG_FLAG_LEGACY_BYTES) else 0
        eff_code = (flags & TSG_FLAG_EFFECT_MASK) >> TSG_FLAG_EFFECT_SHIFT
        effect = TSG_EFFECT_NAMES[eff_code] if eff_code < 3 else ""
        syscalls = self._syscalls
        actions = self._actions
        return Event(
            event_id=event_id,
            rel=rel,
            syscall=syscalls[sid] if sid < len(syscalls) else "",
            bytes=nbytes,
            start=start_ns if has_start else 0,
            end=end_val,
            effect=effect,
            pid=pid,
            owner=owner,
            other=other,
            other_label=other_label,
            other_process_id=other_process_id,
            action=actions[aid] if aid < len(actions) else "",
            result=result,
            has_start=has_start,
            has_end=has_end,
            src_host=src_host,
            dst_host=dst_host,
            src_kind=src_ft,
            dst_kind=dst_ft,
        )

    def find_poi(self, *, kind: str, rel: str, syscall: str, key: str) -> list[dict[str, Any]]:
        return self._reader.find_poi(kind=kind, rel=rel, syscall=syscall, key=key)

    def parent_of_process(self, key: str) -> Optional[str]:
        return self._reader.parent_of_process(key)

    def birth_of_process(self, key: str) -> int:
        parsed = split_process_key(key)
        return parsed[3] if parsed else 0

    def expand_process(self, items: list[tuple[str, int, int]],
                       seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        reader = self._reader
        rel_by_code = TSG_REL_BY_CODE
        make_event = self._event_from_rec
        for key, lo, hi in items:
            vid = reader.find_vertex_id("Process", key)
            if vid is None:
                continue
            # v2 Process 单块有序存储：一次 C 层 iter_unpack 遍历全部入/出边，零双指针归并、零排序
            for rec in reader.iter_block_raw(vid, lo, hi, outgoing=False):
                self.rows += 1
                rel = rel_by_code[rec[8]]
                if seen is not None and (rec[1], rel) in seen:
                    self.skipped += 1
                    continue
                out.append(make_event(vid, rec))
        return out

    def expand_object(self, items: list[tuple[str, int, int]], kind: str,
                      seen: Optional[Any] = None) -> list[Event]:
        out: list[Event] = []
        reader = self._reader
        rel_by_code = TSG_REL_BY_CODE
        syscalls = self._syscalls
        make_event = self._event_from_rec
        for key, lo, hi in items:
            vid = reader.find_vertex_id(kind, key)
            if vid is None:
                continue
            if kind == "File":
                ruling = object_ruling(key)
                if "no_expand" in ruling.effects:
                    label = ruling.label or "未命名条目"
                    self.nondelivery_not_expanded[label] = \
                        self.nondelivery_not_expanded.get(label, 0) + 1
                    continue
            # 对象顶点保持读写双块：in 块只含写/发侧（p2f / p2n），零无效读边扫描
            for rec in reader.iter_block_raw(vid, lo, hi, outgoing=False):
                if rec[8] not in PRODUCER_REL_CODES:
                    continue
                rel = rel_by_code[rec[8]]
                sc = syscalls[rec[6]] if rec[6] < len(syscalls) else ""
                flags = rec[9]
                res_val = rec[3]
                nbytes = res_val if ((flags & TSG_FLAG_HAS_RESULT) and res_val > 0) or (flags & TSG_FLAG_LEGACY_BYTES) else 0
                if "not_delivery" in event_ruling(rel, sc, nbytes).effects:
                    continue
                self.rows += 1
                if seen is not None and (rec[1], rel) in seen:
                    self.skipped += 1
                    continue
                out.append(make_event(vid, rec))
        return out

    def reads_after(self, key: str, kind: str, lo: int, hi: int) -> list[Event]:
        """对象顶点的 out 块只含读取/接收侧（f2p / n2p），零无效写边扫描。"""
        out: list[Event] = []
        vid = self._reader.find_vertex_id(kind, key)
        if vid is None:
            return out
        make_event = self._event_from_rec
        for rec in self._reader.iter_block_raw(vid, lo, hi, outgoing=True):
            self.rows += 1
            out.append(make_event(vid, rec))
        return out

    def process_info(self, process_id: str) -> dict[str, Any]:
        cached = self._process_info.get(process_id)
        if cached is not None:
            return cached
        vid = self._reader.find_vertex_id("Process", str(process_id))
        if vid is None:
            info: dict[str, Any] = {}
        else:
            vp = self._reader.vertex_props(vid)
            info = {
                "process_id": process_id,
                "pid": vp.get("pid"),
                "name": vp.get("name"),
                "exepath": vp.get("exepath"),
                "args": vp.get("args"),
            }
        self._process_info[process_id] = info
        return info

    def vertex_attr(self, kind: str, key: str) -> dict[str, Any]:
        vid = self._reader.find_vertex_id(str(kind), str(key))
        if vid is None:
            return {"kind": str(kind), "key": str(key)}
        return dict(self._reader.vertex_props(vid))

    def network_protocols(self) -> dict[str, str]:
        return self._reader.network_protocols()

    def close(self) -> None:
        self._reader.close()

    def stats(self) -> dict[str, Any]:
        return {
            "source": "tsg",
            "queries": 0,
            "rows": self.rows,
            "skipped_already_included": self.skipped,
            "nondelivery_not_expanded": dict(sorted(self.nondelivery_not_expanded.items())),
            "tsg_file": str(self.path),
            "index_edges": self._reader.edge_count,
        }


def open_tsg_source(scenario_or_path: str | Path, *, database: str = "") -> TSGSource:
    """按场景名或显式路径打开单文件 .tsg 索引（完全离线，不连接 Neo4j）。"""
    p = Path(scenario_or_path)
    if p.suffix != ".tsg" and not p.is_file():
        p = cfg.graph_path(str(scenario_or_path))
    return TSGSource(p, database=database)


def open_source(graph: Any, *, scenario: str = "", log: Any = print) -> Any:
    """优先打开正式单文件 .tsg 索引；仅在未传入场景且传入旧图句柄时兼容旧版目录索引。"""
    if scenario:
        tsg_file = cfg.graph_path(scenario)
        if tsg_file.is_file():
            return TSGSource(tsg_file, database=getattr(graph, "database", ""))
    if graph is None:
        raise FileNotFoundError(f"未找到场景 {scenario!r} 的 .tsg 单文件索引：{cfg.graph_path(scenario)}")
    ensure_snapshot(graph, log=log)
    return SnapshotReader(graph.database)
