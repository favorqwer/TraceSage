"""离线交互式单文件 .tsg 图查询工具（替代人工审计与标注期的临时 Neo4j 查询）。

示例：
  python -m tsg.query info graphs/1_Web_Exploit_Ransomware.tsg
  python -m tsg.query find-vertex graphs/1_Web_Exploit_Ransomware.tsg --kind Process --match php-fpm
  python -m tsg.query event graphs/1_Web_Exploit_Ransomware.tsg 7080705
  python -m tsg.query edges graphs/1_Web_Exploit_Ransomware.tsg --kind File --key /srv/data/README_RESTORE.txt
  python -m tsg.query neighbors graphs/1_Web_Exploit_Ransomware.tsg 7080705 --hops 2 --direction backward
  python -m tsg.query export-sqlite graphs/1_Web_Exploit_Ransomware.tsg tmp/s1.sqlite
"""
from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional

from .format import FLAG_IS_OUT, TSGEdge, TSGReader


def _edge_to_dict(ev: TSGEdge) -> dict[str, Any]:
    out: dict[str, Any] = {
        "event_id": ev.event_id,
        "rel": ev.rel_full,
        "action": ev.action,
        "syscall": ev.syscall,
        "start_ns": ev.start_ns,
        "end_ns": ev.end_ns,
        "result": ev.result,
        "effect": ev.effect,
        "src": f"{ev.src_kind}:{ev.src_key}",
        "dst": f"{ev.dst_kind}:{ev.dst_key}",
    }
    if ev.payload_b64 is not None:
        out["payload_b64"] = ev.payload_b64
    if ev.to_path is not None:
        out["to_path"] = ev.to_path
    if ev.mode is not None:
        out["mode"] = ev.mode
    return out


def search_vertices(
    reader: TSGReader,
    *,
    kind: Optional[str] = None,
    pattern: str = "",
    pid: Optional[int] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    rx = re.compile(pattern, re.IGNORECASE) if pattern else None
    out: list[dict[str, Any]] = []
    for vid, vp in reader.iter_vertices(kind):
        if pid is not None and vp.get("pid") != pid:
            continue
        if rx is not None:
            haystack = " ".join(
                str(vp.get(k) or "") for k in ("key", "content", "exepath", "args", "name")
            )
            if not rx.search(haystack):
                continue
        out.append({"vid": vid, **vp})
        if len(out) >= limit:
            break
    return out


def list_vertex_edges(
    reader: TSGReader,
    *,
    kind: str,
    key: str,
    direction: str = "both",
    lo: int = -1,
    hi: int = (1 << 63) - 1,
    with_extras: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    vid = reader.find_vertex_id(kind, key)
    if vid is None:
        raise KeyError(f"未找到顶点：{kind}:{key}")
    raw: list[tuple] = []
    if kind == "Process":
        for rec in reader.iter_block_raw(vid, lo, hi, outgoing=False):
            is_out = bool(rec[9] & FLAG_IS_OUT)
            if direction == "in" and is_out:
                continue
            if direction == "out" and not is_out:
                continue
            raw.append(rec)
            if len(raw) >= limit:
                break
        return [_edge_to_dict(reader.decode_edge(vid, r, with_extras=with_extras)) for r in raw]
    if direction in ("in", "both"):
        raw.extend(reader.iter_block_raw(vid, lo, hi, outgoing=False))
    if direction in ("out", "both"):
        raw.extend(reader.iter_block_raw(vid, lo, hi, outgoing=True))
    raw.sort(key=lambda r: (r[2], r[1]))
    return [_edge_to_dict(reader.decode_edge(vid, r, with_extras=with_extras)) for r in raw[:limit]]


def expand_neighbors(
    reader: TSGReader,
    event_id: int,
    *,
    hops: int = 1,
    direction: str = "backward",
    limit: int = 200,
) -> list[dict[str, Any]]:
    seeds = reader.find_edges_by_event_id(event_id, with_extras=True)
    if not seeds:
        return []
    seen_edges: set[tuple[int, str, str]] = set()
    results: list[dict[str, Any]] = []
    queue: deque[tuple[int, int, int]] = deque()

    for ev in seeds:
        ekey = (ev.event_id, ev.rel_full, ev.action)
        if ekey not in seen_edges:
            seen_edges.add(ekey)
            results.append({"hop": 0, **_edge_to_dict(ev)})
        if direction == "backward":
            t = ev.end_ns if ev.end_ns is not None else (1 << 63) - 1
            queue.append((ev.src_vid, t, 1))
        else:
            t = ev.start_ns if ev.start_ns is not None else -1
            queue.append((ev.dst_vid, t, 1))

    visited_vids: set[int] = set()
    while queue and len(results) < limit:
        vid, t_bound, depth = queue.popleft()
        if depth > hops or vid in visited_vids:
            continue
        visited_vids.add(vid)
        kcode = reader._vdir_entry(vid)[4]
        if kcode == 0:  # Process 单块
            lo_q, hi_q = (-1, t_bound) if direction == "backward" else (t_bound - 1, (1 << 63) - 1)
            want_out = (direction == "forward")
            recs = [r for r in reader.iter_block_raw(vid, lo_q, hi_q, outgoing=False) if bool(r[9] & FLAG_IS_OUT) == want_out]
        elif direction == "backward":
            recs = list(reader.iter_block_raw(vid, -1, t_bound, outgoing=False))
        else:
            recs = list(reader.iter_block_raw(vid, t_bound - 1, (1 << 63) - 1, outgoing=True))
        for rec in recs:
            ev = reader.decode_edge(vid, rec, with_extras=False)
            ekey = (ev.event_id, ev.rel_full, ev.action)
            if ekey in seen_edges:
                continue
            seen_edges.add(ekey)
            results.append({"hop": depth, **_edge_to_dict(ev)})
            if len(results) >= limit:
                break
            if depth < hops:
                if direction == "backward":
                    nt = ev.end_ns if ev.end_ns is not None else t_bound
                    queue.append((ev.src_vid, nt, depth + 1))
                else:
                    nt = ev.start_ns if ev.start_ns is not None else t_bound
                    queue.append((ev.dst_vid, nt, depth + 1))
    return results


def export_sqlite(reader: TSGReader, sqlite_path: str | Path) -> dict[str, int]:
    """按需将单文件 .tsg 流式导出到嵌入式只读 SQLite，便于临时 SQL 多条件审计。"""
    dst = Path(sqlite_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    conn = sqlite3.connect(str(dst))
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE vertices (
                vid INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                content TEXT,
                host_id TEXT,
                container_id TEXT,
                pid INTEGER,
                ppid INTEGER,
                exepath TEXT,
                args TEXT,
                file_type TEXT,
                protocol TEXT,
                props_json TEXT
            );
            CREATE TABLE edges (
                event_id INTEGER NOT NULL,
                rel TEXT NOT NULL,
                action TEXT,
                syscall TEXT,
                start_ns INTEGER,
                end_ns INTEGER,
                result INTEGER,
                effect TEXT,
                src_vid INTEGER NOT NULL,
                dst_vid INTEGER NOT NULL,
                payload_b64 TEXT,
                to_path TEXT,
                mode TEXT
            );
            """
        )
        v_batch = []
        v_count = 0
        for vid, vp in reader.iter_vertices():
            v_batch.append((
                vid, vp["kind"], vp["key"], vp.get("content"), vp.get("host_id"),
                vp.get("container_id"), vp.get("pid"), vp.get("ppid"),
                vp.get("exepath"), vp.get("args"), vp.get("file_type"),
                vp.get("protocol") or vp.get("proto"),
                json.dumps(vp, ensure_ascii=False),
            ))
            if len(v_batch) >= 5000:
                cur.executemany("INSERT INTO vertices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", v_batch)
                v_count += len(v_batch)
                v_batch.clear()
        if v_batch:
            cur.executemany("INSERT INTO vertices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", v_batch)
            v_count += len(v_batch)

        e_batch = []
        e_count = 0
        for vid in range(reader.vertex_count):
            kcode = reader._vdir_entry(vid)[4]
            it = reader.iter_block_raw(vid, -1, (1 << 63) - 1, outgoing=(kcode != 0))
            for rec in it:
                if not (rec[9] & FLAG_IS_OUT):
                    continue
                ev = reader.decode_edge(vid, rec, with_extras=True)
                e_batch.append((
                    ev.event_id, ev.rel_full, ev.action, ev.syscall,
                    ev.start_ns, ev.end_ns, ev.result, ev.effect,
                    ev.src_vid, ev.dst_vid, ev.payload_b64, ev.to_path, ev.mode,
                ))
                if len(e_batch) >= 10000:
                    cur.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", e_batch)
                    e_count += len(e_batch)
                    e_batch.clear()
        if e_batch:
            cur.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", e_batch)
            e_count += len(e_batch)

        cur.executescript(
            """
            CREATE INDEX idx_vertices_kind_key ON vertices(kind, key);
            CREATE INDEX idx_edges_eid ON edges(event_id);
            CREATE INDEX idx_edges_src ON edges(src_vid, start_ns);
            CREATE INDEX idx_edges_dst ON edges(dst_vid, start_ns);
            """
        )
        conn.commit()
        return {"vertices": v_count, "edges": e_count}
    finally:
        conn.close()


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tsg.query", description="离线 .tsg 溯源图查询工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="查看 .tsg 元数据摘要")
    p_info.add_argument("tsg_file")

    p_fv = sub.add_parser("find-vertex", help="按类型、进程号或正则搜索顶点")
    p_fv.add_argument("tsg_file")
    p_fv.add_argument("--kind", choices=["Process", "File", "Network"], default=None)
    p_fv.add_argument("--match", default="")
    p_fv.add_argument("--pid", type=int, default=None)
    p_fv.add_argument("--limit", type=int, default=50)

    p_ev = sub.add_parser("event", help="按 event_id 精确查询边及完整附加属性")
    p_ev.add_argument("tsg_file")
    p_ev.add_argument("event_id", type=int)

    p_ed = sub.add_parser("edges", help="列出指定顶点在时间窗内的入边/出边")
    p_ed.add_argument("tsg_file")
    p_ed.add_argument("--kind", required=True, choices=["Process", "File", "Network"])
    p_ed.add_argument("--key", required=True)
    p_ed.add_argument("--direction", choices=["in", "out", "both"], default="both")
    p_ed.add_argument("--lo", type=int, default=-1)
    p_ed.add_argument("--hi", type=int, default=(1 << 63) - 1)
    p_ed.add_argument("--extras", action="store_true")
    p_ed.add_argument("--limit", type=int, default=100)

    p_nb = sub.add_parser("neighbors", help="从指定 event_id 展开 k 跳邻域")
    p_nb.add_argument("tsg_file")
    p_nb.add_argument("event_id", type=int)
    p_nb.add_argument("--hops", type=int, default=1)
    p_nb.add_argument("--direction", choices=["backward", "forward"], default="backward")
    p_nb.add_argument("--limit", type=int, default=200)

    p_sql = sub.add_parser("export-sqlite", help="将单个 .tsg 导出为只读 SQLite 便于 SQL 审计")
    p_sql.add_argument("tsg_file")
    p_sql.add_argument("sqlite_file")

    args = ap.parse_args(argv)
    with TSGReader(args.tsg_file) as reader:
        if args.cmd == "info":
            print(json.dumps(reader.meta, ensure_ascii=False, indent=2))
        elif args.cmd == "find-vertex":
            res = search_vertices(reader, kind=args.kind, pattern=args.match, pid=args.pid, limit=args.limit)
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif args.cmd == "event":
            res = [_edge_to_dict(e) for e in reader.find_edges_by_event_id(args.event_id, with_extras=True)]
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif args.cmd == "edges":
            res = list_vertex_edges(
                reader, kind=args.kind, key=args.key, direction=args.direction,
                lo=args.lo, hi=args.hi, with_extras=args.extras, limit=args.limit,
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif args.cmd == "neighbors":
            res = expand_neighbors(
                reader, args.event_id, hops=args.hops, direction=args.direction, limit=args.limit,
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif args.cmd == "export-sqlite":
            stats = export_sqlite(reader, args.sqlite_file)
            print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
