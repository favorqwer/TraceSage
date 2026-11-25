"""全量溯源图 → 内容去重边表（JSONL）。

只做一件事：把 -v2 图库里的全部关系边按评测口径的内容三元组
（源内容, 系统调用, 目标内容, 成败）合并，保留实例数、首末时间、载荷预览。
不做图遍历、不采样、不按时间或度数过滤。
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

from neo4j import GraphDatabase
from .checkpoint import ENDPOINT_IDENTITY

# 一条查询取全图关系边。CASE 只做顶点种类判定与内容取值，不做过滤。
QUERY = """
MATCH (a)-[r]->(b)
RETURN
  CASE WHEN 'Process' IN labels(a) THEN 'P'
       WHEN 'File' IN labels(a) THEN 'F'
       WHEN 'Network' IN labels(a) THEN 'N' ELSE '?' END AS ka,
  CASE WHEN 'Process' IN labels(a) THEN coalesce(a.exe_path, '<NA>')
       WHEN 'File' IN labels(a) THEN coalesce(a.path, '<NA>')
       WHEN 'Network' IN labels(a) THEN coalesce(a.endpoints, '<NA>')
       ELSE coalesce(a.exe_path, a.path, a.endpoints, '<NA>') END AS sa,
  CASE WHEN 'Process' IN labels(b) THEN 'P'
       WHEN 'File' IN labels(b) THEN 'F'
       WHEN 'Network' IN labels(b) THEN 'N' ELSE '?' END AS kb,
  CASE WHEN 'Process' IN labels(b) THEN coalesce(b.exe_path, '<NA>')
       WHEN 'File' IN labels(b) THEN coalesce(b.path, '<NA>')
       WHEN 'Network' IN labels(b) THEN coalesce(b.endpoints, '<NA>')
       ELSE coalesce(b.exe_path, b.path, b.endpoints, '<NA>') END AS sb,
  type(r) AS rel,
  coalesce(r.syscall, r.action) AS call,
  r.action AS action,
  r.start_ns AS t0,
  r.end_ns AS t1,
  r.payload_b64 AS pay
"""


def _decode_payload(payload_b64: Any, limit: int) -> Optional[str]:
    """载荷 → 可打印预览。只保留前 limit 个可见字符。"""
    if not payload_b64 or limit <= 0:
        return None
    try:
        raw = base64.b64decode(str(payload_b64), validate=False)
    except Exception:
        return None
    text = raw.decode("utf-8", "replace")
    chars = [ch if ch.isprintable() else " " for ch in text]
    preview = " ".join("".join(chars).split())
    return preview[:limit] if preview else None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def export_graph(
    uri: str,
    user: str,
    password: str,
    database: str,
    out_path: Path,
    *,
    payload_preview_chars: int = 48,
    progress_every: int = 500_000,
) -> dict[str, Any]:
    """导出并去重；返回统计信息（实例数、三元组数、时间范围等）。"""
    started = time.time()
    agg: dict[tuple, dict[str, Any]] = {}
    instances = 0
    missing_call = 0

    driver = GraphDatabase.driver(uri, auth=(user, password), connection_timeout=10)
    vertices = {"process": 0, "file": 0, "network": 0}
    try:
        with driver.session(database=database) as session:
            result = session.run(QUERY, fetch_size=20_000)
            for row in result:
                instances += 1
                call = row["call"] or "<NA>"
                if call == "<NA>":
                    missing_call += 1
                key = ((row["ka"], row["sa"]), call, (row["kb"], row["sb"]))
                rec = agg.get(key)
                if rec is None:
                    rec = {
                        "src_kind": row["ka"],
                        "src": row["sa"],
                        "call": call,
                        "dst_kind": row["kb"],
                        "dst": row["sb"],
                        "action": row["action"],
                        "rel": row["rel"],
                        "n": 0,
                        "first_ns": None,
                        "last_ns": None,
                        "payload": None,
                        "payload_tries": 0,
                    }
                    agg[key] = rec
                rec["n"] += 1
                t0, t1 = row["t0"], row["t1"]
                if t0 is not None:
                    if rec["first_ns"] is None or t0 < rec["first_ns"]:
                        rec["first_ns"] = int(t0)
                    if rec["last_ns"] is None or t0 > rec["last_ns"]:
                        rec["last_ns"] = int(t0)
                if t1 is not None and (rec["last_ns"] is None or int(t1) > rec["last_ns"]):
                    rec["last_ns"] = int(t1)
                if rec["payload"] is None and row["pay"] and rec["payload_tries"] < 5:
                    rec["payload_tries"] += 1
                    rec["payload"] = _decode_payload(row["pay"], payload_preview_chars)
                if progress_every and instances % progress_every == 0:
                    print(f"  导出中：已读 {instances:,} 条实例边，累计 {len(agg):,} 个内容三元组", flush=True)
            for label, key in (("Process", "process"), ("File", "file"), ("Network", "network")):
                vertices[key] = session.run(
                    f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"]
    finally:
        driver.close()

    triples = list(agg.values())
    triples.sort(key=lambda q: (
        q["first_ns"] if q["first_ns"] is not None else 0,
        q["src_kind"], q["src"], q["call"], q["dst_kind"], q["dst"],
    ))
    for idx, triple in enumerate(triples, start=1):
        triple["id"] = f"E{idx:06d}"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for triple in triples:
            fh.write(json.dumps(triple, ensure_ascii=False, sort_keys=True) + "\n")

    first = min((q["first_ns"] for q in triples if q["first_ns"] is not None), default=None)
    last = max((q["last_ns"] for q in triples if q["last_ns"] is not None), default=None)
    kinds = {"P": 0, "F": 0, "N": 0, "?": 0}
    for triple in triples:
        kinds[triple["src_kind"]] = kinds.get(triple["src_kind"], 0) + 1
        kinds[triple["dst_kind"]] = kinds.get(triple["dst_kind"], 0) + 1

    stats = {
        "input_protocol": "triplet-v1",
        "endpoint_identity": ENDPOINT_IDENTITY,
        "payload_preview_chars": payload_preview_chars,
        "database": database,
        "instances": instances,
        "triples": len(triples),
        "missing_syscall_triples": sum(1 for q in triples if q["call"] == "<NA>"),
        "missing_syscall_instances": missing_call,
        "first_ns": first,
        "last_ns": last,
        "endpoint_mentions": kinds,
        "vertices": vertices,
        "export_seconds": round(time.time() - started, 1),
        "edges_jsonl": str(out_path),
        "edges_sha256": _file_sha256(out_path),
    }
    print(f"  导出完成：{instances:,} 条实例边 → {len(triples):,} 个内容三元组，"
          f"耗时 {stats['export_seconds']}s", flush=True)
    return stats
