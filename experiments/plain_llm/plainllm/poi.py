"""场景输入：POI 定义、锚点边解析、提示词里的 POI 与规模文本。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from neo4j import GraphDatabase

from .chunking import ns_to_iso, triple_key
from .settings import Config


def load_scenarios(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("scenarios") or {}


def scenarios_fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_anchor(cfg: Config, database: str, poi: dict[str, Any]) -> Optional[dict[str, Any]]:
    """把 POI 规格解析成一条具体锚点边（最后一次匹配的边）。

    分三档降级并在结果里记录 tier：syscall 精确匹配 → 不限 syscall → 反向边。
    解析不到返回 None，不猜、不阻断（报告里会披露）。
    """
    driver = GraphDatabase.driver(cfg.neo4j_uri, auth=(cfg.neo4j_user, cfg.neo4j_password),
                                  connection_timeout=10)
    try:
        with driver.session(database=database) as session:
            if poi.get("kind") == "file":
                return _resolve_file(session, poi)
            return _resolve_network(session, poi)
    finally:
        driver.close()


def _resolve_file(session: Any, poi: dict[str, Any]) -> Optional[dict[str, Any]]:
    path = poi.get("file_id")
    call = poi.get("syscall")
    query = """
    MATCH (p:Process)-[r]->(f:File)
    WHERE (f.path = $path OR f.path ENDS WITH ('|' + $path))
      AND ($call IS NULL OR coalesce(r.syscall, r.action) = $call)
    RETURN p.exe_path AS src, coalesce(r.syscall, r.action) AS call, f.path AS dst,
           r.start_ns AS t0, type(r) AS rel
    ORDER BY r.start_ns DESC LIMIT 1
    """
    for tier, call_filter in ((1, call), (2, None)):
        row = session.run(query, path=path, call=call_filter).single()
        if row:
            return _anchor_row(row, tier, "P", "F")
    # 第三档：POI 作为源（如 rename 的源端）
    query_src = """
    MATCH (f:File)-[r]->(x)
    WHERE (f.path = $path OR f.path ENDS WITH ('|' + $path))
    RETURN f.path AS src, coalesce(r.syscall, r.action) AS call,
           coalesce(x.exe_path, x.path, x.endpoints) AS dst,
           r.start_ns AS t0, type(r) AS rel
    ORDER BY r.start_ns DESC LIMIT 1
    """
    row = session.run(query_src, path=path).single()
    return _anchor_row(row, 3, "F", "?") if row else None


def _resolve_network(session: Any, poi: dict[str, Any]) -> Optional[dict[str, Any]]:
    endpoints = poi.get("network_id")
    call = poi.get("syscall")
    query = """
    MATCH (p:Process)-[r]->(n:Network)
    WHERE n.endpoints = $endpoints
      AND ($call IS NULL OR coalesce(r.syscall, r.action) = $call)
    RETURN p.exe_path AS src, coalesce(r.syscall, r.action) AS call, n.endpoints AS dst,
           r.start_ns AS t0, type(r) AS rel
    ORDER BY r.start_ns DESC LIMIT 1
    """
    for tier, call_filter in ((1, call), (2, None)):
        row = session.run(query, endpoints=endpoints, call=call_filter).single()
        if row:
            return _anchor_row(row, tier, "P", "N")
    query_rev = """
    MATCH (n:Network)-[r]->(p:Process)
    WHERE n.endpoints = $endpoints
    RETURN n.endpoints AS src, coalesce(r.syscall, r.action) AS call, p.exe_path AS dst,
           r.start_ns AS t0, type(r) AS rel
    ORDER BY r.start_ns DESC LIMIT 1
    """
    row = session.run(query_rev, endpoints=endpoints).single()
    return _anchor_row(row, 3, "N", "P") if row else None


def _anchor_row(row: Any, tier: int, src_kind: str, dst_kind: str) -> dict[str, Any]:
    src, dst = row["src"], row["dst"]
    return {
        "src": src if src is not None else "<NA>",
        "src_kind": src_kind,
        "call": row["call"] or "<NA>",
        "dst": dst if dst is not None else "<NA>",
        "dst_kind": dst_kind,
        "first_ns": int(row["t0"]) if row["t0"] is not None else None,
        "rel": row["rel"],
        "tier": tier,
    }


def find_anchor_triple(anchor: Optional[dict[str, Any]], triples: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """在导出边表里定位锚点边（按内容三元组匹配）。"""
    if not anchor:
        return None
    for triple in triples:
        if triple_key(triple) == triple_key(anchor):
            return triple
    return None


def stats_block(stats: dict[str, Any], vertices: Optional[dict[str, int]] = None) -> str:
    first = ns_to_iso(stats.get("first_ns"))
    last = ns_to_iso(stats.get("last_ns"))
    lines = [
        f"内容三元组 {stats.get('triples', 0):,} 条（实例边 {stats.get('instances', 0):,} 条）",
        f"时间范围 {first} ~ {last}",
    ]
    if vertices:
        lines.append(
            f"顶点 Process {vertices.get('process', 0):,} / File {vertices.get('file', 0):,} / "
            f"Network {vertices.get('network', 0):,}"
        )
    return "\n".join(lines)


def poi_block(poi: dict[str, Any], anchor: Optional[dict[str, Any]]) -> str:
    lines = [f"类型：{poi.get('kind')}"]
    if poi.get("kind") == "file":
        lines.append(f"对象：{poi.get('file_id')}")
    else:
        lines.append(f"对象：{poi.get('network_id')}")
    lines.append(f"给定动作：{poi.get('syscall') or '未知'}")
    if anchor:
        lines.append(
            f"锚点边：{anchor['src_kind']}|{anchor['src']} --{anchor['call']}--> "
            f"{anchor['dst_kind']}|{anchor['dst']}"
        )
        lines.append(f"锚点边时间：{ns_to_iso(anchor.get('first_ns'))}")
    else:
        lines.append("锚点边：未在图中定位到具体边（只按上面的对象与动作调查）")
    return "\n".join(lines)
