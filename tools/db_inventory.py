#!/usr/bin/env python3
"""图侧信息清单（Neo4j -> inventory JSON）。

与 `tools/log_inventory.py` 对称：把图库里**实际存在的信息**完整落成一份确定性
JSON（标签、关系、属性键与填充率、syscall 取值、event_id 连续性等），供
`tools/coverage_gap.py` 与日志侧清单做差。

用法：
    python tools/db_inventory.py tracesage-1-multi-stage-data-exfiltration \
        -o output/inventory/1_Multi_Stage_Data_Exfiltration.db-inventory.json
    # 不传库名则用 .env / 环境变量的 NEO4J_DATABASE
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sysdig-parser"))

from neo4j import GraphDatabase  # noqa: E402

from parsers.config import load_dotenv  # noqa: E402

load_dotenv()

TOOL_VERSION = 1
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe(name: str) -> str:
    if not _NAME_RE.match(name):
        raise ValueError(f"unsafe schema name: {name!r}")
    return name


def _sorted_counter(c: Counter, limit: Optional[int] = None) -> Dict[str, int]:
    items = sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0])))
    if limit is not None:
        items = items[:limit]
    return {str(k): v for k, v in items}


def collect(database: str) -> dict:
    uri = os.environ["NEO4J_URI"]
    auth = (os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"])
    drv = GraphDatabase.driver(uri, auth=auth)
    out: dict = {"meta": {"tool": "db_inventory", "tool_version": TOOL_VERSION,
                          "database": database, "uri": uri}}
    try:
        with drv.session(database=database) as s:
            labels = [r[0] for r in s.run("CALL db.labels()")]
            rels = [r[0] for r in s.run("CALL db.relationshipTypes()")]
            props = [r[0] for r in s.run("CALL db.propertyKeys()")]

            # --- 顶点：每标签计数 + 属性填充 ---
            vertices = {}
            for lab in sorted(labels):
                lab_s = _safe(lab)
                n = s.run(f"MATCH (n:`{lab_s}`) RETURN count(n) AS c").single()["c"]
                fills = {}
                for rec in s.run(
                    f"MATCH (n:`{lab_s}`) UNWIND keys(n) AS k "
                    "RETURN k AS key, count(*) AS c"):
                    fills[rec["key"]] = rec["c"]
                isolated = s.run(
                    f"MATCH (n:`{lab_s}`) WHERE NOT (n)--() RETURN count(n) AS c"
                ).single()["c"]
                vertices[lab] = {
                    "count": n,
                    "properties": _sorted_counter(Counter(fills)),
                    "property_fill_rate": {
                        k: round(v / n, 6) if n else None
                        for k, v in sorted(fills.items())},
                    "isolated_vertices": isolated,
                }

            # --- 关系：每类型计数 + 属性填充 + syscall/bytes/时间 ---
            relationships = {}
            for rel in sorted(rels):
                rel_s = _safe(rel)
                n = s.run(
                    f"MATCH ()-[r:`{rel_s}`]->() RETURN count(r) AS c"
                ).single()["c"]
                fills = {}
                for rec in s.run(
                    f"MATCH ()-[r:`{rel_s}`]->() UNWIND keys(r) AS k "
                    "RETURN k AS key, count(*) AS c"):
                    fills[rec["key"]] = rec["c"]
                syscalls = Counter()
                bytes_sum = Counter()
                t0: Optional[int] = None
                t1: Optional[int] = None
                for rec in s.run(
                    f"MATCH ()-[r:`{rel_s}`]->() "
                    "RETURN r.syscall AS sc, count(*) AS c, "
                    "sum(coalesce(r.bytes,0)) AS b, "
                    "min(r.starttime) AS a, max(r.endtime) AS z "
                    "GROUP BY r.syscall"):
                    key = rec["sc"] if rec["sc"] is not None else "<null>"
                    syscalls[key] = rec["c"]
                    bytes_sum[key] = rec["b"] or 0
                    if rec["a"] is not None and (t0 is None or rec["a"] < t0):
                        t0 = rec["a"]
                    if rec["z"] is not None and (t1 is None or rec["z"] > t1):
                        t1 = rec["z"]
                relationships[rel] = {
                    "count": n,
                    "properties": _sorted_counter(Counter(fills)),
                    "property_fill_rate": {
                        k: round(v / n, 6) if n else None
                        for k, v in sorted(fills.items())},
                    "syscalls": _sorted_counter(syscalls),
                    "bytes_sum_by_syscall": _sorted_counter(bytes_sum),
                    "starttime_min": t0,
                    "endtime_max": t1,
                }

            # --- event_id 连续性 ---
            ev_id = {"count": 0, "null": 0, "min": None, "max": None,
                     "duplicates": 0, "gap_segments": 0, "missing_total": 0,
                     "max_gap": 0, "gaps_first_20": []}
            last = None
            seen_bad = 0
            for rec in s.run("MATCH ()-[r]->() RETURN r.event_id AS id ORDER BY id"):
                v = rec["id"]
                if v is None:
                    ev_id["null"] += 1
                    continue
                ev_id["count"] += 1
                if ev_id["min"] is None:
                    ev_id["min"] = v
                ev_id["max"] = v
                if last is not None:
                    if v == last:
                        ev_id["duplicates"] += 1
                        seen_bad += 1
                    elif v > last + 1:
                        miss = v - last - 1
                        ev_id["missing_total"] += miss
                        ev_id["gap_segments"] += 1
                        ev_id["max_gap"] = max(ev_id["max_gap"], miss)
                        if len(ev_id["gaps_first_20"]) < 20:
                            ev_id["gaps_first_20"].append([last + 1, v - 1, miss])
                last = v

            # --- Network 协议分布 ---
            protocols = Counter()
            if "Network" in labels:
                for rec in s.run(
                    "MATCH (n:Network) RETURN coalesce(n.protocol,'<null>') AS p, "
                    "count(*) AS c"):
                    protocols[rec["p"]] = rec["c"]

            # --- Process name 分布（TopN） ---
            process_names = Counter()
            if "Process" in labels:
                for rec in s.run(
                    "MATCH (n:Process) RETURN n.name AS nm, count(*) AS c "
                    "ORDER BY c DESC LIMIT 200"):
                    process_names[rec["nm"]] = rec["c"]

            out["meta"]["labels"] = sorted(labels)
            out["meta"]["relationship_types"] = sorted(rels)
            out["meta"]["property_keys"] = sorted(props)
            out["vertices"] = vertices
            out["relationships"] = relationships
            out["event_ids"] = ev_id
            out["network_protocols"] = _sorted_counter(protocols)
            out["process_names_top"] = _sorted_counter(process_names)
    finally:
        drv.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("database", nargs="?", default=None,
                    help="Neo4j database（默认 NEO4J_DATABASE/neo4j）")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    db = args.database or os.environ.get("NEO4J_DATABASE", "neo4j")

    result = collect(db)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True),
                   encoding="utf-8")
    v = result["vertices"]
    r = result["relationships"]
    print(f"db={db} labels={ {k: v[k]['count'] for k in v} } "
          f"rels={ {k: r[k]['count'] for k in r} } -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
