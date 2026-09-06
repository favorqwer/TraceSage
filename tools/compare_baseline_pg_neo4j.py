#!/usr/bin/env python3
"""Content-level comparison of the PG baseline run vs the Neo4j baseline run.

Both artifacts (baseline.json) record final_edges / b_score_edges as
canonical keys "host|srcVertexId|dstVertexId|eventId". The two runs use
different vertex id spaces (PG row ids vs the Neo4j registry's
content-deterministic ids), so the keys are not directly comparable. This
tool re-materializes both sides into a content key space:

    vertex  = entity content from the artifact's final_vertices signature
              (the "id: name" prefix is stripped)
    edge    = (src_vertex, dst_vertex, syscall, starttime_ns, endtime_ns)

syscall/times are read back from the stores by event id (PG: the matching row
in processevent/fileevent/networkevent; Neo4j: event_id on the five
relationship types).

Usage:
    python tools/compare_baseline_pg_neo4j.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

import psycopg2
from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sysdig-parser"))

from parsers.config import load_dotenv  # noqa: E402

load_dotenv()

PG_BASELINE = ROOT / "output/baseline/1_Multi_Stage_Data_Exfiltration/baseline.json"
NEO_BASELINE = ROOT / "output/baseline/neo4j-1_Multi_Stage_Data_Exfiltration/baseline.json"


def load_artifact(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def strip_id(signature: str) -> str:
    """'2707: /usr/bin/nc' -> '/usr/bin/nc'."""
    idx = signature.find(": ")
    return signature[idx + 2 :] if idx >= 0 else signature


def parse_edge_key(key: str):
    _host, src, dst, event = key.split("|")
    return int(src), int(dst), int(event)


def content_edges(artifact, vertex_lookup, syscall_lookup):
    """Map artifact edges into the content key space.

    syscall_lookup(event_id, src_id, dst_id) -> (syscall, start_ns, end_ns)
    """
    edges = Counter()
    unknown = 0
    for edge in artifact["final_edges"]:
        src_id, dst_id, event_id = parse_edge_key(edge["key"])
        src = vertex_lookup(src_id)
        dst = vertex_lookup(dst_id)
        if src is None or dst is None:
            unknown += 1
            continue
        event = syscall_lookup(event_id, src_id, dst_id)
        if event is None:
            unknown += 1
            continue
        syscall, start_ns, end_ns = event
        edges[(src, dst, syscall, start_ns, end_ns)] += 1
    return edges, unknown


def main() -> None:
    pg = load_artifact(PG_BASELINE)
    neo = load_artifact(NEO_BASELINE)

    # ---- PG: vertex content + event content by row id ----
    pg_conn = psycopg2.connect(
        host=os.environ.get("PG_HOST", "localhost"),
        port=os.environ.get("PG_PORT", "5432"),
        user=os.environ.get("PG_USER", "postgres"),
        password=os.environ["PG_PASSWORD"],
        dbname="1_Multi_Stage_Data_Exfiltration",
    )
    pg_cur = pg_conn.cursor()
    pg_vertices = {v["id"]: strip_id(v["signature"]) for v in pg["final_vertices"]}
    neo_vertices = {v["id"]: strip_id(v["signature"]) for v in neo["final_vertices"]}

    pg_event_cache: dict[int, tuple] = {}
    for table in ("processevent", "fileevent", "networkevent"):
        pg_cur.execute(f"SELECT id, optype, starttime, endtime, srcid, dstid FROM {table}")
        for row_id, optype, start_ns, end_ns, src_id, dst_id in pg_cur.fetchall():
            pg_event_cache[row_id] = (optype, start_ns, end_ns, src_id, dst_id)

    def pg_lookup(event_id, src_id, dst_id):
        hit = pg_event_cache.get(event_id)
        if hit and hit[3] == src_id and hit[4] == dst_id:
            return hit[0], hit[1], hit[2]
        return None

    # ---- Neo4j: event content by event_id ----
    driver = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_DATABASE", "neo4j")) as session:
        neo_events = {}
        for rel in ("p2p", "p2f", "f2p", "p2n", "n2p"):
            for rec in session.run(
                f"MATCH ()-[r:{rel}]->() "
                "RETURN r.event_id AS eid, r.syscall AS syscall, r.starttime AS st, r.endtime AS et"
            ):
                neo_events[rec["eid"]] = (rec["syscall"], rec["st"], rec["et"])
    driver.close()

    def neo_lookup(event_id, src_id, dst_id):
        return neo_events.get(event_id)

    pg_edges, pg_unknown = content_edges(pg, pg_vertices.get, pg_lookup)
    neo_edges, neo_unknown = content_edges(neo, neo_vertices.get, neo_lookup)

    print(f"PG  final edges mapped: {sum(pg_edges.values())} (unmapped {pg_unknown})")
    print(f"Neo final edges mapped: {sum(neo_edges.values())} (unmapped {neo_unknown})")
    print()

    common = pg_edges & neo_edges
    only_pg = pg_edges - neo_edges
    only_neo = neo_edges - pg_edges
    print(f"common: {sum(common.values())} edge instances / {len(common)} distinct")
    print(f"only in PG  baseline: {sum(only_pg.values())} instances / {len(only_pg)} distinct")
    print(f"only in Neo baseline: {sum(only_neo.values())} instances / {len(only_neo)} distinct")

    print("\n--- edges only in the PG baseline ---")
    for (src, dst, syscall, start_ns, end_ns), count in sorted(only_pg.items()):
        print(f"  [{syscall}] {src} -> {dst}  @{start_ns}..{end_ns} x{count}")
    print("\n--- edges only in the Neo4j baseline ---")
    for (src, dst, syscall, start_ns, end_ns), count in sorted(only_neo.items()):
        print(f"  [{syscall}] {src} -> {dst}  @{start_ns}..{end_ns} x{count}")

    # ---- reputation consistency on common vertices ----
    pg_rep = {strip_id(v["signature"]): v["reputation"] for v in pg["final_vertices"]}
    neo_rep = {strip_id(v["signature"]): v["reputation"] for v in neo["final_vertices"]}
    common_rep = set(pg_rep) & set(neo_rep)
    diffs = [(k, pg_rep[k], neo_rep[k]) for k in sorted(common_rep) if abs(pg_rep[k] - neo_rep[k]) > 1e-9]
    print(f"\nvertices in both final graphs: {len(common_rep)}, reputation mismatches: {len(diffs)}")
    for key, a, b in diffs[:10]:
        print(f"  {key}: PG {a} vs Neo {b}")


if __name__ == "__main__":
    main()
