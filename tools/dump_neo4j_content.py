#!/usr/bin/env python3
"""Dev tool: dump the FULL content of a TraceSage Neo4j provenance database
(all vertices with properties, all relationships with properties and endpoint
identities) as canonically ordered JSON, for content-level equality checks
between two databases imported from the same log.

Usage:
    python tools/dump_neo4j_content.py <database> -o out.json
    python tools/dump_neo4j_content.py <database> -o out.json --baseline other.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sysdig-parser"))

from parsers.config import load_dotenv  # noqa: E402
from parsers.storage.neo4j_writer import Neo4jWriter  # noqa: E402

load_dotenv()

# Vertex identity property per label (same keys the writer MERGEs on).
_ID_PROP = {"Process": "process_id", "File": "file_id", "Network": "network_id"}


def dump(db: str) -> dict:
    w = Neo4jWriter(database=db)
    try:
        d = w.driver

        vertices = []
        for rec in d.execute_query(
            "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props",
            database_=db,
        ).records:
            labels = [l for l in rec["labels"] if l]
            props = dict(rec["props"])
            id_prop = _ID_PROP.get(labels[0] if labels else "")
            vertices.append({
                "label": labels[0] if labels else "",
                "key": props.get(id_prop, json.dumps(props, sort_keys=True)),
                "props": props,
            })
        vertices.sort(key=lambda v: (v["label"], v["key"]))

        edges = []
        for rec in d.execute_query(
            """
            MATCH (a)-[r]->(b)
            RETURN type(r) AS type, properties(r) AS props,
                   labels(a) AS la, properties(a) AS pa,
                   labels(b) AS lb, properties(b) AS pb
            """,
            database_=db,
        ).records:
            def endpoint(labels, props):
                label = labels[0] if labels else ""
                id_prop = _ID_PROP.get(label, "")
                return {"label": label, "key": props.get(id_prop)}
            edges.append({
                "type": rec["type"],
                "event_id": rec["props"].get("event_id"),
                "props": dict(rec["props"]),
                "src": endpoint(rec["la"], rec["pa"]),
                "dst": endpoint(rec["lb"], rec["pb"]),
            })
        edges.sort(key=lambda e: (e["type"], e["event_id"]))

        return {
            "database": db,
            "vertex_count": len(vertices),
            "edge_count": len(edges),
            "vertices": vertices,
            "edges": edges,
        }
    finally:
        w.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("database", help="Neo4j database name")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--baseline", help="previous dump to compare against")
    args = ap.parse_args()

    result = dump(args.database)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(
        json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True),
        encoding="utf-8",
    )
    print(f"dumped {result['vertex_count']} vertices, {result['edge_count']} edges -> {args.out}")

    if args.baseline:
        base = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        diffs = []
        if base["vertex_count"] != result["vertex_count"]:
            diffs.append(f"vertex_count: {base['vertex_count']} -> {result['vertex_count']}")
        if base["edge_count"] != result["edge_count"]:
            diffs.append(f"edge_count: {base['edge_count']} -> {result['edge_count']}")
        # vertices are sorted identically; index-wise compare
        bv, nv = base["vertices"], result["vertices"]
        for i in range(min(len(bv), len(nv))):
            if bv[i] != nv[i]:
                diffs.append(f"vertex[{i}]: {json.dumps(bv[i], sort_keys=True)[:200]} -> {json.dumps(nv[i], sort_keys=True)[:200]}")
                if len(diffs) > 20:
                    break
        be, ne = base["edges"], result["edges"]
        shown = 0
        for i in range(min(len(be), len(ne))):
            if be[i] != ne[i]:
                diffs.append(f"edge[{i}]: {json.dumps(be[i], sort_keys=True)[:260]} -> {json.dumps(ne[i], sort_keys=True)[:260]}")
                shown += 1
                if shown >= 20:
                    break
        if diffs:
            print(f"\nDIFF vs {args.baseline}: {len(diffs)} difference(s)")
            for line in diffs:
                print("  " + line)
            return 1
        print(f"\nIDENTICAL: full content matches {args.baseline}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
