"""证据编号回填（第 5 层内部）：只补证据，不改内容三元组。

报告里的每条边必须有证据编号（图上那条边的编号）；万一某条边没有，回库按内容三元组查一条补上。
"""

from __future__ import annotations

from typing import Any


def resolve_event_ids(graph: Any, edges: list[dict[str, Any]]) -> tuple[int, int]:
    """回库给缺证据编号的边补证据；返回（补上的条数，补不到的条数）。"""
    content = "coalesce({a}.path, {a}.network_id, coalesce({a}.exepath, {a}.name))"
    rels = ("p2f", "f2p", "p2n", "n2p", "p2p")
    resolved = unresolved = 0
    for edge in edges:
        if edge.get("event_id"):
            resolved += 1
            continue
        found = None
        for rel in rels:
            cypher = (
                f"MATCH (a)-[e:{rel} {{syscall:$sc}}]->(b) "
                f"WHERE {content.format(a='a')} = $src AND {content.format(a='b')} = $dst "
                "RETURN e.event_id AS eid ORDER BY e.starttime LIMIT 1"
            )
            try:
                rows = graph.run(cypher, {"sc": edge.get("syscall"), "src": edge.get("src"),
                                          "dst": edge.get("dst")})
            except Exception:  # noqa: BLE001 - 补证据失败不影响报告
                continue
            if rows:
                found = int(rows[0]["eid"])
                break
        if found is not None:
            edge["event_id"] = found
            resolved += 1
        else:
            unresolved += 1
    return resolved, unresolved
