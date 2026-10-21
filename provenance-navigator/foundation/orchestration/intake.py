"""起点定位（编排）：核对终点事件、算实例数与时间范围。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core import graph_facts
from ..core.trace import trace_event

if TYPE_CHECKING:
    from ..deps import Deps

_POI_EDGES_CYPHER = """
MATCH (p:Process)-[e:{rel_match}]->(o:{label})
WHERE (e.syscall = $sc OR e.action = $sc) AND (
    (o.file_id IS NOT NULL AND o.file_id = $key) OR
    (o.path IS NOT NULL AND o.path = $key) OR
    (o.network_id IS NOT NULL AND o.network_id = $key) OR
    (o.endpoints IS NOT NULL AND o.endpoints = $key)
)
RETURN e.event_id AS event_id,
       coalesce(e.start_ns, e.starttime) AS starttime,
       coalesce(e.end_ns, e.endtime) AS endtime,
       coalesce(e.syscall, e.action) AS syscall,
       CASE WHEN e.result > 0 THEN e.result
            WHEN e.bytes IS NOT NULL THEN e.bytes
            ELSE 0 END AS bytes,
       coalesce(p.process_id, coalesce(p.host_id, '') + '|' + coalesce(p.container_id, '') + '|' + toString(p.pid) + '|' + toString(p.start_ns)) AS process_id,
       coalesce(p.exe_path, p.exepath, p.name) AS process_content,
       coalesce(o.path, o.endpoints, o.file_id, o.network_id) AS other,
       labels(o)[0] AS other_label,
       coalesce(o.proto, o.protocol, '') AS other_protocol
ORDER BY starttime
"""


def intake(deps: "Deps") -> dict[str, Any]:
    """POI 命中校验 + 时间范围现算（实例数/时间范围不写进配置）。"""
    poi = deps.scenario.poi.as_dict()
    rel_match = graph_facts.cypher_rel_match(poi["rel"])
    cypher = _POI_EDGES_CYPHER.format(rel_match=rel_match, label="File" if poi["kind"] == "file" else "Network")
    rows = deps.graph.run(cypher, {"key": poi["key"], "sc": poi["syscall"]})
    if not rows:
        raise RuntimeError(f"POI 在库中未命中：{poi}")

    process_ids = sorted({r["process_id"] for r in rows})
    owner = rows[0]["process_content"]
    t_first = min(int(r["starttime"]) for r in rows)
    t_last = max(int(r["endtime"]) for r in rows)

    inv = deps.record
    inv.poi_owner = owner
    inv.poi_instances = len(rows)
    inv.poi_t0 = t_first
    inv.poi_t1 = t_last
    # 终点事件的原文（闭包引擎的种子）
    normalized_rel = graph_facts.normalize_rel(poi["rel"])
    inv.poi_rows = [dict(row, rel=normalized_rel) for row in rows]
    inv.add_hypothesis("POI", f"POI: {owner} {poi['rel']} {poi['syscall']} {poi['key']}", status="confirmed")

    for pid in process_ids:
        inv.add_entity("Process", pid, status="tracing")
    deps.log(f"[intake] POI 命中 {len(rows)} 条实例；涉及进程 {process_ids}")
    trace_event(deps.trace, "intake", poi_rows=len(rows), processes=len(process_ids))
    return {"poi_rows": rows}
