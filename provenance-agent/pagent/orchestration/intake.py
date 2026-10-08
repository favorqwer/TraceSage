"""起点定位（编排）：核对终点事件、算实例数与时间范围。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.trace import trace_event

if TYPE_CHECKING:
    from ..app import Deps

_POI_EDGES_CYPHER = """
MATCH (p:Process)-[e:{rel}]->(o:{label} {{{key_name}:$key}})
WHERE e.syscall = $sc
RETURN e.event_id AS event_id, e.starttime AS starttime, e.endtime AS endtime,
       e.syscall AS syscall, e.bytes AS bytes, p.process_id AS process_id,
       coalesce(p.exepath,p.name) AS process_content,
       coalesce(o.path, o.network_id) AS other, labels(o)[0] AS other_label,
       o.protocol AS other_protocol
ORDER BY e.starttime
"""


def intake(deps: "Deps") -> dict[str, Any]:
    """POI 命中校验 + 时间范围现算（实例数/时间范围不写进配置）。"""
    poi = deps.scenario.poi.as_dict()
    cypher = _POI_EDGES_CYPHER.format(rel=poi["rel"], label="File" if poi["kind"] == "file" else "Network",
                                      key_name="file_id" if poi["kind"] == "file" else "network_id")
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
    inv.poi_rows = [dict(row, rel=poi["rel"]) for row in rows]
    inv.add_hypothesis("POI", f"POI: {owner} {poi['rel']} {poi['syscall']} {poi['key']}", status="confirmed")

    for pid in process_ids:
        inv.add_entity("Process", pid, status="tracing")
    deps.log(f"[intake] POI 命中 {len(rows)} 条实例；涉及进程 {process_ids}")
    trace_event(deps.trace, "intake", poi_rows=len(rows), processes=len(process_ids))
    return {"poi_rows": rows}
