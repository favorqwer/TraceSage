"""Collapse report rows without losing the event references and rule evidence."""
from collections.abc import Iterable


def record_attributes(edge: dict) -> dict:
    if (edge.get("instances") or 0) > 1 or len(edge.get("event_ids") or ()) > 1:
        return {}
    return {name: edge[name] for name in ("bytes", "duration_ns") if edge.get(name) is not None}


def merge_report_edges(edges: Iterable[dict]) -> list[dict]:
    merged = {}
    for edge in edges:
        key = (edge["src"], edge["syscall"], edge["dst"])
        existing = merged.get(key)
        if existing is None:
            copied = {name: value for name, value in edge.items()
                      if name not in ("effect", "effects", "result")}
            if isinstance(copied.get("record_attributes"), list):
                copied["record_attributes"] = list(copied["record_attributes"])
            merged[key] = copied
            continue
        attributes = existing.setdefault("record_attributes", [record_attributes(existing)])
        attributes.extend(edge.get("record_attributes") or [record_attributes(edge)])
        if existing.get("event_ids") or edge.get("event_ids"):
            existing["event_ids"] = list(dict.fromkeys(
                [*(existing.get("event_ids") or ()), *(edge.get("event_ids") or ())]
            ))
            existing["instances"] = len(existing["event_ids"])
        if existing.get("bytes") is not None or edge.get("bytes") is not None:
            existing["bytes"] = int(existing.get("bytes") or 0) + int(edge.get("bytes") or 0)
        if existing.get("rels") or edge.get("rels"):
            existing["rels"] = list(dict.fromkeys(
                [*(existing.get("rels") or ()), *(edge.get("rels") or ())]
            ))
        for field, choose in (("t0", min), ("t1", max)):
            values = [row[field] for row in (existing, edge) if row.get(field) is not None]
            if values:
                existing[field] = choose(values)
    return list(merged.values())


def refresh_event_totals(edges: list[dict], events: list[dict]) -> None:
    """Recompute report totals using each distinct syscall once per relation."""
    by_index: dict[int, dict[tuple, dict]] = {}
    for event in events:
        identity = (event.get("src_host") or event.get("dst_host"), event["event_id"])
        for membership in event["memberships"]:
            by_index.setdefault(membership["agg_edge_index"], {}).setdefault(identity, event)
    for index, distinct in by_index.items():
        records = distinct.values()
        edge = edges[index]
        edge["instances"] = len(distinct)
        edge["bytes"] = sum(event.get("bytes") or 0 for event in records)
        for target, source, choose in (("t0", "start_ns", min), ("t1", "end_ns", max)):
            times = [event[source] for event in records if event.get(source) is not None]
            if times:
                edge[target] = choose(times)
