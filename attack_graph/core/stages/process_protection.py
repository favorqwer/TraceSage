"""用同一进程实例的已确认前后事件保护待删操作。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import Iterable

from domain.edge import REL_NORM


def protect(confirmed: Iterable[dict], dropped: list[dict],
            members: dict[tuple[int, str], list[dict]], cutoff: int) -> tuple[list[dict], list[dict]]:
    """返回应恢复的候选及仍可删除的候选，按原始事件记录保留依据。"""
    def matching(edge):
        edge_sc = str(edge.get("syscall") or "")
        return (event for eid in edge.get("event_ids", ()) for rel in edge.get("rels", ())
                for event in members.get((eid, REL_NORM.get(rel)), ())
                if not edge_sc or not event.get("syscall") or event.get("syscall") == edge_sc)

    inputs, outputs, launches = defaultdict(list), defaultdict(list), defaultdict(list)
    for edge in confirmed:
        for event in matching(edge):
            start, end = event["start"], event["finish"]
            if start is None or end is None or start > cutoff:
                continue
            rel, action, result = REL_NORM[event["rel"]], event["action"], event["result"]
            if rel == "p2p" and action in ("clone", "exec") and result is not None and result >= 0:
                inputs[event["dst"]].append((start, event["eid"]))
                launches[event["dst"]].append((start, event["eid"]))
            elif rel == "n2p" and action == "recv" and result is not None and result > 0:
                inputs[event["dst"]].append((start, event["eid"]))
            elif rel == "p2p" and action == "exit":
                outputs[event["src"]].append((end, event["eid"]))
            elif rel in ("p2f", "p2n") and action in ("write", "send") and result is not None and result > 0:
                outputs[event["src"]].append((end, event["eid"]))
    for index in (inputs, outputs, launches):
        for entries in index.values():
            entries.sort()

    kept, removed = [], []
    for edge in dropped:
        evidence = {}
        for event in matching(edge):
            start, end = event["start"], event["finish"]
            if start is None or end is None or end > cutoff:
                continue
            rel, action = REL_NORM[event["rel"]], event["action"]
            if (rel == "f2p" and action == "read" and event["src_kind"] == "pipe"
                    and event["result"] is not None and event["result"] > 0):
                ingress, egress = inputs[event["dst"]], outputs[event["dst"]]
                a = bisect_right(ingress, (start, float("inf"))) - 1
                b = bisect_left(egress, (end, -1))
                if a >= 0 and b < len(egress):
                    evidence[event["eid"]] = ["pipe_input_between_confirmed_actions", ingress[a][1], egress[b][1]]
            elif rel == "p2p" and action == "exit":
                execution = launches[event["src"]]
                ingress, egress = inputs[event["dst"]], outputs[event["dst"]]
                a = bisect_right(execution, (start, float("inf"))) - 1
                b = bisect_right(ingress, (start, float("inf"))) - 1
                c = bisect_left(egress, (end, -1))
                if min(a, b) >= 0 and c < len(egress):
                    evidence[event["eid"]] = ["exit_between_confirmed_parent_actions", execution[a][1],
                                              ingress[b][1], egress[c][1]]
        if evidence:
            kept.append({**edge, "origin": "kept", "reason": "同一进程实例的前后确认事件支持保留",
                         "process_guard_evidence": evidence})
        else:
            removed.append(edge)
    return kept, removed
