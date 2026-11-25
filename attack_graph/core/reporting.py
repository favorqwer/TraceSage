"""调查结果状态结构定义与调查报告导出。"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import gzip
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from domain.edge import labels_of, normalize_rel
from domain.keys import process_content_or_na, split_process_key

EVENTS_EXPORT_FORMAT_VERSION = 1


@dataclass
class RouteOutcome:
    """一次调查或判定的最终三段式分区结果与审计信息。"""
    confirmed: Dict[Tuple[Any, Any, Any], Dict[str, Any]]
    unexcluded: List[Dict[str, Any]]
    excluded: List[Dict[str, Any]]
    audit: Dict[str, Any] = field(default_factory=dict)


def report_endpoint(value: Any, label: Any) -> Any:
    """报告端点内容：进程取不到可执行文件时按官方口径写 `<NA>`。"""
    if str(label or "") == "Process" or not label:
        value = process_content_or_na(value)
    if split_process_key(value) is not None:
        raise ValueError(f"报告端点内容不能是进程主键：{value!r}")
    return value


def _report_edges(edges: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for edge in edges or []:
        rec = dict(edge)
        rec["src"] = report_endpoint(rec.get("src"), rec.get("src_label"))
        rec["dst"] = report_endpoint(rec.get("dst"), rec.get("dst_label"))
        out.append(rec)
    return out


def build_report(
    scenario_name: str,
    confirmed_edges: list,
    unexcluded_edges: list,
    excluded_edges: list = None,
    pruned_count: int = 0,
    promoted_count: int = 0,
    elapsed_seconds: float = 0.0,
    llm_calls: int = 0,
    llm_enabled: bool = False,
    anchor_confirmed_count: int = 0,
    promoted_by_motif: dict = None,
    mode: str = "hybrid",
    matcher_admitted_count: int = None,
    conf_filtered_count: int = 0,
    library: dict = None,
) -> dict:
    if excluded_edges is None:
        excluded_edges = []

    unique_confirmed = {}
    for e in confirmed_edges:
        key = (e.get("src"), e.get("syscall"), e.get("dst"))
        unique_confirmed[key] = e

    return {
        "scenario": scenario_name,
        "edges": _report_edges(unique_confirmed.values()),
        "unexcluded": _report_edges(unexcluded_edges),
        "excluded": _report_edges(excluded_edges),
        "stats": {
            "mode": mode,
            "confirmed_count": len(unique_confirmed),
            "unexcluded_count": len(unexcluded_edges),
            "excluded_count": len(excluded_edges),
            "pruned_noise_count": pruned_count,
            "promoted_count": promoted_count,
            "promoted_by_motif": promoted_by_motif or {},
            "matcher_admitted_count": matcher_admitted_count,
            "conf_filtered_count": int(conf_filtered_count),
            "anchor_confirmed_count": anchor_confirmed_count,
            "llm_enabled": bool(llm_enabled),
            "llm_calls": int(llm_calls),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "rules_library": library or {},
    }


def build_report_from_outcome(outcome: RouteOutcome, scenario_name: str, *,
                              elapsed_seconds: float = 0.0, llm_calls: int = 0,
                              llm_enabled: bool = False, library: dict = None) -> dict:
    audit = outcome.audit
    return build_report(
        scenario_name=scenario_name,
        confirmed_edges=list(outcome.confirmed.values()),
        unexcluded_edges=outcome.unexcluded,
        excluded_edges=outcome.excluded,
        pruned_count=audit.get("pruned_count", 0),
        promoted_count=audit.get("promoted_count", 0),
        elapsed_seconds=elapsed_seconds,
        llm_calls=llm_calls,
        llm_enabled=llm_enabled,
        anchor_confirmed_count=audit.get("anchor_confirmed_count", 0),
        promoted_by_motif=audit.get("promoted_by_motif", {}),
        mode=audit.get("mode", "hybrid"),
        matcher_admitted_count=audit.get("matcher_admitted_count"),
        conf_filtered_count=audit.get("conf_filtered_count", 0),
        library=library,
    )


def save_report(report: dict, out_path: str, *, overwrite: bool = True) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w" if overwrite else "x", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def default_events_path(report_out_path: str | Path) -> Path:
    """由聚合报告路径推导同目录伴生事件级明细文件路径（*.events.json.gz）。"""
    p = Path(report_out_path)
    name = p.name
    if name.endswith(".json.gz"):
        stem = name[:-8]
    elif name.endswith(".json"):
        stem = name[:-5]
    else:
        stem = p.stem
    return p.with_name(f"{stem}.events.json.gz")


def build_events_export(
    scenario_name: str,
    database: str,
    *,
    confirmed_edges: List[Dict[str, Any]],
    unexcluded_edges: List[Dict[str, Any]],
    raw_events: List[Dict[str, Any]],
    vertex_attrs: Dict[str, Dict[str, Any]],
    poi_rows: List[Dict[str, Any]],
    aggregate_indices: Optional[Dict[Tuple[Any, Any, Any], int]] = None,
) -> Dict[str, Any]:
    """按最终保留的聚合边筛选并导出完整单事件明细与去重实体属性表。"""
    raw_by_eid_rel: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)
    for ev in raw_events:
        rel_short = normalize_rel(str(ev.get("rel") or ev.get("rel_full") or ""))
        raw_by_eid_rel[(int(ev["event_id"]), rel_short)].append(ev)

    retained_entries: List[Tuple[int, str, Dict[str, Any]]] = []
    for idx, edge in enumerate(confirmed_edges):
        retained_entries.append((idx, "confirmed", edge))
    base_unex = len(confirmed_edges)
    for offset, edge in enumerate(unexcluded_edges):
        retained_entries.append((base_unex + offset, "unexcluded", edge))

    exported_by_key: Dict[Tuple[int, str, str], Dict[str, Any]] = {}
    multi_membership_events = 0
    missing_refs: List[Dict[str, Any]] = []

    for agg_index, report_status, edge in retained_entries:
        if aggregate_indices is not None:
            agg_index = aggregate_indices[(edge["src"], edge["syscall"], edge["dst"])]
        allowed_rels = {normalize_rel(str(r)) for r in (edge.get("rels") or ())}
        src_idents = {
            (str(pair[0]), str(pair[1]))
            for pair in (edge.get("src_identities") or ())
            if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[1]
        }
        dst_idents = {
            (str(pair[0]), str(pair[1]))
            for pair in (edge.get("dst_identities") or ())
            if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[1]
        }
        membership = {
            "agg_edge_index": agg_index,
            "report_status": report_status,
            "bundle_triple": [
                str(edge.get("src") or ""),
                str(edge.get("syscall") or ""),
                str(edge.get("dst") or ""),
            ],
            "verdict": str(edge.get("verdict") or ""),
            "llm_verdict": str(edge.get("llm_verdict") or edge.get("verdict") or ""),
            "decision_source": str(edge.get("decision_source") or ""),
            "verdict_reason": str(edge.get("verdict_reason") or ""),
            "llm_bundle_id": str(edge.get("llm_bundle_id") or ""),
            "llm_bundle_level": (int(edge["llm_bundle_level"]) if edge.get("llm_bundle_level") is not None else None),
            "llm_bundle_size": (int(edge["llm_bundle_size"]) if edge.get("llm_bundle_size") is not None else None),
            "rag_rules": list(edge.get("rag_rules") or ()),
            "origin": str(edge.get("origin") or ""),
            "class": str(edge.get("class") or ""),
            "reason": str(edge.get("reason") or ""),
            "dist": int(edge.get("dist") or 0),
            "via": str(edge.get("via") or ""),
            "channels": int(edge.get("channels") or 0),
        }

        edge_sc = str(edge.get("syscall") or "")
        for raw_eid in (edge.get("event_ids") or ()):
            eid = int(raw_eid)
            candidates: List[Dict[str, Any]] = []
            for rel_short in allowed_rels:
                candidates.extend(raw_by_eid_rel.get((eid, rel_short), ()))
            matched: List[Dict[str, Any]] = []
            for ev in candidates:
                ev_sc = str(ev.get("syscall") or "")
                if edge_sc and ev_sc and ev_sc != edge_sc:
                    continue
                src_pair = (str(ev["src_kind"]), str(ev["src_key"]))
                dst_pair = (str(ev["dst_kind"]), str(ev["dst_key"]))
                if src_idents and src_pair not in src_idents:
                    continue
                if dst_idents and dst_pair not in dst_idents:
                    continue
                matched.append(ev)
            if not matched:
                missing_refs.append({
                    "agg_edge_index": agg_index,
                    "event_id": eid,
                    "rels": sorted(allowed_rels),
                    "bundle_triple": membership["bundle_triple"],
                })
                continue
            for ev in matched:
                ev_key = (int(ev["event_id"]), str(ev["rel_full"]), str(ev.get("action") or ""))
                existing = exported_by_key.get(ev_key)
                if existing is None:
                    exported_by_key[ev_key] = {
                        "id": str(ev["id"]),
                        "event_id": int(ev["event_id"]),
                        "rel": str(ev["rel"]),
                        "rel_full": str(ev["rel_full"]),
                        "action": str(ev.get("action") or ""),
                        "syscall": str(ev.get("syscall") or ""),
                        "start_ns": ev.get("start_ns"),
                        "end_ns": ev.get("end_ns"),
                        "result": ev.get("result"),
                        "bytes": int(ev.get("bytes") or 0),
                        "effect": str(ev.get("effect") or ""),
                        "src_kind": str(ev["src_kind"]),
                        "src_key": str(ev["src_key"]),
                        "src_host": str(ev.get("src_host") or ""),
                        "src_file_type": ev.get("src_file_type"),
                        "dst_kind": str(ev["dst_kind"]),
                        "dst_key": str(ev["dst_key"]),
                        "dst_host": str(ev.get("dst_host") or ""),
                        "dst_file_type": ev.get("dst_file_type"),
                        "dist": int(ev.get("dist") or 0),
                        "via_kind": str(ev.get("via_kind") or ""),
                        "via_key": str(ev.get("via_key") or ""),
                        "support": int(ev.get("support") or 0),
                        "agg_edge_index": agg_index,
                        "report_status": report_status,
                        "verdict": membership["verdict"],
                        "llm_verdict": membership["llm_verdict"],
                        "decision_source": membership["decision_source"],
                        "verdict_reason": membership["verdict_reason"],
                        "llm_bundle_id": membership["llm_bundle_id"],
                        "llm_bundle_level": membership["llm_bundle_level"],
                        "llm_bundle_size": membership["llm_bundle_size"],
                        "rag_rules": membership["rag_rules"],
                        "origin": membership["origin"],
                        "class": membership["class"],
                        "reason": membership["reason"],
                        "bundle_triple": membership["bundle_triple"],
                        "memberships": [membership],
                    }
                else:
                    if membership not in existing["memberships"]:
                        existing["memberships"].append(membership)
                        if len(existing["memberships"]) == 2:
                            multi_membership_events += 1
                        if report_status == "confirmed" and existing["report_status"] != "confirmed":
                            existing["agg_edge_index"] = agg_index
                            existing["report_status"] = "confirmed"
                            existing["verdict"] = membership["verdict"]
                            existing["llm_verdict"] = membership["llm_verdict"]
                            existing["decision_source"] = membership["decision_source"]
                            existing["verdict_reason"] = membership["verdict_reason"]
                            existing["llm_bundle_id"] = membership["llm_bundle_id"]
                            existing["llm_bundle_level"] = membership["llm_bundle_level"]
                            existing["llm_bundle_size"] = membership["llm_bundle_size"]
                            existing["rag_rules"] = membership["rag_rules"]
                            existing["origin"] = membership["origin"]
                            existing["class"] = membership["class"]
                            existing["reason"] = membership["reason"]
                            existing["bundle_triple"] = membership["bundle_triple"]

    if missing_refs:
        sample = missing_refs[:10]
        raise RuntimeError(
            f"阶段 7 事件明细导出阻断：{len(missing_refs)} 条保留边事件编号在阶段 1 原始事件中未命中，样例：{sample}"
        )

    events = sorted(
        exported_by_key.values(),
        key=lambda e: (
            -1 if e["start_ns"] is None else int(e["start_ns"]),
            int(e["event_id"]),
            str(e["rel_full"]),
            str(e["action"]),
        ),
    )

    entities: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        for kind, key in ((ev["src_kind"], ev["src_key"]), (ev["dst_kind"], ev["dst_key"])):
            vkey = f"{kind}:{key}"
            if vkey not in entities:
                entities[vkey] = dict(vertex_attrs.get(vkey) or {"kind": kind, "key": key})

    poi_events: List[str] = []
    for row in poi_rows:
        rel_short = normalize_rel(str(row.get("rel") or ""))
        src_label, dst_label = labels_of(rel_short)
        rel_full = f"{src_label}To{dst_label}"
        poi_id = f"{rel_full}:{int(row['event_id'])}:{str(row.get('action') or '')}"
        if poi_id not in poi_events:
            poi_events.append(poi_id)

    return {
        "format_version": EVENTS_EXPORT_FORMAT_VERSION,
        "scenario": scenario_name,
        "database": database,
        "poi_events": poi_events,
        "stats": {
            "retained_aggregated_edges": len(retained_entries),
            "confirmed_aggregated_edges": len(confirmed_edges),
            "unexcluded_aggregated_edges": len(unexcluded_edges),
            "retained_events": len(events),
            "entities": len(entities),
            "multi_membership_events": multi_membership_events,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "events": events,
        "entities": entities,
    }


def save_events_export(payload: Dict[str, Any], out_path: str | Path, *, overwrite: bool = False) -> Path:
    """将事件级明细原子写盘为 gzip 压缩 JSON（*.events.json.gz）。"""
    p = Path(out_path)
    if p.exists() and not overwrite:
        raise FileExistsError(f"事件明细文件已存在：{p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    try:
        with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=3) as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, p)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return p
