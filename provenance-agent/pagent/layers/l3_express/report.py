"""报告装配（表达层内部）：三段报告——已确认 / 未排除 / 已排除，不做任何挑选。

- **已确认**（报告字段 `edges`）：模型判「整束相关」的边，全部保留、按首次发生时间排序。
  含义与历史报告一致（评分工具读的就是它，按内容三元组评分）。段内再用 `class` 字段分两栏：
  `story`（解释链候选）与 `mechanism`（机制类：只读边 + 对象落在系统路径前缀里）。机制类
  **只分栏、不删除**——里面藏着读 `/etc/shadow`、`/etc/passwd` 这类凭据步骤。
- **未排除**（`unexcluded`）：已确认 + 其余未排除的边（含被闸门跳过、没轮到判、达到调用上限的）。
  它是**覆盖可证明**的那一段：只要「已排除」里没有相关边，它就覆盖候选前沿的全部可达步骤。
  每条边带 `origin`（`confirmed` / `kept`）说明它属于哪一档。
- **已排除**（`excluded`）：只有模型判「整束无关」的边——判定层的任何其它结论都不会删边。

报告字段与命名见 `provenance-agent/README.md`；评分口径只读 `edges` 的内容三元组。
"""

from __future__ import annotations

from typing import Any

from ...contracts import triple
from ...core import graph_facts
from .narrative import build_reflection, pick_entry_point, render_narrative

# 机制类的对象前缀：库 / 配置 / 设备 / 内核 / 缓存与包管理状态（只读边才参与分栏）
MECH_PREFIXES = ("/lib", "/usr/lib", "/usr/share", "/etc", "/dev", "/proc", "/sys",
                 "/var/cache", "/var/lib/dpkg", "/run")


def mechanism_class(edge: dict[str, Any]) -> bool:
    """这条边是不是「机制类」：只读边，且对象端落在系统路径前缀里。

    只读边里藏着凭据读取等真步骤，所以机制类只从「已确认」里分出去另列一栏，不从报告里删除。
    """
    if not set(edge.get("rels") or ()) <= set(graph_facts.CONSUMER_RELS):
        return False
    src_label = str(edge.get("src_label") or "")
    dst_label = str(edge.get("dst_label") or "")
    obj = edge.get("src") if src_label != "Process" else edge.get("dst")
    label = src_label if src_label != "Process" else dst_label
    return label == "File" and str(obj).startswith(MECH_PREFIXES)


def _edge_record(edge: dict[str, Any], *, origin: str, edge_class: str = "") -> dict[str, Any]:
    """一条边写进报告的形状：两端与操作名，加上证据与归属信息。"""
    record = {"src": edge["src"], "syscall": edge["syscall"], "dst": edge["dst"]}
    record.update({
        "event_id": int((edge.get("event_ids") or [0])[0]),
        "instances": edge.get("instances"), "bytes": edge.get("bytes"),
        "process_id": edge.get("process_id"), "origin": origin,
        "reason": edge.get("verdict_reason"),
    })
    if edge_class:
        record["class"] = edge_class
    return record


def build_report(inv: Any, *, poi: dict[str, Any], stats: dict[str, Any], stop_reason: str,
                 expand_rounds: int) -> dict[str, Any]:
    """把调查记录装配成三段报告。"""
    order = lambda edge: (int(edge.get("t0") or 0), triple(edge))
    confirmed_edges = sorted(inv.confirmed.values(), key=order)
    kept_edges = sorted(inv.kept.values(), key=order)
    excluded_edges = sorted(inv.excluded.values(), key=order)

    edges: list[dict[str, Any]] = []
    story = mechanism = 0
    for edge in confirmed_edges:
        is_mech = mechanism_class(edge)
        story += 0 if is_mech else 1
        mechanism += 1 if is_mech else 0
        edges.append(_edge_record(edge, origin="confirmed",
                                  edge_class="mechanism" if is_mech else "story"))
    unexcluded = ([_edge_record(edge, origin="confirmed") for edge in confirmed_edges]
                  + [_edge_record(edge, origin="kept") for edge in kept_edges])
    excluded = [_edge_record(edge, origin="excluded") for edge in excluded_edges]

    gaps: list[dict[str, Any]] = []
    gaps.extend({"label": g["label"], "next_action": g.get("next_action"), "status": g["status"]}
                for g in inv.gaps)

    selfcheck = {
        "origin_complete": all(key in inv.origin for key in inv.edges),
        "confirmed_subset_of_unexcluded": set(inv.confirmed) <= set(inv.unexcluded()),
        "unexcluded_plus_excluded_is_candidates": (len(inv.unexcluded()) + len(inv.excluded)
                                                   == len(inv.edges)),
        "confirmed_split_is_disjoint_and_complete": (story + mechanism == len(edges)),
    }
    stats = dict(stats)
    stats.update({
        "expand_rounds": expand_rounds,
        "processes_examined": len(inv.process_context),
        "candidates": len(inv.edges),
        "confirmed_triples": len(edges),
        "story_triples": story,
        "mechanical_triples": mechanism,
        "kept_triples": len(kept_edges),
        "unexcluded_triples": len(unexcluded),
        "excluded_triples": len(excluded),
        "selfcheck": selfcheck,
        "state": inv.stats(),
    })
    return {
        "scenario": inv.scenario,
        "run_id": inv.run_id,
        "poi": poi,
        "edges": edges,
        "unexcluded": unexcluded,
        "excluded": excluded,
        "narrative": render_narrative(edges),
        "entry_point": pick_entry_point(confirmed_edges),
        "gaps": gaps,
        "hypotheses": [{"key": h["key"], "label": h["label"], "status": h["status"]} for h in inv.hypotheses],
        "reflection": build_reflection(stop_reason, expand_rounds),
        "stop_reason": stop_reason,
        "selection_note": (f"三段报告：已确认 {len(edges)} 条（解释链候选 {story} / 机制类 {mechanism}）；"
                           f"未排除 {len(unexcluded)} 条（覆盖可证明的那一段）；"
                           f"已排除 {len(excluded)} 条（只有判「整束无关」的边）"),
        "generated_by": "deterministic_reporter",
        "stats": stats,
    }
