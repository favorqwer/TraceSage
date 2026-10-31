"""规则准入：拓扑指纹、覆盖重放、边际查准率贪心。

准入判据不含任何数值阈值：
  - 选谁：边际查准率（新增攻击边 / 新增报告边）最高者，平局按拓扑指纹升序
  - 何时停：没有任何形态能带来新的攻击边
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from rules.coverage import Bitmask, CoverageStore, ScenarioShard


# ---------- 身份 ----------

def motif_fingerprint(motif: Dict[str, Any]) -> Tuple:
    """规范拓扑指纹：只由形态结构决定，与挖掘顺序、来源场景无关。"""
    from rules.offline import motif_signature
    return motif_signature(motif)


def motif_sort_key(motif: Dict[str, Any]) -> str:
    """可比较的稳定排序键。

    拓扑指纹是 tuple，1 跳与 2 跳的元数不同，直接比 tuple 依赖 Python 的
    逐元素比较规则（元素可能是 str 也可能是 tuple）。统一成 JSON 字符串，
    避免将来出现不可比较的类型组合。
    """
    return json.dumps(list(motif_fingerprint(motif)), ensure_ascii=False, sort_keys=True)


def motif_id(motif: Dict[str, Any]) -> str:
    """由拓扑指纹派生稳定编号。"""
    canonical = json.dumps(list(motif_fingerprint(motif)), ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"MOTIF_{digest}"


def assign_ids(motifs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """给每个形态写入稳定编号；同一指纹只出现一次。"""
    seen: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for m in motifs:
        mid = motif_id(m)
        if mid in seen:
            continue
        rec = dict(m)
        rec["id"] = mid
        rec["fingerprint"] = list(motif_fingerprint(m))
        seen[mid] = rec
        out.append(rec)
    return out


# ---------- 覆盖重放 ----------

def compute_hits(scenario_edges: Sequence[Dict[str, Any]],
                 motifs: Sequence[Dict[str, Any]],
                 rule_matcher: Any,
                 role_cuts: Any = None) -> Dict[str, List[int]]:
    """在给定场景的边列表上，算出每个形态匹配到的边下标。

    与在线匹配共用 MatchIndex，不做任何近似。
    """
    from rules.offline import TopologyFacts
    from rules.online import MatchIndex

    pool = list(scenario_edges)
    tf = TopologyFacts(pool)
    ctx = MatchIndex(pool, tf, role_cuts=role_cuts)
    by_key: Dict[Tuple[str, str, str], List[int]] = {}
    for idx, pe in enumerate(ctx.edges):
        by_key.setdefault(pe.key, []).append(idx)

    hits: Dict[str, List[int]] = {}
    for motif in motifs:
        matched = ctx.match([motif], admitted=None)
        idxs: List[int] = []
        for key in matched:
            idxs.extend(by_key.get(key, ()))
        if idxs:
            hits[str(motif["id"])] = sorted(set(idxs))
    return hits


def replay_missing(store: CoverageStore, motifs: Sequence[Dict[str, Any]],
                   rule_matcher: Any = None, role_cuts: Any = None) -> Dict[str, int]:
    """让形态在全部历史场景补齐位图：缺少记录的形态在各分片上重放匹配。

    返回 {形态编号: 新补的边数}。已经全部场景都有记录的形态跳过。
    """
    report: Dict[str, int] = {}
    for name in store.names():
        shard = store.shards[name]
        missing = [m for m in motifs if str(m["id"]) not in shard.hits]
        if not missing:
            continue
        edges = shard.edge_dicts()
        fresh = compute_hits(edges, missing, rule_matcher, role_cuts=role_cuts)
        for mid, idxs in fresh.items():
            shard.hits[mid] = list(idxs)
            report[mid] = report.get(mid, 0) + len(idxs)
        for m in missing:
            mid = str(m["id"])
            if mid not in shard.hits:
                shard.hits[mid] = []
    return report


# ---------- 贪心 ----------

def greedy_select(store: CoverageStore, motif_ids: Sequence[str],
                  sort_keys: Dict[str, str]) -> Dict[str, Any]:
    """边际查准率降序贪心。返回 trace 与 selected。"""
    pos = store.label_bitmap("pos")
    ignore = store.label_bitmap("ignore")
    reportable = ~pos & ~ignore          # 计入成本的位（neg）
    bitmaps: Dict[str, Bitmask] = {mid: store.rule_bitmap(mid) for mid in motif_ids}
    total_bits = store.total_keys()
    full = (1 << total_bits) - 1 if total_bits else 0

    covered = 0
    remaining = set(motif_ids)
    trace: List[Dict[str, Any]] = []

    while True:
        best: Optional[str] = None
        best_eff = -1.0
        best_gain = 0
        best_neg = 0
        best_ign = 0
        for mid in remaining:
            new = bitmaps[mid] & ~covered & full
            gain = (new & pos).bit_count()
            if gain == 0:
                continue
            neg = (new & reportable).bit_count()
            ign = (new & ignore).bit_count()
            report = gain + neg + ign
            eff = gain / report if report else 0.0
            if (eff > best_eff
                    or (eff == best_eff and best is not None
                        and sort_keys[mid] < sort_keys[best])):
                best, best_eff, best_gain, best_neg, best_ign = mid, eff, gain, neg, ign
        if best is None:
            break
        covered |= bitmaps[best]
        remaining.discard(best)
        trace.append({
            "step": len(trace) + 1,
            "rule": best,
            "gain": best_gain,
            "cost": best_neg,
            "ignore": best_ign,
            "report": best_gain + best_neg + best_ign,
            "efficiency": round(best_eff, 8),
            "cum_gain": (covered & pos).bit_count(),
            "cum_report": (covered & ~ignore).bit_count(),
        })

    pos_total = pos.bit_count()
    cov = (covered & pos).bit_count()
    return {
        "trace": trace,
        "selected": [t["rule"] for t in trace],
        "stats": {
            "candidate_rules": len(motif_ids),
            "selected_rules": len(trace),
            "global_key_count": total_bits,
            "pos_key_count": pos_total,
            "baseline_precision": round(pos_total / total_bits, 8) if total_bits else 0.0,
            "coverage_rate": round(cov / pos_total, 6) if pos_total else 0.0,
            "cum_report_edges": (covered & ~ignore).bit_count(),
        },
    }
