"""规则证据的结构检索通道（第二路）。

与 `graph_retrieve.retrieve_rules`（第一路：单边键匹配）并列：

- 第一路：拿束里每条边的 (系统调用, 源角色, 目标角色) 去匹配 Motif 的**某一个 hop**，
  命中即入候选，按 对齐类型 → 训练折查准率 → 攻击命中数 排序。
- 第二路：拿束内所有边在**束内能否走通**去匹配 Motif 的**整条 hop 序列**，
  按 全链走通 → 走通跳数 → 链长 → 训练折查准率 排序。

本模块只产出规则证据，不读 Technique / BehaviorObservable。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

MemberEdge = Tuple[str, str, str, str, str, str, str]   # (src, syscall, dst, src_role, dst_role, src_label, dst_label)

# 角色串首字母即顶点类型；规则库的角色档位（single/multi、usr/sys）跨场景不迁移，
# 实测束级全等匹配只有 3.4% 可用，顶点类型级有 62.4%，故按顶点类型比较。
LABEL_OF_ROLE = {"P": "Process", "F": "File", "N": "Network"}


def _syscalls_of(hop: Dict[str, Any]) -> set[str]:
    return {s for s in str(hop.get("syscall") or "").split("+") if s}


def walk_hops(hops: Sequence[Dict[str, Any]], edges: Sequence[MemberEdge]
              ) -> Tuple[int, int]:
    """返回 (走通跳数, 链长)。相邻两跳必须在束内共用中间端点。

    角色按字符串全等比较；hop 的系统调用字段允许 `a+b` 形式。
    """
    hops = [h for h in hops if h]
    if not hops:
        return 0, 0
    first = hops[0]
    want = _syscalls_of(first)
    l1 = LABEL_OF_ROLE.get(str(first.get("src_role"))[:1], "?")
    l2 = LABEL_OF_ROLE.get(str(first.get("dst_role"))[:1], "?")
    mids = {e[2] for e in edges if e[5] == l1 and e[6] == l2 and e[1] in want}
    if not mids:
        return 0, len(hops)
    if len(hops) == 1:
        return 1, 1
    second = hops[1]
    want2 = _syscalls_of(second)
    l2b = LABEL_OF_ROLE.get(str(second.get("src_role"))[:1], "?")
    l3 = LABEL_OF_ROLE.get(str(second.get("dst_role"))[:1], "?")
    ok = any(e[0] in mids and e[5] == l2b and e[6] == l3 and e[1] in want2 for e in edges)
    return (2 if ok else 1), len(hops)


class StructureIndex:
    """某一折全部 Motif 及其 hop 序列的内存索引（一次查询，进程内缓存）。"""

    def __init__(self, retriever: Any) -> None:
        self.retriever = retriever
        self._items: Optional[List[Dict[str, Any]]] = None

    def items(self) -> List[Dict[str, Any]]:
        if self._items is None:
            self._items = self.retriever.all_motifs()
        return self._items

    def rank(self, edges: Sequence[MemberEdge], limit: int
             ) -> List[Dict[str, Any]]:
        """按结构走通排序，返回与 `_rule_lines` 兼容的记录（entry_source=structure）。"""
        scored: List[Tuple[Tuple, Dict[str, Any]]] = []
        for it in self.items():
            hops = it.get("hops") or []
            walked, total = walk_hops(hops, edges)
            if walked == 0:
                continue
            motif = it.get("motif") or {}
            prec = motif.get("precision")
            key = (-int(walked == total), -int(walked), -int(total),
                   -(float(prec) if prec is not None else -1.0),
                   str(motif.get("motif_id") or ""))
            scored.append((key, {
                "g": {"motif": motif, "hops": hops, "alignment": 0,
                      "entry_source": "structure"},
                "exact": 0,
                "partial": 0,
                "entry_source": "structure",
                "structure": int(walked),
                "hops_total": int(total),
                "members": set(),
            }))
        scored.sort(key=lambda pair: pair[0])
        return [rec for _, rec in scored[:limit]]


def merge_rounds(primary: List[Dict[str, Any]], secondary: List[Dict[str, Any]],
                 keep_primary: int, keep_secondary: int) -> List[Dict[str, Any]]:
    """前 `keep_primary` 条主路记录 + 其后不与主路重复的 `keep_secondary` 条副路记录。"""
    out = list(primary[:keep_primary])
    seen = {str((r.get("g", {}).get("motif") or {}).get("motif_id") or "") for r in out}
    for rec in secondary:
        if len(out) >= keep_primary + keep_secondary:
            break
        mid = str((rec.get("g", {}).get("motif") or {}).get("motif_id") or "")
        if not mid or mid in seen:
            continue
        seen.add(mid)
        out.append(rec)
    return out
