"""训练折规则的纯内存本地检索器（直接加载 output/rule-kg/v1/folds/<fold>.json，零 Neo4j 连接）。"""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import settings as cfg


def _fold_kg_path(fold: str, kg_dir: Optional[Path] = None) -> Path:
    base = Path(kg_dir) if kg_dir is not None else cfg.rule_kg_dir()
    return base / "folds" / f"{fold}.json"


class RuleGraphRetriever:
    """留一折规则的本地内存检索器（与历史 Neo4j 版接口和排序口径 100% 一致）。"""

    def __init__(
        self,
        uri: Optional[str] = None,
        auth: Optional[tuple[str, str]] = None,
        database: Optional[str] = None,
        fold: str = "",
        *,
        kg_dir: Optional[Path] = None,
    ) -> None:
        # 保留 uri/auth/database 位置参数以兼容旧调用方，内部完全不连接 Neo4j
        self.fold = str(fold)
        self.kg_path = _fold_kg_path(self.fold, kg_dir=kg_dir)
        self._motifs_by_id: Dict[str, Dict[str, Any]] = {}
        self._hops_by_mid: Dict[str, List[Dict[str, Any]]] = {}
        self._exact_index: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
        self._by_sc_src: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self._by_sc_dst: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self._load()

    def _load(self) -> None:
        if not self.kg_path.is_file():
            raise FileNotFoundError(f"本地规则知识快照缺失：{self.kg_path}")
        kg = json.loads(self.kg_path.read_text(encoding="utf-8"))
        fold = str(kg.get("fold_of") or self.fold)

        for m in kg.get("motifs") or []:
            mid = str(m["motif_id"])
            stats = m.get("stats") or {}
            self._motifs_by_id[mid] = {
                "uid": f"{fold}|{mid}",
                "fold": fold,
                "motif_id": mid,
                "name": str(m.get("name") or ""),
                "hops": int(m.get("hops") or 1),
                "admitted": bool(m.get("admitted")),
                "role_chain": list(m.get("role_chain") or []),
                "syscall_chain": list(m.get("syscall_chain") or []),
                "support_scenarios": list(m.get("support_scenarios") or []),
                "attack_hits": int(stats.get("attack_hits") or 0),
                "background_hits": int(stats.get("background_hits") or 0),
                "ignore_hits": int(stats.get("ignore_hits") or 0),
                "precision": stats.get("precision"),
                "source": str(m.get("source") or ""),
                "version": str(m.get("version") or ""),
            }
            self._hops_by_mid[mid] = []

        exact_sets: Dict[Tuple[str, str, str], set[str]] = defaultdict(set)
        src_sets: Dict[Tuple[str, str], set[str]] = defaultdict(set)
        dst_sets: Dict[Tuple[str, str], set[str]] = defaultdict(set)

        for h in kg.get("hops") or []:
            mid = str(h["motif_id"])
            if mid not in self._motifs_by_id:
                continue
            idx = int(h["index"])
            sc = str(h.get("syscall") or "")
            sr = str(h.get("src_role") or "")
            dr = str(h.get("dst_role") or "")
            self._hops_by_mid[mid].append({
                "uid": f"{fold}|{mid}|{idx}",
                "fold": fold,
                "motif_id": mid,
                "index": idx,
                "src_role": sr,
                "syscall": sc,
                "dst_role": dr,
            })
            exact_sets[(sc, sr, dr)].add(mid)
            src_sets[(sc, sr)].add(mid)
            dst_sets[(sc, dr)].add(mid)

        for mid, hops in self._hops_by_mid.items():
            hops.sort(key=lambda x: int(x["index"]))

        def _sort_key(mid: str) -> Tuple[float, int, str]:
            m = self._motifs_by_id[mid]
            prec = m.get("precision")
            return (
                -(float(prec) if prec is not None else -1.0),
                -int(m.get("attack_hits") or 0),
                mid,
            )

        for k, mids in exact_sets.items():
            self._exact_index[k] = sorted(mids, key=_sort_key)
        for k, mids in src_sets.items():
            self._by_sc_src[k] = sorted(mids, key=_sort_key)
        for k, mids in dst_sets.items():
            self._by_sc_dst[k] = sorted(mids, key=_sort_key)

    def close(self) -> None:
        return None

    def exact_motifs(self, src_role: str, syscall: str, dst_role: str, limit: int = 10) -> List[str]:
        return list(self._exact_index.get((syscall, src_role, dst_role), ())[:int(limit)])

    def expand_motif(self, motif_id: str) -> Optional[Dict[str, Any]]:
        m = self._motifs_by_id.get(str(motif_id))
        if m is None:
            return None
        hops = [dict(h) for h in self._hops_by_mid.get(str(motif_id), ())]
        cases = [
            {"case_id": str(cid), "attack_phases": "[]"}
            for cid in (m.get("support_scenarios") or [])
        ]
        return {"motif": dict(m), "hops": hops, "cases": cases}

    def all_motifs(self) -> List[Dict[str, Any]]:
        """本折全部 Motif 及其按 index 排好的 hop 序列（结构检索通道用，只读）。"""
        out: List[Dict[str, Any]] = []
        for mid in sorted(self._motifs_by_id):
            out.append({
                "motif": dict(self._motifs_by_id[mid]),
                "hops": [dict(h) for h in self._hops_by_mid.get(mid, ())],
            })
        return out

    def _rule_subgraph(self, motif_id: str, entry_source: str) -> Optional[Dict[str, Any]]:
        sub = self.expand_motif(motif_id)
        if not sub:
            return None
        sub["entry_source"] = entry_source
        sub["alignment"] = 2 if entry_source == "exact" else 1
        return sub

    @staticmethod
    def _rank_rule(g: Dict[str, Any]):
        m = g.get("motif") or {}
        prec = m.get("precision")
        return (-int(g.get("alignment") or 0),
                -(float(prec) if prec is not None else -1.0),
                -int(m.get("attack_hits") or 0),
                str(m.get("motif_id") or ""))

    def retrieve_rules(self, src_role: str, syscall: str, dst_role: str,
                       limit: int = 10) -> Dict[str, Any]:
        """只查蒸馏规则。精确：三项全同；部分：系统调用 + 至少一个角色。"""
        lim = int(limit)
        exact_ids = list(self._exact_index.get((syscall, src_role, dst_role), ())[:lim])
        exact_set = set(exact_ids)

        partial_pool: set[str] = set()
        partial_pool.update(self._by_sc_src.get((syscall, src_role), ()))
        partial_pool.update(self._by_sc_dst.get((syscall, dst_role), ()))
        partial_pool -= exact_set

        def _sort_key(mid: str) -> Tuple[float, int, str]:
            m = self._motifs_by_id[mid]
            prec = m.get("precision")
            return (
                -(float(prec) if prec is not None else -1.0),
                -int(m.get("attack_hits") or 0),
                mid,
            )

        partial_ids = sorted(partial_pool, key=_sort_key)[:lim]
        exact = [g for mid in exact_ids for g in [self._rule_subgraph(mid, "exact")] if g]
        partial = [g for mid in partial_ids for g in [self._rule_subgraph(mid, "partial")] if g]
        return {
            "exact": exact,
            "partial": partial,
            "motifs": sorted(exact + partial, key=self._rank_rule),
        }
