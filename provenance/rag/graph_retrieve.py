"""训练折规则的图查询。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase


class RuleGraphRetriever:
    def __init__(self, uri: str, auth: tuple[str, str], database: str, fold: str):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        self.database = database
        self.fold = fold

    def close(self) -> None:
        self.driver.close()

    def _session(self):
        return self.driver.session(database=self.database)

    def exact_motifs(self, src_role: str, syscall: str, dst_role: str, limit: int = 10) -> List[str]:
        with self._session() as s:
            rows = s.run(
                """
                MATCH (m:Motif {fold:$fold})-[:HAS_HOP]->(h:Hop)
                WHERE h.syscall = $sc AND h.src_role = $src_role AND h.dst_role = $dst_role
                RETURN DISTINCT m.motif_id AS mid
                LIMIT $limit
                """,
                fold=self.fold, sc=syscall, src_role=src_role, dst_role=dst_role,
                limit=int(limit)).data()
        return [str(r["mid"]) for r in rows]

    def expand_motif(self, motif_id: str) -> Optional[Dict[str, Any]]:
        query = """
                MATCH (m:Motif {fold:$fold, motif_id:$mid})-[:HAS_HOP]->(h:Hop)
                WITH m, h ORDER BY h.index
                WITH m, collect(h{.*}) AS hops
                OPTIONAL MATCH (m)-[:DERIVED_FROM]->(c:Case {fold:$fold})
                RETURN m{.*} AS motif, hops,
                       collect(DISTINCT {case_id:c.case_id, attack_phases:c.attack_phases}) AS cases
                """
        with self._session() as s:
            rec = s.run(query, fold=self.fold, mid=motif_id).single()
        if not rec:
            return None
        return {"motif": dict(rec["motif"]),
                "hops": [dict(h) for h in rec["hops"]],
                "cases": [dict(c) for c in rec["cases"] if c.get("case_id")]}

    def all_motifs(self) -> List[Dict[str, Any]]:
        """本折全部 Motif 及其按 index 排好的 hop 序列（结构检索通道用，只读）。"""
        with self._session() as s:
            rows = s.run(
                """
                MATCH (m:Motif {fold:$fold})-[:HAS_HOP]->(h:Hop)
                WITH m, h ORDER BY h.index
                WITH m, collect(h{.*}) AS hops
                RETURN m{.*} AS motif, hops
                ORDER BY m.motif_id
                """,
                fold=self.fold).data()
        return [{"motif": dict(r["motif"]),
                 "hops": [dict(h) for h in (r["hops"] or [])]} for r in rows]

    # ---------- 规则证据：只读 Motif/Hop ----------
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
        """只查蒸馏规则。精确：三项全同；部分：系统调用 + 至少一个角色。

        """
        with self._session() as s:
            exact_rows = s.run(
                """
                MATCH (m:Motif {fold:$fold})-[:HAS_HOP]->(h:Hop)
                WHERE h.syscall = $sc AND h.src_role = $src_role AND h.dst_role = $dst_role
                WITH DISTINCT m
                RETURN m.motif_id AS mid
                ORDER BY coalesce(m.precision, -1) DESC,
                         coalesce(m.attack_hits, 0) DESC, mid
                LIMIT $limit
                """,
                fold=self.fold, sc=syscall, src_role=src_role, dst_role=dst_role,
                limit=int(limit)).data()
            exact_ids = [str(r["mid"]) for r in exact_rows]
            partial_rows = s.run(
                """
                MATCH (m:Motif {fold:$fold})-[:HAS_HOP]->(h:Hop)
                WHERE h.syscall = $sc
                  AND (h.src_role = $src_role OR h.dst_role = $dst_role)
                  AND NOT m.motif_id IN $exclude
                WITH DISTINCT m
                RETURN m.motif_id AS mid
                ORDER BY coalesce(m.precision, -1) DESC,
                         coalesce(m.attack_hits, 0) DESC, mid
                LIMIT $limit
                """,
                fold=self.fold, sc=syscall, src_role=src_role, dst_role=dst_role,
                exclude=exact_ids, limit=int(limit)).data()
            partial_ids = [str(r["mid"]) for r in partial_rows]
        exact = [g for mid in exact_ids for g in [self._rule_subgraph(mid, "exact")] if g]
        partial = [g for mid in partial_ids for g in [self._rule_subgraph(mid, "partial")] if g]
        return {
            "exact": exact,
            "partial": partial,
            "motifs": sorted(exact + partial, key=self._rank_rule),
        }
