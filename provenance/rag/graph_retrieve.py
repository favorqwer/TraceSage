"""规则知识图谱的图优先检索。

入口不是文本向量，而是：
1. Hop 节点精确查询 (src_role, syscall, dst_role)；
2. BehaviorObservable -> Technique -> Motif 反向图查询；
3. 命中后沿 HAS_HOP / IMPLEMENTS / DERIVED_FROM 扩展出规则子图。

向量检索只作为可选的第三入口，不替代图查询。
"""
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

    def technique_entry(self, syscall: str, src_label: str, dst_label: str,
                        src_role: str, dst_role: str,
                        programs: Optional[List[str]] = None,
                        limit: int = 10) -> Dict[str, Any]:
        programs = list(programs or [])
        with self._session() as s:
            techs = s.run(
                """
                MATCH (o:BehaviorObservable)-[:OBSERVES]->(t:Technique)
                WHERE ($sc IN o.syscall_pattern
                       AND (size(o.role_prefixes) = 0
                            OR $src_label IN o.role_prefixes
                            OR $dst_label IN o.role_prefixes))
                   OR (size(o.process_pattern) > 0
                       AND ANY(p IN o.process_pattern
                               WHERE ANY(prog IN $programs WHERE prog CONTAINS p)))
                WITH t, max(o.confidence) AS confidence
                RETURN t.attack_id AS attack_id, t.name AS name, confidence
                ORDER BY confidence DESC, attack_id
                LIMIT $limit
                """,
                sc=syscall, src_label=src_label, dst_label=dst_label,
                programs=programs, limit=int(limit)).data()
            ids = [str(r["attack_id"]) for r in techs]
            if not ids:
                return {"techniques": [], "motifs": []}
            # 结构约束：Motif 必须有一个 Hop 与边 syscall 一致，且至少一个角色一致。
            # 否则只是「技术上相关」，不是「这条边的规则证据」。
            motifs = s.run(
                """
                MATCH (m:Motif {fold:$fold})-[:IMPLEMENTS]->(t:Technique)
                WHERE t.attack_id IN $ids
                MATCH (m)-[:HAS_HOP]->(h:Hop)
                WHERE h.syscall = $sc
                  AND (h.src_role = $src_role OR h.dst_role = $dst_role)
                RETURN DISTINCT m.motif_id AS mid
                LIMIT $limit
                """,
                fold=self.fold, ids=ids, sc=syscall,
                src_role=src_role, dst_role=dst_role,
                limit=int(limit)).data()
        return {
            "techniques": [{"attack_id": r["attack_id"], "name": r["name"],
                            "confidence": r.get("confidence", 0.0)} for r in techs],
            "motifs": [str(r["mid"]) for r in motifs],
        }

    def expand_motif(self, motif_id: str, *, include_techniques: bool = True) -> Optional[Dict[str, Any]]:
        if include_techniques:
            query = """
                MATCH (m:Motif {fold:$fold, motif_id:$mid})-[:HAS_HOP]->(h:Hop)
                WITH m, h ORDER BY h.index
                WITH m, collect(h{.*}) AS hops
                OPTIONAL MATCH (m)-[i:IMPLEMENTS]->(t:Technique)
                OPTIONAL MATCH (m)-[:DERIVED_FROM]->(c:Case {fold:$fold})
                RETURN m{.*} AS motif, hops,
                       collect(DISTINCT {attack_id:t.attack_id, name:t.name,
                                         confidence:i.confidence, verified:i.verified}) AS techniques,
                       collect(DISTINCT {case_id:c.case_id, attack_phases:c.attack_phases}) AS cases
                """
        else:
            query = """
                MATCH (m:Motif {fold:$fold, motif_id:$mid})-[:HAS_HOP]->(h:Hop)
                WITH m, h ORDER BY h.index
                WITH m, collect(h{.*}) AS hops
                OPTIONAL MATCH (m)-[:DERIVED_FROM]->(c:Case {fold:$fold})
                RETURN m{.*} AS motif, hops, [] AS techniques,
                       collect(DISTINCT {case_id:c.case_id, attack_phases:c.attack_phases}) AS cases
                """
        with self._session() as s:
            rec = s.run(query, fold=self.fold, mid=motif_id).single()
        if not rec:
            return None
        techniques = [t for t in rec["techniques"] if t.get("attack_id")]
        return {
            "motif": dict(rec["motif"]),
            "hops": [dict(h) for h in rec["hops"]],
            "techniques": techniques,
            "cases": [dict(c) for c in rec["cases"] if c.get("case_id")],
        }

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
        sub = self.expand_motif(motif_id, include_techniques=False)
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

        不读 Technique / BehaviorObservable，不生成技术证据。
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

    # ---------- 技术证据：只读 BehaviorObservable/Technique ----------
    @staticmethod
    def _role_hit(patterns: List[str], src_role: str, dst_role: str) -> str:
        for pattern in patterns:
            p = str(pattern or "")
            if p and (str(src_role).startswith(p) or str(dst_role).startswith(p)):
                return p
        return ""

    def retrieve_techniques(self, syscall: str, src_role: str, dst_role: str,
                            src_label: str = "", dst_label: str = "",
                            programs: Optional[List[str]] = None,
                            paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """只查 ATT&CK 技术，不读 Motif/Hop，不把技术转成规则。

        T-强：系统调用 + 完整角色前缀匹配。
        T-弱：只有进程名或路径匹配，或观测本身只有系统调用条件。
        """
        programs = [str(x) for x in (programs or [])]
        paths = [str(x) for x in (paths or []) if x]
        with self._session() as s:
            rows = s.run(
                """
                MATCH (o:BehaviorObservable)-[:OBSERVES]->(t:Technique)
                WHERE $sc IN o.syscall_pattern
                RETURN o.observable_id AS observable_id,
                       coalesce(o.role_patterns, []) AS role_patterns,
                       coalesce(o.role_prefixes, []) AS role_prefixes,
                       coalesce(o.process_pattern, []) AS process_pattern,
                       coalesce(o.path_pattern, []) AS path_pattern,
                       coalesce(o.confidence, 0.0) AS confidence,
                       coalesce(o.verified, false) AS verified,
                       t.attack_id AS attack_id, t.name AS name,
                       coalesce(t.tactics, []) AS tactics
                """,
                sc=syscall).data()
        by_tech: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            role_patterns = [str(x) for x in (row.get("role_patterns") or [])]
            role_prefixes = [str(x) for x in (row.get("role_prefixes") or [])]
            if role_patterns:
                role_hit = self._role_hit(role_patterns, src_role, dst_role)
            else:
                role_hit = self._role_hit(role_prefixes, src_label, dst_label)
            process_hit = next(
                (str(p) for p in (row.get("process_pattern") or [])
                 for prog in programs if str(p).lower() in prog.lower()), "")
            path_hit = next(
                (str(p) for p in (row.get("path_pattern") or [])
                 for path in paths if str(p) in path), "")
            has_pattern = bool(role_patterns or role_prefixes
                               or (row.get("process_pattern") or [])
                               or (row.get("path_pattern") or []))
            if role_hit:
                strong = True
            elif process_hit or path_hit or not has_pattern:
                strong = False
            else:
                continue
            tid = str(row.get("attack_id") or "")
            if not tid:
                continue
            rec = by_tech.setdefault(tid, {
                "attack_id": tid, "name": str(row.get("name") or ""),
                "tactics": [str(x) for x in (row.get("tactics") or [])],
                "strong": False,
                "strong_observable_ids": set(), "weak_observable_ids": set(),
                "strong_conditions": set(), "weak_conditions": set(),
                "observable_ids": set(), "conditions": set(),
                "confidence": 0.0, "verified": False,
            })
            oid = str(row.get("observable_id") or "")
            if role_hit:
                cond = f"角色 {role_hit} 匹配"
            elif process_hit:
                cond = f"进程 {process_hit} 匹配"
            elif path_hit:
                cond = f"路径 {path_hit} 匹配"
            else:
                cond = "仅系统调用匹配"
            rec["strong"] = rec["strong"] or strong
            rec["observable_ids"].add(oid)
            rec["conditions"].add(cond)
            if strong:
                rec["strong_observable_ids"].add(oid)
                rec["strong_conditions"].add(cond)
            else:
                rec["weak_observable_ids"].add(oid)
                rec["weak_conditions"].add(cond)
            rec["confidence"] = max(rec["confidence"], float(row.get("confidence") or 0.0))
            rec["verified"] = rec["verified"] or bool(row.get("verified"))

        def rank(rec: Dict[str, Any]):
            return (-float(rec["confidence"]), -len(rec["observable_ids"]),
                    -len(rec["conditions"]), str(rec["attack_id"]))

        strong = sorted([r for r in by_tech.values() if r["strong"]], key=rank)
        weak = sorted([r for r in by_tech.values() if not r["strong"]], key=rank)
        for rec in strong + weak:
            for key in ("observable_ids", "conditions",
                        "strong_observable_ids", "weak_observable_ids",
                        "strong_conditions", "weak_conditions"):
                rec[key] = sorted(rec[key])
        return {"strong": strong, "weak": weak, "techniques": strong}

    def retrieve_for_edge(self, src_role: str, syscall: str, dst_role: str,
                          src_label: str, dst_label: str,
                          programs: Optional[List[str]] = None,
                          limit: int = 10) -> Dict[str, Any]:
        """返回 {exact: [...], technique: [...], technique_only: [...]}，每项是子图或技术。"""
        exact_ids = self.exact_motifs(src_role, syscall, dst_role, limit=limit)
        tech = self.technique_entry(syscall, src_label, dst_label,
                                    src_role, dst_role, programs=programs, limit=limit)
        tech_ids = [mid for mid in tech["motifs"] if mid not in set(exact_ids)]

        exact = []
        for mid in exact_ids:
            sub = self.expand_motif(mid)
            if sub:
                sub["entry_source"] = "hop"
                sub["alignment"] = 2
                exact.append(sub)
        from_tech = []
        for mid in tech_ids:
            sub = self.expand_motif(mid)
            if sub:
                sub["entry_source"] = "technique"
                sub["alignment"] = 1
                from_tech.append(sub)

        def rank_key(g: Dict[str, Any]):
            m = g.get("motif") or {}
            prec = m.get("precision")
            return (-int(g.get("alignment") or 0),
                    -(float(prec) if prec is not None else 0.0),
                    -int(m.get("attack_hits") or 0),
                    str(m.get("motif_id") or ""))

        exact.sort(key=rank_key)
        from_tech.sort(key=rank_key)
        return {
            "exact": exact,
            "technique": from_tech,
            "motifs": sorted(exact + from_tech, key=rank_key),
            "technique_only": tech["techniques"] if not tech["motifs"] else [],
            "technique_candidates": tech["techniques"],
        }
