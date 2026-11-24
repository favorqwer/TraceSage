"""Rule KG 的 Neo4j 入库与查询。

与溯源图库（attack-*-v2）完全隔离，使用独立数据库 `trace-rules-kg-v1`。
每折数据用 `fold` 属性隔离；查询必须带 `fold` 条件，禁止跨折读取。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from neo4j import GraphDatabase

DEFAULT_DATABASE = "trace-rules-kg-v1"


def _batches(items: Sequence[Any], size: int = 500) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


class RuleKGStore:
    def __init__(self, uri: str, auth: tuple[str, str], database: str = DEFAULT_DATABASE):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        self.database = database

    def close(self) -> None:
        self.driver.close()

    def ensure_database(self) -> None:
        with self.driver.session(database="system") as s:
            s.run("CREATE DATABASE $name IF NOT EXISTS", name=self.database).consume()
        for _ in range(30):
            with self.driver.session(database="system") as s:
                rec = s.run(
                    "SHOW DATABASES YIELD name, currentStatus "
                    "WHERE name = $name RETURN currentStatus",
                    name=self.database).single()
            if rec and str(rec["currentStatus"]).lower() == "online":
                return
            time.sleep(1)
        raise RuntimeError(f"数据库未上线：{self.database}")

    def create_constraints(self) -> None:
        stmts = [
            "CREATE CONSTRAINT motif_uid IF NOT EXISTS FOR (n:Motif) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT hop_uid IF NOT EXISTS FOR (n:Hop) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT case_uid IF NOT EXISTS FOR (n:Case) REQUIRE n.uid IS UNIQUE",
            "CREATE INDEX motif_fold IF NOT EXISTS FOR (n:Motif) ON (n.fold)",
            "CREATE INDEX hop_fold IF NOT EXISTS FOR (n:Hop) ON (n.fold)",
        ]
        with self.driver.session(database=self.database) as s:
            for stmt in stmts:
                s.run(stmt).consume()

    # ---------- 导入 ----------

    def import_cases(self, fold: str, cases: Dict[str, Dict[str, Any]]) -> None:
        rows = []
        for cid, rec in cases.items():
            rows.append({
                "uid": f"{fold}|{cid}", "fold": fold, "case_id": cid,
                "description": rec.get("description", ""),
                "attack_phases": json.dumps(rec.get("attack_phases") or [], ensure_ascii=False),
            })
        if not rows:
            return
        with self.driver.session(database=self.database) as s:
            for batch in _batches(rows):
                s.run("UNWIND $rows AS r MERGE (n:Case {uid:r.uid}) SET n += r", rows=list(batch)).consume()

    def import_fold(self, kg: Dict[str, Any]) -> None:
        fold = str(kg["fold_of"])
        motifs = []
        for m in kg.get("motifs") or []:
            stats = m.get("stats") or {}
            motifs.append({
                "uid": f"{fold}|{m['motif_id']}", "fold": fold,
                "motif_id": m["motif_id"], "name": m.get("name", ""),
                "hops": int(m.get("hops") or 1), "admitted": bool(m.get("admitted")),
                "role_chain": m.get("role_chain") or [],
                "syscall_chain": m.get("syscall_chain") or [],
                "support_scenarios": m.get("support_scenarios") or [],
                "attack_hits": int(stats.get("attack_hits") or 0),
                "background_hits": int(stats.get("background_hits") or 0),
                "ignore_hits": int(stats.get("ignore_hits") or 0),
                "precision": stats.get("precision"),
                "source": m.get("source", ""), "version": m.get("version", ""),
            })
        hops = []
        for h in kg.get("hops") or []:
            idx = int(h["index"])
            hops.append({
                "uid": f"{fold}|{h['motif_id']}|{idx}", "fold": fold,
                "motif_id": h["motif_id"], "index": idx,
                "src_role": h.get("src_role", ""), "syscall": h.get("syscall", ""),
                "dst_role": h.get("dst_role", ""),
            })
        derived = []
        for m in kg.get("motifs") or []:
            for case_id in m.get("support_scenarios") or []:
                derived.append({
                    "motif_uid": f"{fold}|{m['motif_id']}",
                    "case_uid": f"{fold}|{case_id}",
                    "fold": fold,
                })
        with self.driver.session(database=self.database) as s:
            for batch in _batches(motifs):
                s.run("UNWIND $rows AS r MERGE (n:Motif {uid:r.uid}) SET n += r", rows=list(batch)).consume()
            for batch in _batches(hops):
                s.run("UNWIND $rows AS r MERGE (n:Hop {uid:r.uid}) SET n += r", rows=list(batch)).consume()
            s.run(
                "UNWIND $rows AS r "
                "MATCH (m:Motif {uid:r.motif_uid}) MATCH (h:Hop {uid:r.hop_uid}) "
                "MERGE (m)-[e:HAS_HOP]->(h) SET e.index = r.index",
                rows=[{"motif_uid": f"{fold}|{h['motif_id']}",
                       "hop_uid": f"{fold}|{h['motif_id']}|{int(h['index'])}",
                       "index": int(h["index"])} for h in kg.get("hops") or []]).consume()
            s.run(
                "UNWIND $rows AS r "
                "MATCH (a:Hop {uid:r.a}) MATCH (b:Hop {uid:r.b}) "
                "MERGE (a)-[e:NEXT_HOP]->(b) SET e.index = r.index",
                rows=[{"a": f"{fold}|{m['motif_id']}|{i}",
                       "b": f"{fold}|{m['motif_id']}|{i + 1}", "index": i}
                      for m in kg.get("motifs") or []
                      for i in range(1, int(m.get("hops") or 1))]).consume()
            s.run("MATCH (m:Motif {fold:$fold})-[r:DERIVED_FROM]->() DELETE r",
                  fold=fold).consume()
            for batch in _batches(derived):
                s.run(
                    "UNWIND $rows AS r "
                    "MATCH (m:Motif {uid:r.motif_uid}) MATCH (c:Case {uid:r.case_uid}) "
                    "MERGE (m)-[:DERIVED_FROM]->(c)",
                    rows=list(batch)).consume()

    def counts(self, fold: Optional[str] = None) -> Dict[str, int]:
        """按折统计规则、步骤、训练场景及其关系。"""
        out: Dict[str, int] = {}
        with self.driver.session(database=self.database) as s:
            for label in ("Motif", "Hop", "Case"):
                rec = s.run(
                    "MATCH (n) WHERE $label IN labels(n) "
                    "AND ($fold IS NULL OR n.fold = $fold) RETURN count(n) AS c",
                    label=label, fold=fold).single()
                out[label] = int(rec["c"]) if rec else 0
            for rel in ("HAS_HOP", "NEXT_HOP", "DERIVED_FROM"):
                rec = s.run(
                    "MATCH (a)-[r]->() WHERE type(r) = $rel "
                    "AND ($fold IS NULL OR a.fold = $fold) RETURN count(r) AS c",
                    rel=rel, fold=fold).single()
                out[rel] = int(rec["c"]) if rec else 0
        return out
