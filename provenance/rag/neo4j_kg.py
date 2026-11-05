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
            s.run(f"CREATE DATABASE `{self.database}` IF NOT EXISTS").consume()
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
            "CREATE CONSTRAINT technique_uid IF NOT EXISTS FOR (n:Technique) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT tactic_uid IF NOT EXISTS FOR (n:Tactic) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT case_uid IF NOT EXISTS FOR (n:Case) REQUIRE n.uid IS UNIQUE",
            "CREATE CONSTRAINT observable_uid IF NOT EXISTS FOR (n:BehaviorObservable) REQUIRE n.uid IS UNIQUE",
            "CREATE INDEX motif_fold IF NOT EXISTS FOR (n:Motif) ON (n.fold)",
            "CREATE INDEX hop_fold IF NOT EXISTS FOR (n:Hop) ON (n.fold)",
        ]
        with self.driver.session(database=self.database) as s:
            for stmt in stmts:
                s.run(stmt).consume()

    # ---------- 导入 ----------
    def import_attack(self, attack: Dict[str, Any], *, version: str = "attack-v1",
                      replace: bool = False) -> None:
        """导入全局 ATT&CK 快照（技术、战术、行为观测）。

        这三类内容与折无关，每个折完全相同，只存一份；折隔离只作用于
        Motif/Hop/Case。Motif 到 Technique 的 IMPLEMENTS 链接仍由
        `import_fold` 按折导入。
        """
        tactics = []
        for tid, rec in (attack.get("tactics") or {}).items():
            tactics.append({
                "uid": f"TACTIC|{tid}", "tactic_id": tid,
                "name": rec.get("name", ""), "shortname": rec.get("shortname", ""),
                "description": rec.get("description", ""), "version": version,
            })
        techniques = []
        for tid, rec in (attack.get("techniques") or {}).items():
            techniques.append({
                "uid": f"TECH|{tid}", "attack_id": tid,
                "name": rec.get("name", ""), "tactics": rec.get("tactics") or [],
                "description": rec.get("description", ""), "url": rec.get("url", ""),
                "stix_version": rec.get("stix_version", ""), "version": version,
            })
        observables = []
        for obs in attack.get("observables") or []:
            role_prefixes = sorted({
                str(p).split(".", 1)[0] for p in (obs.get("role_pattern") or [])
            })
            observables.append({
                "uid": f"OBS|{obs.get('observable_id')}",
                "observable_id": obs.get("observable_id", ""),
                "technique_id": obs.get("technique_id", ""),
                "description": obs.get("description", ""),
                "syscall_pattern": obs.get("syscall_pattern") or [],
                "role_patterns": [str(p) for p in (obs.get("role_pattern") or [])],
                "role_prefixes": role_prefixes,
                "process_pattern": obs.get("process_pattern") or [],
                "path_pattern": obs.get("path_pattern") or [],
                "confidence": float(obs.get("confidence") or 0.0),
                "source": obs.get("source", ""),
                "observable": bool(obs.get("observable", True)),
                "verified": bool(obs.get("verified", False)),
                "version": version,
            })
        with self.driver.session(database=self.database) as s:
            if replace:
                s.run("MATCH (n) WHERE n:Technique OR n:Tactic OR n:BehaviorObservable "
                      "DETACH DELETE n").consume()
            for batch in _batches(tactics):
                s.run("UNWIND $rows AS r MERGE (n:Tactic {uid:r.uid}) SET n += r", rows=list(batch)).consume()
            for batch in _batches(techniques):
                s.run("UNWIND $rows AS r MERGE (n:Technique {uid:r.uid}) SET n += r", rows=list(batch)).consume()
            for batch in _batches(observables):
                s.run("UNWIND $rows AS r MERGE (n:BehaviorObservable {uid:r.uid}) SET n += r",
                      rows=list(batch)).consume()
            s.run(
                "UNWIND $rows AS r "
                "MATCH (n:Technique {uid:r.uid}) "
                "UNWIND r.tactics AS shortname "
                "MATCH (t:Tactic {shortname:shortname}) "
                "MERGE (n)-[:BELONGS_TO]->(t)",
                rows=[{"uid": f"TECH|{tid}", "tactics": rec.get("tactics") or []}
                      for tid, rec in (attack.get("techniques") or {}).items()]).consume()
            s.run(
                "UNWIND $rows AS r "
                "MATCH (o:BehaviorObservable {uid:r.uid}) "
                "MATCH (t:Technique {attack_id:r.technique_id}) "
                "MERGE (o)-[:OBSERVES]->(t)",
                rows=[{"uid": f"OBS|{obs.get('observable_id')}",
                       "technique_id": obs.get("technique_id", "")}
                      for obs in attack.get("observables") or []]).consume()

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
        links = []
        for m in kg.get("motifs") or []:
            for link in m.get("techniques") or []:
                links.append({
                    "motif_uid": f"{fold}|{m['motif_id']}",
                    "tech_uid": f"TECH|{link.get('technique_id')}",
                    "fold": fold,
                    "confidence": float(link.get("confidence") or 0.0),
                    "evidence": link.get("evidence", ""),
                    "source": link.get("source", ""),
                    "verified": bool(link.get("verified", False)),
                    "technique_id": link.get("technique_id", ""),
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
            s.run("MATCH (m:Motif {fold:$fold})-[r:IMPLEMENTS]->() DELETE r",
                  fold=fold).consume()
            for batch in _batches(links):
                s.run(
                    "UNWIND $rows AS r "
                    "MATCH (m:Motif {uid:r.motif_uid}) MATCH (t:Technique {uid:r.tech_uid}) "
                    "MERGE (m)-[e:IMPLEMENTS]->(t) SET e.confidence=r.confidence, "
                    "e.evidence=r.evidence, e.source=r.source, e.verified=r.verified",
                    rows=list(batch)).consume()
            s.run("MATCH (m:Motif {fold:$fold})-[r:DERIVED_FROM]->() DELETE r",
                  fold=fold).consume()
            for batch in _batches(derived):
                s.run(
                    "UNWIND $rows AS r "
                    "MATCH (m:Motif {uid:r.motif_uid}) MATCH (c:Case {uid:r.case_uid}) "
                    "MERGE (m)-[:DERIVED_FROM]->(c)",
                    rows=list(batch)).consume()

    def counts(self, fold: Optional[str] = None) -> Dict[str, int]:
        """统计。全局节点（Technique/Tactic/BehaviorObservable）不带折；
        折内节点（Motif/Hop/Case）与折内关系按 fold 过滤。"""
        out: Dict[str, int] = {}
        with self.driver.session(database=self.database) as s:
            for label in ("Technique", "Tactic", "BehaviorObservable"):
                rec = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()
                out[label] = int(rec["c"]) if rec else 0
            for label in ("Motif", "Hop", "Case"):
                query = f"MATCH (n:{label})"
                params: Dict[str, Any] = {}
                if fold:
                    query += " WHERE n.fold = $fold"
                    params["fold"] = fold
                rec = s.run(query + " RETURN count(n) AS c", **params).single()
                out[label] = int(rec["c"]) if rec else 0
            fold_rels = {
                "HAS_HOP": "m:Motif",
                "NEXT_HOP": "a:Hop",
                "IMPLEMENTS": "m:Motif",
                "DERIVED_FROM": "m:Motif",
            }
            for rel, var in fold_rels.items():
                query = f"MATCH ({var})-[r:{rel}]->()"
                params = {}
                if fold:
                    query += f" WHERE {var.split(':')[0]}.fold = $fold"
                    params["fold"] = fold
                rec = s.run(query + " RETURN count(r) AS c", **params).single()
                out[rel] = int(rec["c"]) if rec else 0
            for rel in ("BELONGS_TO", "OBSERVES"):
                rec = s.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()
                out[rel] = int(rec["c"]) if rec else 0
        return out
