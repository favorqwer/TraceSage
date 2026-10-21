"""Read-only Neo4j connection and audited query execution."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from neo4j import GraphDatabase

from common import fail, load_dotenv
from facts import effect_of


def _projected_row(rec: dict[str, Any]) -> dict[str, Any]:
    """Build the small row needed by validation from projected properties."""
    def key(kind: str, host: Any, container: Any, content: Any) -> str:
        if kind == "Process":
            return f"p:{host}/{container}:{content or '<NA>'}"
        if kind == "File":
            return f"f:{host}/{container}:{content}"
        if kind == "Network":
            return f"n:{host}:{content}"
        return f"?:{host}/{container}:{content}"

    def context(kind: str, content: Any) -> dict[str, Any]:
        if kind == "Process":
            return {"label": "Process", "exe_path": content or "<NA>"}
        if kind == "File":
            return {"label": "File", "path": content}
        if kind == "Network":
            return {"label": "Network", "endpoints": content}
        return {"label": kind}

    src_key = key(rec["a_kind"], rec["a_host"], rec["a_container"],
                  rec["a_content"])
    dst_key = key(rec["b_kind"], rec["b_host"], rec["b_container"],
                  rec["b_content"])
    action = str(rec["action"] or "")
    result = rec["result"]
    return {
        "edge_key": f"{rec['rel_type']}:{rec['event_id']}:{action}",
        "edge_type": rec["rel_type"],
        "fact": {"src": src_key, "action": action, "dst": dst_key,
                 "effect": effect_of(result)},
        "evidence": {"event_id": rec["event_id"],
                     "start_ns": rec["start_ns"],
                     "end_ns": rec["end_ns"],
                     "syscall": rec.get("syscall"),
                     "result": result},
        "context": {"src": context(rec["a_kind"], rec["a_content"]),
                    "dst": context(rec["b_kind"], rec["b_content"])},
    }


class DB:
    def __init__(self, name: str) -> None:
        load_dotenv()
        uri = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "")
        if not password:
            fail("缺少 NEO4J_PASSWORD；请在仓库根 .env 或环境变量里设置")
        self.name = name
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def close(self) -> None:
        self.driver.close()

    def run(self, cypher: str, **params: Any) -> list[dict[str, Any]]:
        with self.driver.session(database=self.name) as session:
            return session.execute_read(
                lambda tx: [dict(record) for record in tx.run(cypher, **params)]
            )




    def scan_facts_and_rules(self, facts: set[tuple[str, str, str, str]],
                             edge_keys: set[str], specs: list[Any],
                             must_vertices: set[str],
                             ) -> tuple[set, set, dict[str, tuple], dict[tuple, int], dict[str, int]]:
        """One relationship scan for both GT fact lookup and rule matching."""
        actions = {fact[1] for fact in facts}
        actions.update(key.split(":", 2)[2] for key in edge_keys)
        for spec in specs:
            actions.update(spec.actions)
        actions = sorted(actions)
        if not actions:
            return set(), set(), {}, {}, {}
        by_action: dict[str, list[Any]] = defaultdict(list)
        active: set[int] = set()
        for spec in specs:
            active.add(id(spec))
            for action in spec.actions:
                by_action[action].append(spec)
        found_facts: set[tuple[str, str, str, str]] = set()
        found_keys: set[str] = set()
        key_facts: dict[str, tuple[str, str, str, str]] = {}
        fact_times: dict[tuple[str, str, str, str], int] = {}
        key_times: dict[str, int] = {}
        cypher = (
            "MATCH (a)-[r]->(b) WHERE r.action IN $actions "
            "RETURN type(r) AS rel_type, r.event_id AS event_id, "
            "r.action AS action, r.result AS result, "
            "r.start_ns AS start_ns, r.end_ns AS end_ns, r.syscall AS syscall, "
            "CASE WHEN a:Process THEN 'Process' WHEN a:File THEN 'File' "
            "WHEN a:Network THEN 'Network' ELSE 'Unknown' END AS a_kind, "
            "a.host_id AS a_host, a.container_id AS a_container, "
            "CASE WHEN a:Process THEN coalesce(a.exe_path,'') "
            "WHEN a:File THEN a.path ELSE a.endpoints END AS a_content, "
            "CASE WHEN b:Process THEN 'Process' WHEN b:File THEN 'File' "
            "WHEN b:Network THEN 'Network' ELSE 'Unknown' END AS b_kind, "
            "b.host_id AS b_host, b.container_id AS b_container, "
            "CASE WHEN b:Process THEN coalesce(b.exe_path,'') "
            "WHEN b:File THEN b.path ELSE b.endpoints END AS b_content"
        )
        with self.driver.session(database=self.name) as session:
            def consume(tx: Any) -> None:
                nonlocal active
                for record in tx.run(cypher, actions=actions):
                    row = _projected_row(dict(record))
                    fact = (
                        row["fact"]["src"], row["fact"]["action"],
                        row["fact"]["dst"], row["fact"]["effect"],
                    )
                    if fact in facts:
                        found_facts.add(fact)
                        start = row["evidence"].get("start_ns")
                        if start is not None:
                            fact_times[fact] = min(fact_times.get(fact, int(start)),
                                                   int(start))
                    if row["edge_key"] in edge_keys:
                        found_keys.add(row["edge_key"])
                        key_facts[row["edge_key"]] = fact
                        start_k = row["evidence"].get("start_ns")
                        if start_k is not None:
                            key_times[row["edge_key"]] = int(start_k)
                    for spec in by_action.get(row["fact"]["action"], ()):
                        if spec.done:
                            continue
                        try:
                            ok = spec.predicate(row)
                        except Exception as exc:
                            spec.failed = f"{type(exc).__name__}: {exc}"
                            spec.done = True
                            active.discard(id(spec))
                            continue
                        if not ok:
                            continue
                        spec.hit = True
                        if spec.matched < spec.cap:
                            spec.matched += 1
                            if spec.matched >= spec.cap:
                                spec.truncated = True
                        if (row["fact"]["src"] in must_vertices
                                or row["fact"]["dst"] in must_vertices):
                            spec.attached = True
                        if fact in facts or row["edge_key"] in edge_keys:
                            if hasattr(spec, "overlapped_must") and spec.overlapped_must is not None:
                                spec.overlapped_must.append(row["edge_key"] or f"{fact[0]}->{fact[1]}->{fact[2]}")
                        if spec.truncated and spec.attached:
                            spec.done = True
                            active.discard(id(spec))
                    if (not active and facts <= found_facts
                            and edge_keys <= found_keys):
                        return
            session.execute_read(consume)
        return found_facts, found_keys, key_facts, fact_times, key_times


