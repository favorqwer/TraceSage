"""Neo4j 写入适配器：只认连接参数与图模型，不认 Config / 解析流程。"""

from __future__ import annotations

from typing import Any

from ..core.graph import Edge, Node
from ..core.kinds import EdgeClass, key_tuple, label_of
from ..core.options import Neo4jOptions

_NODE_QUERIES = {
    "Process": (
        "UNWIND $rows AS x MERGE (n:Process {host_id: x.k[0], container_id: x.k[1], "
        "pid: x.k[2], start_ns: x.k[3]}) SET n += x.p"
    ),
    "File": (
        "UNWIND $rows AS x MERGE (n:File {host_id: x.k[0], container_id: x.k[1], "
        "path: x.k[2]}) SET n += x.p"
    ),
    "Network": (
        "UNWIND $rows AS x MERGE (n:Network {host_id: x.k[0], endpoints: x.k[1]}) "
        "SET n += x.p"
    ),
}

_EDGE_MATCH = {
    EdgeClass.P2P: ("Process", "Process"),
    EdgeClass.P2F: ("Process", "File"),
    EdgeClass.F2P: ("File", "Process"),
    EdgeClass.P2N: ("Process", "Network"),
    EdgeClass.N2P: ("Network", "Process"),
}


def _match_clause(label: str, alias: str, prefix: str) -> str:
    if label == "Process":
        return (f"MATCH ({alias}:Process {{host_id: {prefix}[0], container_id: {prefix}[1], "
                f"pid: {prefix}[2], start_ns: {prefix}[3]}})")
    if label == "File":
        return (f"MATCH ({alias}:File {{host_id: {prefix}[0], container_id: {prefix}[1], "
                f"path: {prefix}[2]}})")
    return f"MATCH ({alias}:Network {{host_id: {prefix}[0], endpoints: {prefix}[1]}})"


def _edge_query(cls: EdgeClass) -> str:
    src_label, dst_label = _EDGE_MATCH[cls]
    rel = cls.value
    return (
        f"UNWIND $rows AS x "
        f"{_match_clause(src_label, 'a', 'x.s')} "
        f"{_match_clause(dst_label, 'b', 'x.d')} "
        f"MERGE (a)-[r:{rel} {{event_id: x.event_id, action: x.action}}]->(b) "
        "SET r.start_ns = x.start_ns, r.end_ns = x.end_ns, "
        "r.syscall = x.syscall, "
        "r.result = x.result, r.payload_b64 = x.payload_b64, "
        "r.to_path = x.to_path, r.mode = x.mode"
    )


class Neo4jWriter:
    def __init__(self, options: Neo4jOptions) -> None:
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("未安装 neo4j 驱动：pip install neo4j") from exc
        self._options = options
        self._driver = GraphDatabase.driver(
            options.uri, auth=(options.user, options.password)
        )
        self._driver.verify_connectivity()
        self._session = self._driver.session(database=options.database)
        self._edge_queries = {cls: _edge_query(cls) for cls in EdgeClass}
        self._ensure_schema()

    def _run(self, query: str, **params):
        return self._session.execute_write(lambda tx: tx.run(query, **params).consume())

    def _ensure_schema(self) -> None:
        statements = [
            "CREATE CONSTRAINT proc_key IF NOT EXISTS FOR (n:Process) "
            "REQUIRE (n.host_id, n.container_id, n.pid, n.start_ns) IS UNIQUE",
            "CREATE CONSTRAINT file_key IF NOT EXISTS FOR (n:File) "
            "REQUIRE (n.host_id, n.container_id, n.path) IS UNIQUE",
            "CREATE CONSTRAINT net_key IF NOT EXISTS FOR (n:Network) "
            "REQUIRE (n.host_id, n.endpoints) IS UNIQUE",
        ]
        for statement in statements:
            try:
                self._run(statement)
            except Exception:
                pass
        # 关系边必须是 (event_id, action) 唯一约束，不能是普通索引：只有唯一约束才会让
        # MERGE 规划成 DirectedRelationshipUniqueIndexSeek；普通索引（单列 event_id 或组合）
        # 在有数据后一律退化成 Expand(Into)，每条边要扫源节点全部同类型边。
        # 实测（超节点 5 万出度/6 万入度，1 万条新边）：无索引 569 边/秒、单列索引
        # 154 边/秒、组合索引 90 边/秒、唯一约束 8,982 边/秒。
        for cls in EdgeClass:
            try:
                self._run(
                    f"CREATE CONSTRAINT rel_{cls.name.lower()}_event_action IF NOT EXISTS "
                    f"FOR ()-[r:{cls.value}]-() REQUIRE (r.event_id, r.action) IS UNIQUE"
                )
            except Exception:
                pass

    def reset(self, host_id: str) -> None:
        while True:
            result = self._session.execute_write(
                lambda tx: tx.run(
                    "MATCH (n) WHERE n.host_id = $h "
                    "WITH n LIMIT 50000 DETACH DELETE n RETURN count(*) AS c",
                    h=host_id,
                ).single()
            )
            if not result or result["c"] == 0:
                break

    def write_nodes(self, nodes: list[Node]) -> None:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for node in nodes:
            label = label_of(node.key)
            grouped.setdefault(label, []).append(
                {"k": key_tuple(node.key), "p": node.props}
            )
        for label, rows in grouped.items():
            self._run(_NODE_QUERIES[label], rows=rows)

    def write_edges(self, edges: list[Edge]) -> None:
        grouped: dict[EdgeClass, list[dict[str, Any]]] = {}
        for edge in edges:
            grouped.setdefault(edge.cls, []).append(
                {
                    "s": key_tuple(edge.src),
                    "d": key_tuple(edge.dst),
                    "event_id": edge.event_id,
                    "action": edge.action,
                    "syscall": edge.syscall,
                    "start_ns": edge.start_ns,
                    "end_ns": edge.end_ns,
                    "result": edge.result,
                    "payload_b64": edge.payload_b64,
                    "to_path": edge.to_path,
                    "mode": edge.mode,
                }
            )
        for cls, rows in grouped.items():
            self._run(self._edge_queries[cls], rows=rows)

    def close(self) -> None:
        try:
            self._session.close()
        finally:
            self._driver.close()
