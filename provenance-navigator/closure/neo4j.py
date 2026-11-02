"""只读 Neo4j 访问、只读守卫与查询审计。"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from neo4j import GraphDatabase
from neo4j.graph import Node, Path as Neo4jPath, Relationship

import settings

# ==== 5. 只读 Neo4j ====

_FORBIDDEN = re.compile(
    r"\b("
    r"CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|FOREACH|"
    r"LOAD\s+CSV|ALTER|GRANT|REVOKE|TERMINATE|"
    r"START\s+DATABASE|STOP\s+DATABASE|CREATE\s+DATABASE|DROP\s+DATABASE|"
    r"USE\s+"
    r")\b",
    re.IGNORECASE,
)
_STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
_FORBIDDEN_CALL = re.compile(
    r"\bCALL\s+(?:DB\.|DBMS\.|APOC\.PERIODIC|APOC\.CREATE|APOC\.MERGE|APOC\.LOAD|"
    r"APOC\.REFACTOR|GDS\.GRAPH\.(?:PROJECT|DROP|CREATE)|GDS\.GRAPH\.WRITE|"
    r"GDS\.BETA\.|GDS\.(?:NODE|REL|DEGREE|PAGE|LOUVAIN|WCC|BFS|DFS)\.WRITE)\b",
    re.IGNORECASE,
)


class ReadOnlyViolation(RuntimeError):
    """查询被只读守卫拒绝。"""


@dataclass
class QueryRecord:
    seq: int
    cypher: str
    params: dict[str, Any]
    rows: int = 0
    ms: float = 0.0
    ok: bool = True
    error: Optional[str] = None
    count_only: bool = False


def _strip_literals(cypher: str) -> str:
    return _STRING_LITERAL.sub("''", cypher)


def check_read_only(cypher: str) -> None:
    if ";" in _strip_literals(cypher):
        raise ReadOnlyViolation("查询不得包含分号（禁止多语句）")
    stripped = _strip_literals(cypher)
    hit = _FORBIDDEN.search(stripped)
    if hit:
        raise ReadOnlyViolation(f"查询含写/管理关键字 {hit.group(0)!r}，只读守卫拒绝")
    hit = _FORBIDDEN_CALL.search(stripped)
    if hit:
        raise ReadOnlyViolation(f"查询含被禁 CALL {hit.group(0)!r}，只读守卫拒绝")


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, Node):
        return {"_label": sorted(value.labels), **{k: _jsonable(v) for k, v in dict(value).items()}}
    if isinstance(value, Relationship):
        return {"_type": value.type, **{k: _jsonable(v) for k, v in dict(value).items()}}
    if isinstance(value, Neo4jPath):
        return {"_path": [_jsonable(n) for n in value.nodes]}
    return str(value)


class ReadOnlyGraph:
    """一个场景库的只读句柄；同时是查询审计日志的写入点。"""

    def __init__(
        self,
        database: str,
        *,
        uri: Optional[str] = None,
        auth: Optional[tuple[str, str]] = None,
        scenario: str = "",
        run_id: str = "",
    ) -> None:
        self.database = database
        self.scenario = scenario
        self.run_id = run_id
        self._driver = GraphDatabase.driver(uri or settings.neo4j_uri(), auth=auth or settings.neo4j_auth())
        self._seq = 0
        self.records: list[QueryRecord] = []
        self._lock = threading.RLock()
        settings.ensure_work_dirs()
        self.log_path = settings.LOG_DIR / f"queries-{run_id or 'default'}.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        self._driver.close()

    def run(self, cypher: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        check_read_only(cypher)
        params = params or {}
        with self._lock:
            self._seq += 1
            rec = QueryRecord(seq=self._seq, cypher=cypher, params=params)
        t0 = time.perf_counter()
        rows: list[dict[str, Any]] = []
        try:
            with self._driver.session(database=self.database) as session:
                result = session.execute_read(lambda tx: tx.run(cypher, **params).to_eager_result())
            for record in result.records:
                rows.append({k: _jsonable(v) for k, v in record.items()})
            rec.rows = len(rows)
        except ReadOnlyViolation:
            raise
        except Exception as exc:  # noqa: BLE001 - 审计后原样抛出，供调用方自校正
            rec.ok = False
            rec.error = f"{type(exc).__name__}: {exc}".splitlines()[0][:500]
            raise
        finally:
            rec.ms = (time.perf_counter() - t0) * 1000.0
            with self._lock:
                self.records.append(rec)
            self._log(rec)
        return rows

    def count(self, cypher: str, params: Optional[dict[str, Any]] = None) -> int:
        check_read_only(cypher)
        wrapped = f"CALL () {{\n{cypher}\n}}\nRETURN count(*) AS n"
        rows = self.run(wrapped, params)
        n = int(rows[0]["n"]) if rows else 0
        self.records[-1].count_only = True
        return n

    def _log(self, rec: QueryRecord) -> None:
        payload = {
            "ts": time.time(),
            "run_id": self.run_id,
            "scenario": self.scenario,
            "database": self.database,
            "seq": rec.seq,
            "cypher": rec.cypher,
            "params": _jsonable(rec.params),
            "rows": rec.rows,
            "ms": round(rec.ms, 3),
            "ok": rec.ok,
            "error": rec.error,
            "count_only": rec.count_only,
        }
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        try:
            with self._lock:
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception:  # noqa: BLE001 - 审计是旁路
            pass

    @property
    def query_count(self) -> int:
        return len(self.records)

    @property
    def total_rows(self) -> int:
        return sum(r.rows for r in self.records)

