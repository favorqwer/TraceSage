"""图访问、边语义、路径拆装、调查记录、轨迹与通用键。

这一层只做“图上有什么”和“内容怎么拆”，不做“哪条边是攻击”。
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from neo4j import GraphDatabase
from neo4j.graph import Node, Path as Neo4jPath, Relationship

from common import config

# ==== 1. 边语义：关系类型唯一决定方向与两端标签 ====

RELATION_LABELS: dict[str, tuple[str, str]] = {
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
    "p2p": ("Process", "Process"),
}

REL_NORM: dict[str, str] = {
    "ProcessToFile": "p2f",
    "FileToProcess": "f2p",
    "ProcessToNetwork": "p2n",
    "NetworkToProcess": "n2p",
    "ProcessToProcess": "p2p",
    "p2f": "p2f",
    "f2p": "f2p",
    "p2n": "p2n",
    "n2p": "n2p",
    "p2p": "p2p",
}

REL_CYPHER: dict[str, str] = {
    "p2f": "ProcessToFile|p2f",
    "f2p": "FileToProcess|f2p",
    "p2n": "ProcessToNetwork|p2n",
    "n2p": "NetworkToProcess|n2p",
    "p2p": "ProcessToProcess|p2p",
    "ProcessToFile": "ProcessToFile|p2f",
    "FileToProcess": "FileToProcess|f2p",
    "ProcessToNetwork": "ProcessToNetwork|p2n",
    "NetworkToProcess": "NetworkToProcess|n2p",
    "ProcessToProcess": "ProcessToProcess|p2p",
}

ALL_RELS = ("p2f", "f2p", "p2n", "n2p", "p2p")
PRODUCER_RELS = ("p2f", "p2n")
CONSUMER_RELS = ("f2p", "n2p")
DERIVATION_REL = "p2p"


def normalize_rel(rel: str) -> str:
    return REL_NORM.get(rel, rel)


def cypher_rel_match(rel: str) -> str:
    return REL_CYPHER.get(rel, rel)


def labels_of(rel: str) -> tuple[str, str]:
    return RELATION_LABELS.get(normalize_rel(rel), ("Process", "Process"))


def owner_is_source(rel: str) -> bool:
    return normalize_rel(rel) in PRODUCER_RELS


def is_derivation(rel: str) -> bool:
    return normalize_rel(rel) == DERIVATION_REL


def content_triple_of(rel: str, syscall: str, owner: str, other: str,
                      ) -> tuple[str, str, str, str]:
    src_label, _dst_label = labels_of(rel)
    src, dst = (owner, other) if owner_is_source(rel) else (other, owner)
    return src, syscall, dst, src_label


def endpoints_of(rel: str, src: str, dst: str) -> tuple[str, str, str]:
    src_label, dst_label = labels_of(rel)
    if owner_is_source(rel):
        return src, dst, dst_label
    return dst, src, src_label


# ==== 2. 路径与端点拆装 ====

_PROCESS_ID = re.compile(r"^[^|]*\|[^|]*\|\d+\|\d+$")


def split_container(content: Any) -> tuple[str, str]:
    """文件内容 →（容器, 纯路径）。恰好一个 `|` 且两侧非空时才认容器前缀。"""
    s = "" if content is None else str(content)
    if s.count("|") == 1:
        container, path = s.split("|", 1)
        if container and path:
            return container, path
    return "host", s


def path_part(content: Any) -> str:
    """文件内容的纯路径部分（剥掉容器前缀）。"""
    return split_container(content)[1]


def split_process_id(process_id: Any) -> tuple[str, str]:
    """进程标识 `主机|容器|pid|启动纳秒` →（主机, 容器）。"""
    parts = str(process_id or "").split("|")
    if len(parts) >= 4:
        return parts[0], (parts[1] or "host")
    return "", "host"


def process_content_or_na(content: Any, process_id: Optional[str] = None) -> str:
    """进程端点内容：图里取不到可执行文件时，标准答案与报告都写 `<NA>`。"""
    s = "" if content is None else str(content)
    if not s:
        return "<NA>"
    if process_id is not None and s == str(process_id):
        return "<NA>"
    if _PROCESS_ID.match(s):
        return "<NA>"
    return s


def split_process_key(key: Any) -> tuple[str, str, int, int] | None:
    """进程顶点键 `主机|容器|pid|启动时刻` →（主机, 容器, pid, 启动纳秒）。"""
    parts = str(key or "").split("|")
    if len(parts) < 4:
        return None
    try:
        return parts[0], (parts[1] or "host"), int(parts[2]), int(parts[3])
    except ValueError:
        return None


def process_identity_variants(pid_raw: Any) -> set[str]:
    """进程键的全部等价标识：自身 + 去掉启动纳秒的三段前缀。"""
    if not pid_raw:
        return set()
    s = str(pid_raw).strip()
    if not s or s == "<NA>":
        return set()
    variants = {s}
    if "|" in s:
        parts = s.split("|")
        if len(parts) >= 3:
            variants.add(f"{parts[0]}|{parts[1]}|{parts[2]}")
    return variants


def edge_key(edge: dict[str, Any]) -> tuple[Any, Any, Any]:
    """边的内容三元组键（报告与评分口径）。"""
    return (edge.get("src"), edge.get("syscall"), edge.get("dst"))


# ==== 3. 通用契约 ====

BUNDLE_VERDICTS = ("all", "none", "mixed", "unknown")


def triple(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (edge.get("src", ""), edge.get("syscall", ""), edge.get("dst", ""))


def short(text: Any, limit: Any = None) -> str:
    """一句话摘要：换行压成空格并截断；默认长度取参数文件。"""
    if limit is None:
        limit = config.log_text_limit()
    return str(text or "").replace("\n", " ")[:int(limit)]


def rel_time(value: Any, ref_t: Any) -> str:
    """相对终点事件的秒数。"""
    try:
        t = int(value or 0)
    except (TypeError, ValueError):
        return "?"
    if not ref_t or not t:
        return str(t)
    return f"{(t - int(ref_t)) / 1e9:+.1f}s"


def parse_bundle_verdicts(result: dict[str, Any], valid_ids: set[str]
                          ) -> tuple[dict[str, dict[str, Any]], int]:
    """按编号收束级结论；重复/越界/缺失/非法结论都算没给结论，绝不当成无关。"""
    verdicts: dict[str, dict[str, Any]] = {}
    invalid = 0
    for row in result.get("verdicts") or []:
        if not isinstance(row, dict):
            invalid += 1
            continue
        bid = str(row.get("id") or "").strip()
        verdict = str(row.get("verdict") or "").strip().lower()
        if bid not in valid_ids or bid in verdicts or verdict not in BUNDLE_VERDICTS:
            invalid += 1
            continue
        verdicts[bid] = row
    return verdicts, invalid


# ==== 4. 调查记录 ====

ENTITY_STATUSES = ("unexplored", "tracing", "confirmed", "excluded")
RELS = ("supports", "refutes", "derived-from")


def entity_key(etype: str, content: str) -> str:
    e = (etype or "").lower()
    if e == "process":
        return f"proc:{content}"
    if e == "file":
        return f"file:{content}"
    if e == "network":
        return f"net:{content}"
    return f"{e}:{content}"


def _guess_type(content: str) -> str:
    if "->" in content and ":" in content:
        return "Network"
    if content.startswith(("pipe:[", "unix:[")):
        return "File"
    return "Process"


@dataclass
class Investigation:
    run_id: str
    scenario: str
    database: str = ""
    poi_process: str = ""
    poi_owner: str = ""
    poi_instances: int = 0
    poi_t0: int = 0
    poi_t1: int = 0
    poi_rows: list[dict[str, Any]] = field(default_factory=list)
    process_context: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    origin: dict[tuple[str, str, str], str] = field(default_factory=dict)
    confirmed: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    kept: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    excluded: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    links: list[tuple[str, str, str, str]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)

    def mark(self, keys: Iterable[tuple[str, str, str]], origin: str) -> None:
        if origin not in ("confirmed", "kept", "excluded"):
            raise ValueError(f"未知来路 {origin!r}")
        for key in keys:
            self.origin[key] = origin

    def settle(self) -> None:
        self.confirmed = {}
        self.kept = {}
        self.excluded = {}
        for key, edge in self.edges.items():
            origin = self.origin.get(key, "kept")
            bucket = {"confirmed": self.confirmed, "excluded": self.excluded}.get(origin, self.kept)
            bucket[key] = edge

    def unexcluded(self) -> dict[tuple[str, str, str], dict[str, Any]]:
        return {**self.confirmed, **self.kept}

    def add_entity(self, etype: str, content: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知实体状态 {status!r}")
        key = entity_key(etype, content)
        node = self.entities.get(key)
        if node is None:
            self.entities[key] = {"key": key, "kind": "entity", "etype": etype,
                                  "label": content, "status": status}
        elif node["status"] != "confirmed":
            node["status"] = status
        return key

    def add_hypothesis(self, key: str, label: str, *, status: str = "tracing") -> str:
        if status not in ENTITY_STATUSES:
            raise ValueError(f"未知假设状态 {status!r}")
        self.hypotheses = [h for h in self.hypotheses if h["key"] != key]
        self.hypotheses.append({"key": key, "kind": "hypothesis", "label": label, "status": status})
        return key

    def add_gap(self, label: str, next_action: str) -> None:
        if not next_action or not next_action.strip():
            raise ValueError("gap 必须带 next_action（哪个库、哪条查询/哪个工具）")
        if any(g["label"] == label for g in self.gaps):
            return
        self.gaps.append({"key": f"gap:{len(self.gaps) + 1}", "kind": "gap", "label": label,
                          "status": "open", "next_action": next_action.strip()})

    def link(self, src: str, rel: str, dst: str, *, note: str = "") -> None:
        if rel not in RELS:
            raise ValueError(f"未知关系 {rel!r}；允许 {RELS}")
        item = (src, rel, dst, note)
        if item not in self.links:
            self.links.append(item)

    def register_edges(self, records: list[dict[str, Any]], *, relevant: bool,
                       hypothesis_key: str = "") -> None:
        for edge in records:
            src_key = entity_key(edge.get("src_label") or _guess_type(edge["src"]), edge["src"])
            dst_key = entity_key(edge.get("dst_label") or _guess_type(edge["dst"]), edge["dst"])
            self.add_entity(edge.get("src_label") or _guess_type(edge["src"]), edge["src"],
                            status="confirmed" if relevant else "excluded")
            self.add_entity(edge.get("dst_label") or _guess_type(edge["dst"]), edge["dst"],
                            status="confirmed" if relevant else "excluded")
            if hypothesis_key:
                for key in (src_key, dst_key) if relevant else (src_key,):
                    self.link(key, "supports" if relevant else "refutes", hypothesis_key)

    def unclosed(self) -> list[dict[str, Any]]:
        return [h for h in self.hypotheses if h["status"] == "tracing"]

    def close_unclosed(self) -> int:
        n = 0
        for h in self.hypotheses:
            if h["status"] == "tracing":
                h["status"] = "excluded"
                n += 1
        return n

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for node in list(self.entities.values()) + self.hypotheses + self.gaps:
            by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
            by_status[node["status"]] = by_status.get(node["status"], 0) + 1
        by_origin: dict[str, int] = {}
        for origin in self.origin.values():
            by_origin[origin] = by_origin.get(origin, 0) + 1
        return {
            "nodes": len(self.entities) + len(self.hypotheses) + len(self.gaps),
            "by_kind": by_kind,
            "by_status": by_status,
            "edges": len(self.links),
            "unclosed_hypotheses": len(self.unclosed()),
            "open_gaps": sum(1 for g in self.gaps if g["status"] == "open"),
            "origin": by_origin,
        }

    def dump(self, path: Optional[Path] = None) -> Optional[Path]:
        if path is None:
            return None
        payload = {
            "run_id": self.run_id, "scenario": self.scenario, "database": self.database,
            "poi_process": self.poi_process,
            "nodes": list(self.entities.values()) + self.hypotheses + self.gaps,
            "edges": [{"src": s, "rel": r, "dst": d, "note": n} for s, r, d, n in self.links],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        return Path(path)


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
        self._driver = GraphDatabase.driver(uri or config.neo4j_uri(), auth=auth or config.neo4j_auth())
        self._seq = 0
        self.records: list[QueryRecord] = []
        self._lock = threading.RLock()
        config.ensure_work_dirs()
        self.log_path = config.LOG_DIR / f"queries-{run_id or 'default'}.jsonl"
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


# ==== 6. 运行轨迹 ====

def trace_event(trace: list[dict[str, Any]], node: str, **fields: Any) -> None:
    trace.append({"node": node, "ts": time.time(), **fields})


def write_trace(path: Path, trace: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(json.dumps(t, ensure_ascii=False) for t in trace), encoding="utf-8")
