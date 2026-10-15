"""Neo4j writer for TraceSage provenance graphs.

Writes Process / File / Network vertices and the five directed event
relationships (p2p / p2f / f2p / p2n / n2p) into Neo4j using the official
driver, parameterized Cypher, MERGE with unique constraints, and batched
transactions (configurable batch size).

Connection settings are read from the environment (NEO4J_URI / NEO4J_USER /
NEO4J_PASSWORD / NEO4J_DATABASE); the stdlib-only .env loader lives in
parsers.config.  Credentials are never hardcoded and never logged.

Performance notes:
- Every MATCH/MERGE uses a *label* so the unique-constraint index is hit
  (an unlabeled MATCH scans the whole node/relationship space).
- All statements go through driver.execute_query(), which both executes and
  consumes the result (lazy session.run() without consume() never commits).
- Each direction's endpoint labels are statically known (p2f is always
  Process->File, ...), so the Cypher is built once per relation type with
  labels interpolated from a closed constant set (never user data).
"""

import os
import queue
import sys
import threading
import time
from typing import Dict, Iterable, List, Optional, Tuple

from ..config import load_dotenv, resolve_batch_size
from ..model.entities import FileEntity, NetworkEntity, Process
from ..model.event_edge import EventEdge
from ..reporting import format_duration

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - module-level guard is in main
    GraphDatabase = None

# Fixed endpoint labels per relationship type (AGENTS.md §1: 五种方向化事件边).
_REL_LABELS: Dict[str, Tuple[str, str]] = {
    "p2p": ("Process", "Process"),
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
}

# MERGE key property name per vertex label.
_ID_PROP: Dict[str, str] = {
    "Process": "process_id",
    "File": "file_id",
    "Network": "network_id",
}


class Neo4jWriter:
    """Batch writer for the TraceSage provenance graph.

    Layout (per AGENTS.md §1: 三类顶点 + 五种方向化事件边):
        (:Process {process_id, pid, name, exepath?, args?, cwd?})
        (:File {file_id, path})
        (:Network {network_id, lip, lport, rip, rport, protocol?})
        ()-[:p2p|p2f|f2p|p2n|n2p {event_id, starttime, endtime, syscall, bytes}]->()

    属性可空性（exepath/args/cwd/protocol）：解析日志能取到才写，
    取不到传 None；Neo4j 中 `SET n.x = null` 等价于不设置/移除该属性，
    因此顶点上不会出现空字符串占位。MERGE + SET 幂等：同一日志重复导入
    写入相同值。注意 SET 以"本轮解析结果"为准：若某属性在本轮解析中从未
    取到，写入时用 null 覆盖（即移除）上一轮已写入的值——同一输入重跑时
    各轮取值序列一致，最终状态不变；用不同日志重导入时才会发生真实覆盖。
    （File 不带 type：当前值域仅为 'file'，与 :File 标签完全冗余；
    若将来目录顶点方案落地再引入。）

    - Vertices use MERGE on their id property (unique constraint created first).
    - Vertices are written in batches before edges (referential consistency).
    - Edges are written in 5 per-direction batches; each relationship is
      unique-merged on (event_id) so re-running an interrupted import is idempotent.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        batch_size: Optional[int] = None,
    ) -> None:
        load_dotenv()
        self._uri = uri or os.environ.get("NEO4J_URI")
        self._user = user or os.environ.get("NEO4J_USER")
        self._password = password or os.environ.get("NEO4J_PASSWORD")
        self._database = database or os.environ.get("NEO4J_DATABASE", "neo4j")
        if not self._uri or not self._user or self._password is None:
            raise ValueError(
                "Neo4j connection not configured. Set NEO4J_URI, NEO4J_USER, "
                "NEO4J_PASSWORD (and optionally NEO4J_DATABASE) in .env or environment."
            )
        if GraphDatabase is None:
            raise RuntimeError(
                "neo4j driver is not installed. Run: pip install neo4j"
            )
        self._batch_size = batch_size or resolve_batch_size()
        self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
        self._stats = {
            "processes": 0,
            "files": 0,
            "networks": 0,
            "p2p": 0,
            "p2f": 0,
            "f2p": 0,
            "p2n": 0,
            "n2p": 0,
            "batches": 0,
            "batch_errors": 0,
            "skipped_missing": 0,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def database(self) -> str:
        """Target database name (read-only access for tooling)."""
        return self._database

    @property
    def driver(self):
        """Underlying driver instance (read-only access for tooling)."""
        return self._driver

    def close(self) -> None:
        try:
            self._driver.close()
        except Exception:
            pass

    def __enter__(self) -> "Neo4jWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Schema setup
    # ------------------------------------------------------------------
    def create_schema(self) -> None:
        """Create unique constraints/indexes for all MERGE keys (idempotent).

        Relationship-property uniqueness constraints are named PER relationship
        type (event_id_p2p / event_id_p2f / ...).  Constraint names are unique
        database-wide: reusing a single name across types makes every
        `IF NOT EXISTS` after the first a silent no-op (previously only p2p
        actually got its event_id constraint).
        """
        # 旧版遗留：曾创建名为 event_id 的单一约束（只落在 p2p 上）。该名字
        # 会让下方按类型命名的 IF NOT EXISTS 全部 no-op（同名冲突），且
        # event_id_p2p 也会被同 schema 的旧约束挡住，因此先删除。
        # IF EXISTS 幂等；删除唯一约束会连带删除其 backing index，
        # 由下方按类型命名的约束重建。
        self._driver.execute_query(
            "DROP CONSTRAINT event_id IF EXISTS", database_=self._database
        )
        statements = (
            "CREATE CONSTRAINT process_id IF NOT EXISTS FOR (n:Process) REQUIRE n.process_id IS UNIQUE",
            "CREATE CONSTRAINT file_id IF NOT EXISTS FOR (n:File) REQUIRE n.file_id IS UNIQUE",
            "CREATE CONSTRAINT network_id IF NOT EXISTS FOR (n:Network) REQUIRE n.network_id IS UNIQUE",
        ) + tuple(
            f"CREATE CONSTRAINT event_id_{rel} IF NOT EXISTS "
            f"FOR ()-[r:{rel}]-() REQUIRE r.event_id IS UNIQUE"
            for rel in _REL_LABELS
        )
        for stmt in statements:
            _, summary, _ = self._driver.execute_query(stmt, database_=self._database)
            # IF NOT EXISTS 把同名/同 schema 冲突降级为通知而非报错；
            # 打印通知，避免约束被静默跳过（本次修复的 bug 即由此暴露）。
            for notification in summary.notifications or []:
                if isinstance(notification, dict):
                    text = (
                        f"{notification.get('title', '')} — "
                        f"{notification.get('description', '')}"
                    )
                else:  # 防御：其他驱动版本可能返回对象
                    text = str(notification)
                print(f"[Neo4j] schema notification: {text}")
        constraints, _, _ = self._driver.execute_query(
            "SHOW CONSTRAINTS", database_=self._database
        )
        names = sorted(rec["name"] for rec in constraints)
        print(
            f"Neo4j schema ensured: {len(statements)} statements issued, "
            f"{len(names)} constraints present: {', '.join(names)}"
        )

    # ------------------------------------------------------------------
    # Vertices
    # ------------------------------------------------------------------
    def insert_processes(self, processes: Iterable[Process]) -> None:
        batch: List[Dict] = []
        for proc in processes:
            batch.append(
                {
                    "process_id": proc.pid_and_name,
                    "pid": proc.pid,
                    "name": proc.name,
                    "exepath": proc.exe_path,
                    "args": proc.args,
                    "cwd": proc.cwd,
                }
            )
            if len(batch) >= self._batch_size:
                self._flush_process_batch(batch)
                batch.clear()
        if batch:
            self._flush_process_batch(batch)

    def insert_files(self, files: Iterable[FileEntity]) -> None:
        batch: List[Dict] = []
        for f in files:
            batch.append({"file_id": f.path, "path": f.path})
            if len(batch) >= self._batch_size:
                self._flush_file_batch(batch)
                batch.clear()
        if batch:
            self._flush_file_batch(batch)

    def insert_networks(self, networks: Iterable[NetworkEntity]) -> None:
        batch: List[Dict] = []
        for n in networks:
            batch.append(
                {
                    "network_id": n.src_and_dst_ip,
                    "lip": n.src_address,
                    "lport": n.src_port,
                    "rip": n.dst_address,
                    "rport": n.dst_port,
                    "protocol": n.protocol,
                }
            )
            if len(batch) >= self._batch_size:
                self._flush_network_batch(batch)
                batch.clear()
        if batch:
            self._flush_network_batch(batch)

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------
    def insert_edges(self, edges: Iterable[EventEdge], rel_type: str) -> None:
        """Batch-insert one direction of edges.

        Each edge references source/sink vertices by their MERGE key
        (Process: process_id, File: file_id, Network: network_id); if either is
        missing, the edge is skipped and counted (auditable, no silent loss).
        """
        batch: List[Dict] = []
        for edge in edges:
            src = Neo4jWriter._entity_key(edge.source)
            dst = Neo4jWriter._entity_key(edge.sink)
            if src is None or dst is None:
                self._stats["skipped_missing"] += 1
                continue
            batch.append(
                {
                    "src": src,
                    "dst": dst,
                    "event_id": edge.id,
                    "starttime": edge.start_ns,
                    "endtime": edge.end_ns,
                    "syscall": edge.event,
                    "bytes": edge.size,
                }
            )
            if len(batch) >= self._batch_size:
                self._flush_edge_batch(rel_type, batch)
                batch.clear()
        if batch:
            self._flush_edge_batch(rel_type, batch)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _entity_key(node) -> Optional[str]:
        """Return the MERGE-key value for an EntityNode source/sink, or None."""
        if node.file is not None:
            return node.file.path
        if node.network is not None:
            return node.network.src_and_dst_ip
        if node.process is not None:
            return node.process.pid_and_name
        return None

    # ------------------------------------------------------------------
    # Flush helpers (one transaction per batch)
    # ------------------------------------------------------------------
    def _flush_process_batch(self, batch: List[Dict]) -> None:
        # SET n.x = null（行内值为 None 时）在 Neo4j 中等价于不设置该属性，
        # 因此只有解析到的属性才会出现在顶点上。
        query = (
            "UNWIND $rows AS row "
            "MERGE (n:Process {process_id: row.process_id}) "
            "SET n.pid = row.pid, n.name = row.name, "
            "    n.exepath = row.exepath, "
            "    n.args = row.args, "
            "    n.cwd = row.cwd"
        )
        self._run_batch("processes", query, batch)

    def _flush_file_batch(self, batch: List[Dict]) -> None:
        query = (
            "UNWIND $rows AS row "
            "MERGE (n:File {file_id: row.file_id}) "
            "SET n.path = row.path"
        )
        self._run_batch("files", query, batch)

    def _flush_network_batch(self, batch: List[Dict]) -> None:
        query = (
            "UNWIND $rows AS row "
            "MERGE (n:Network {network_id: row.network_id}) "
            "SET n.lip = row.lip, n.lport = row.lport, "
            "    n.rip = row.rip, n.rport = row.rport, "
            "    n.protocol = row.protocol"
        )
        self._run_batch("networks", query, batch)

    def _flush_edge_batch(self, rel_type: str, batch: List[Dict]) -> None:
        src_label, dst_label = _REL_LABELS[rel_type]
        src_prop = _ID_PROP[src_label]
        dst_prop = _ID_PROP[dst_label]
        # Labels / id-props / rel_type come from the closed constant sets above,
        # so interpolating them is safe (no user-controlled content).
        query = (
            "UNWIND $rows AS row "
            f"MATCH (a:{src_label} {{{src_prop}: row.src}}) "
            f"MATCH (b:{dst_label} {{{dst_prop}: row.dst}}) "
            f"MERGE (a)-[r:{rel_type} {{event_id: row.event_id}}]->(b) "
            "SET r.starttime = row.starttime, r.endtime = row.endtime, "
            "    r.syscall = row.syscall, r.bytes = row.bytes"
        )
        self._run_batch(rel_type, query, batch)

    def _run_batch(self, kind: str, query: str, rows: List[Dict]) -> None:
        if not rows:
            return
        self._stats["batches"] += 1
        try:
            # execute_query executes and consumes the result in one auto-commit
            # transaction; lazy session.run() without consume() would never commit.
            self._driver.execute_query(query, rows=rows, database_=self._database)
            self._stats[kind] += len(rows)
        except Exception as exc:
            self._stats["batch_errors"] += 1
            print(
                f"[Neo4j] batch error on {kind} (batch #{self._stats['batches']}, "
                f"{len(rows)} rows): {exc}"
            )
            # Re-throw so the caller can know the import did not complete; this
            # writer keeps no internal retry state (idempotent MERGE on retry).
            raise

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        return dict(self._stats)

    def print_summary(self) -> None:
        s = self._stats
        print(
            "Neo4j import summary: "
            f"processes={s['processes']} files={s['files']} networks={s['networks']} "
            f"p2p={s['p2p']} p2f={s['p2f']} f2p={s['f2p']} p2n={s['p2n']} n2p={s['n2p']} "
            f"batches={s['batches']} batchErrors={s['batch_errors']} "
            f"skippedMissing={s['skipped_missing']}"
        )


class AsyncNeo4jWriter:
    """Asynchronous double-buffered batch writer for Neo4j.

    Offloads Cypher transaction execution to a dedicated background worker thread,
    allowing the parser main thread to continue parsing without Stop-the-World pauses.
    Provides backpressure via a bounded queue and strict fail-fast error propagation.
    """

    def __init__(self, database: str, queue_size: int = 2) -> None:
        self._database = database
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._writer: Optional[Neo4jWriter] = None
        self._error: Optional[Exception] = None
        self._closed = False
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name="AsyncNeo4jWriterWorker"
        )
        self._worker.start()

    def _worker_loop(self) -> None:
        try:
            self._writer = Neo4jWriter(database=self._database)
            self._writer.create_schema()
            while True:
                item = self._queue.get()
                if item is None:
                    self._queue.task_done()
                    break
                processes, files, networks, edges_dict, include_process_events, round_num = item
                flush_start = int(time.time() * 1000)
                self._writer.insert_processes(processes)
                self._writer.insert_files(files)
                self._writer.insert_networks(networks)
                if include_process_events:
                    self._writer.insert_edges(edges_dict.get("p2p", []), "p2p")
                self._writer.insert_edges(edges_dict.get("p2f", []), "p2f")
                self._writer.insert_edges(edges_dict.get("f2p", []), "f2p")
                self._writer.insert_edges(edges_dict.get("p2n", []), "p2n")
                self._writer.insert_edges(edges_dict.get("n2p", []), "n2p")
                elapsed = int(time.time() * 1000) - flush_start
                print(
                    f"Flush #{round_num} [neo4j] committed in {format_duration(elapsed)}."
                )
                self._queue.task_done()
        except Exception as exc:
            self._error = exc
            print(f"[AsyncNeo4jWriter] Background write failed: {exc}", file=sys.stderr)
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except Exception:
                    break

    def submit_batch(
        self,
        processes: List[Process],
        files: List[FileEntity],
        networks: List[NetworkEntity],
        edges_dict: Dict[str, List[EventEdge]],
        include_process_events: bool,
        round_num: int,
    ) -> None:
        if self._error is not None:
            raise self._error
        while True:
            if self._error is not None:
                raise self._error
            try:
                self._queue.put(
                    (processes, files, networks, edges_dict, include_process_events, round_num),
                    timeout=0.5,
                )
                break
            except queue.Full:
                if self._error is not None:
                    raise self._error

    def flush_and_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._error is None:
                self._queue.put(None)
                self._worker.join()
            if self._writer is not None:
                if self._error is None:
                    self._writer.print_summary()
                self._writer.close()
        finally:
            if self._error is not None:
                raise self._error

    def close_on_error(self) -> None:
        """Emergency cleanup on upstream failure; aborts pending writes and closes driver."""
        if self._closed:
            return
        self._closed = True
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except Exception:
                break
        try:
            self._queue.put_nowait(None)
        except Exception:
            pass
        self._worker.join(timeout=2)
        if self._writer is not None:
            self._writer.close()


