import os
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Deque, List, Optional, Tuple

from .action import Action
from .entity import Entity
from .file_entity import FileEntity
from .network_entity import NetworkEntity
from .process import Process
from .entity_node import EntityNode
from .event_edge import EventEdge
from .fingerprint import Fingerprint
from .meta_config import MetaConfig
from .system_call import SystemCall
from .system_call_factory import SystemCallFactory
from .utils import (
    extract_file_and_socket,
    extract_process_file,
    extract_size,
    parse_jsonl_entry,
)
from .neo4j_writer import Neo4jWriter

_DEFAULT_FLUSH_EDGE_LIMIT = 50000
_FLUSH_EDGE_LIMIT_ENV = "PROGQL_SYSDIG_FLUSH_EDGE_LIMIT"
_FLUSH_EDGE_LIMIT_PROPERTY = "progql.sysdig.flush.edge.limit"

_DRY_RUN_ENV = "PROGQL_SYSDIG_DRY_RUN"

_DEFAULT_PROGRESS_INTERVAL_SECONDS = 15
_PROGRESS_INTERVAL_SECONDS_ENV = "PROGQL_SYSDIG_PROGRESS_INTERVAL_SECONDS"
_PROGRESS_INTERVAL_SECONDS_PROPERTY = "progql.sysdig.progress.interval.seconds"

_PROGRESS_CHECK_LINE_INTERVAL = 5000
_SKIP_SAMPLE_LIMIT_PER_REASON = 3
_SKIP_SUMMARY_REASON_LIMIT = 10
_PAIRING_FALLBACK_TOLERANCE_NANOS = 1000
_PAIRING_TOLERANCE_NS_ENV = "PROGQL_SYSDIG_PAIRING_TOLERANCE_NS"

_RENAME_PATHS = re.compile(
    r"oldpath=(?P<old>.+?) newpath=(?P<new>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)"
)
_PARENT_PATTERN = re.compile(r"ptid=(?P<parentPID>\d+)\((?P<parent>.+?)\)")

# fd.l4proto 中“非真实协议”的取值：视为解析不出来，不写入 Network.protocol。
_L4PROTO_NOT_APPLICABLE = frozenset({"", "<NA>"})

# 五种方向化事件边（AGENTS.md §1）。
_EDGE_RELS = ("p2p", "p2f", "f2p", "p2n", "n2p")

# MetaConfig 驱动的四类通用方向：
#   rel -> (工厂实体类型, 系统调用名集合, start_entities 中作为边源/汇的下标)
# 这四类系统调用的两端实体都取自进入记录
# （start_entities[0]=Process，[1]=File/Network），方向由下标决定。
# 顺序须与旧版逐段注册一致（ftop -> ptof -> ntop -> pton），
# 保证同名系统调用（如 rename 同时在 ftop/ptof 中）的覆盖结果不变。
_GENERIC_SYSCALL_DIRECTIONS = (
    ("f2p", FileEntity, MetaConfig.ftop_system_calls, 1, 0),
    ("p2f", FileEntity, MetaConfig.ptof_system_calls, 0, 1),
    ("n2p", NetworkEntity, MetaConfig.ntop_system_calls, 1, 0),
    ("p2n", NetworkEntity, MetaConfig.pton_system_calls, 0, 1),
)


@dataclass(frozen=True, slots=True)
class _EventKey:
    """Primary key for pairing enter/exit records: (start_ns, tid, event)."""

    start_ns: int
    tid: str
    event: str


@dataclass(frozen=True, slots=True)
class _ThreadEventKey:
    """Secondary key for pairing: (tid, event) without timestamp."""

    tid: str
    event: str


@dataclass(frozen=True, slots=True, eq=False)
class _PendingStart:
    """A buffered enter (>) record awaiting its matching exit record."""

    key: _EventKey
    thread_event_key: _ThreadEventKey
    entry: Dict[str, str]

    @property
    def start_ns(self) -> int:
        return self.key.start_ns


class SysdigLogParser:
    """Core parser that reads a Sysdig JSONL log, pairs enter/exit records,
    extracts entities, generates provenance edges, and flushes to Neo4j."""

    def __init__(
        self,
        log_file: str,
        db_str: str,
        start_event_id: int,
        dry_run: bool = False,
    ) -> None:
        self._log_file = log_file
        # db target: 仅支持 Neo4j，构造时立刻校验以便快速失败
        self._validate_db_target(db_str)
        self._neo4j_writer = None  # lazy-created on first flush

        # dry_run: 只统计不写库（验证/观察用），flush 阶段跳过 DB
        self._dry_run = dry_run or self._resolve_dry_run_env()

        # --- buffers ---
        self._incomplete_events: Dict[_EventKey, Deque[_PendingStart]] = {}
        self._incomplete_events_by_thread: Dict[_ThreadEventKey, Deque[_PendingStart]] = {}
        self._files: Dict[str, FileEntity] = {}
        self._processes: Dict[str, Process] = {}
        self._networks: Dict[str, NetworkEntity] = {}
        self._pending_files: Dict[str, FileEntity] = {}
        self._pending_processes: Dict[str, Process] = {}
        self._pending_networks: Dict[str, NetworkEntity] = {}

        self._incomplete_network_count = 0
        self._no_object_count = 0
        self._syscall_handlers: Dict[Fingerprint, SystemCall] = {}
        self._forward_flow: Dict[str, EventEdge] = {}

        # --- edge queues（按关系类型缓冲；p2p 只在导入结束的最终 flush 写入）---
        self._edge_queues: Dict[str, List[EventEdge]] = {rel: [] for rel in _EDGE_RELS}

        # --- counters ---
        self._event_id = start_event_id
        self._flush_rounds = 0
        self._edge_totals: Dict[str, int] = {rel: 0 for rel in _EDGE_RELS}
        self._total_log_bytes = 0
        self._bytes_read = 0
        self._scanned_lines = 0
        self._processed_event_lines = 0
        self._skipped_log_lines = 0
        self._skipped_reason_counts: Dict[str, int] = {}
        self._skipped_reason_samples: Dict[str, List[str]] = {}
        self._parse_start_millis = 0
        self._last_progress_report_millis = 0

        # --- pairing counters ---
        self._pairing_start_records = 0
        self._pairing_end_records = 0
        self._pairing_exact_matches = 0
        self._pairing_fallback_matched = 0
        self._pairing_fallback_rejected = 0
        self._pairing_fallback_no_partner = 0
        self._pairing_dummy_starts = 0
        self._pairing_dummy_by_event: Dict[str, int] = {}
        self._pairing_start_key_collisions = 0
        self._pairing_ambiguous_fallbacks = 0

        # 同一四元组出现不同协议的冲突次数（保留首个，仅计数上报）
        self._network_protocol_conflicts = 0

        self._flush_edge_limit = self._resolve_flush_edge_limit()
        self._progress_interval_millis = self._resolve_progress_interval_millis()
        self._pairing_tolerance_ns = self._resolve_pairing_tolerance_ns()

        self._register_system_calls()

    # ==================================================================
    # System call registration
    # ==================================================================
    def _register_system_calls(self) -> None:
        # --- 通用方向（MetaConfig 驱动：f2p / p2f / n2p / p2n）---
        for rel, entity_cls, syscall_names, src_idx, dst_idx in _GENERIC_SYSCALL_DIRECTIONS:
            factory = SystemCallFactory(entity_cls, None)
            factory.add_action(self._update_p2p_links)
            factory.add_action(self._make_edge_action(rel, src_idx, dst_idx))
            for sc_name in syscall_names:
                sc = factory.get_system_call(sc_name)
                self._syscall_handlers[sc.fingerprint] = sc

        # --- execve (special: PtoP + file edge) ---
        def _execve_action(
            start_rec: Dict[str, str],
            end_rec: Dict[str, str],
            start_entities: List[Optional[Entity]],
            end_entities: List[Optional[Entity]],
        ) -> None:
            p_start = start_entities[0]  # Process
            p_end = end_entities[0]  # Process
            p_end_node = EntityNode(p_end)
            f = start_entities[1]  # FileEntity (executable)
            file_node = EntityNode(f)
            exe_path = start_rec.get("exepath", "")
            ts_start = start_rec.get("timestamp", "0.0")
            ts_end = end_rec.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            args = end_rec.get("args", "")

            if "res=0" in args:
                if f.path != "<NA>":
                    edge = EventEdge(
                        file_node, p_end_node, self._next_event_id(),
                        "execve", 0, start_ns, end_ns,
                    )
                    self._queue_edge("f2p", edge)

                parent_match = _PARENT_PATTERN.search(args)
                if parent_match:
                    pid_parent = parent_match.group("parentPID")
                    name_parent = parent_match.group("parent")
                    key_parent = pid_parent + name_parent
                    parent = self._get_or_create_process(
                        key_parent, pid_parent, name_parent, exe_path
                    )
                    parent_node = EntityNode(parent)
                    forward_edge = EventEdge(
                        parent_node, p_end_node, self._next_event_id(),
                        "execve", 0, start_ns, end_ns,
                    )
                    self._queue_edge("p2p", forward_edge)
                    self._forward_flow[key_parent] = forward_edge

        execve_sc = SystemCall(
            Fingerprint("execve", FileEntity, None),
        ).add_action(_execve_action)
        self._syscall_handlers[execve_sc.fingerprint] = execve_sc

        # --- accept (special: NtoP) ---
        def _accept_action(
            start_rec: Dict[str, str],
            end_rec: Dict[str, str],
            start_entities: List[Optional[Entity]],
            end_entities: List[Optional[Entity]],
        ) -> None:
            p = end_entities[0]  # Process
            p_node = EntityNode(p)
            n = end_entities[1]  # NetworkEntity
            if n is None:
                # 无完整五元组的 accept（如内核 fd 地址）-> 不建边，可审计
                self._incomplete_network_count += 1
                return
            n_node = EntityNode(n)
            ts_end = end_rec.get("timestamp", "0.0")
            end_ns = self._parse_timestamp_ns(ts_end)

            edge = EventEdge(
                n_node, p_node, self._next_event_id(),
                "accept", 0, end_ns, end_ns,
            )
            self._queue_edge("n2p", edge)

        accept_sc = SystemCall(
            Fingerprint("accept", None, NetworkEntity),
        ).add_action(_accept_action)
        self._syscall_handlers[accept_sc.fingerprint] = accept_sc

        # --- fcntl (special: NtoP) ---
        def _fcntl_action(
            start_rec: Dict[str, str],
            end_rec: Dict[str, str],
            start_entities: List[Optional[Entity]],
            end_entities: List[Optional[Entity]],
        ) -> None:
            ts_start = start_rec.get("timestamp", "0.0")
            ts_end = end_rec.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            p = end_entities[0]  # Process
            p_node = EntityNode(p)
            n = end_entities[1]  # NetworkEntity
            if n is None:
                self._incomplete_network_count += 1
                return
            n_node = EntityNode(n)

            edge = EventEdge(
                n_node, p_node, self._next_event_id(),
                "fcntl", 0, start_ns, end_ns,
            )
            self._queue_edge("n2p", edge)

        fcntl_sc = SystemCall(
            Fingerprint("fcntl", None, NetworkEntity),
        ).add_action(_fcntl_action)
        self._syscall_handlers[fcntl_sc.fingerprint] = fcntl_sc

        # --- rename (special: PtoF + FtoP) ---
        def _rename_action(
            start_rec: Dict[str, str],
            end_rec: Dict[str, str],
            start_entities: List[Optional[Entity]],
            end_entities: List[Optional[Entity]],
        ) -> None:
            ts_start = start_rec.get("timestamp", "0.0")
            ts_end = end_rec.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            args = end_rec.get("args", "")
            rename_match = _RENAME_PATHS.search(args)
            if not rename_match:
                return

            old_path = self._normalize_rename_path(rename_match.group("old"))
            new_path = self._normalize_rename_path(rename_match.group("new"))

            p = start_entities[0]  # Process
            p_node = EntityNode(p)

            old_file = self._get_or_create_file(old_path, old_path)
            old_f_node = EntityNode(old_file)
            f2p_edge = EventEdge(
                old_f_node, p_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns,
            )
            self._queue_edge("f2p", f2p_edge)

            new_file = self._get_or_create_file(new_path, new_path)
            new_f_node = EntityNode(new_file)
            p2f_edge = EventEdge(
                p_node, new_f_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns,
            )
            self._queue_edge("p2f", p2f_edge)

        rename_sc = SystemCall(
            Fingerprint("rename", None, None),
        ).add_action(_rename_action)
        self._syscall_handlers[rename_sc.fingerprint] = rename_sc

    @staticmethod
    def _normalize_rename_path(path: Optional[str]) -> str:
        if path is None:
            return ""
        normalized = path.strip()
        if normalized.endswith(")") and "(" in normalized:
            normalized = normalized[normalized.index("(") + 1:-1].strip()
        return normalized

    @staticmethod
    def _parse_timestamp_ns(ts: str) -> int:
        parts = ts.split(".")
        if len(parts) < 2:
            return int(parts[0]) * 1_000_000_000
        return int(parts[0]) * 1_000_000_000 + int(parts[1])

    def _next_event_id(self) -> int:
        v = self._event_id
        self._event_id += 1
        return v

    # ==================================================================
    # Main parsing loop
    # ==================================================================
    def parse_entry(self) -> None:
        start_date = datetime.now()
        print(f"Log parse Start::::::::::::::::{start_date}")

        log = self._log_file
        self._total_log_bytes = os.path.getsize(log)
        self._bytes_read = 0
        self._scanned_lines = 0
        self._processed_event_lines = 0
        self._parse_start_millis = int(time.time() * 1000)
        self._last_progress_report_millis = self._parse_start_millis

        print(
            f"Import config: logSize={self._format_bytes(self._total_log_bytes)}, "
            f"flushEdgeLimit={self._flush_edge_limit}, "
            f"progressInterval={self._progress_interval_millis // 1000}s, "
            f"pairingToleranceNs={self._pairing_tolerance_ns}, "
            f"dryRun={self._dry_run}"
        )
        self._maybe_report_progress(True, "startup")

        parse_failure: Optional[Exception] = None

        try:
            with open(log, "r", buffering=1024 * 1024, encoding="utf-8") as fh:
                while True:
                    raw_line = fh.readline()
                    if not raw_line:
                        break
                    self._scanned_lines += 1
                    self._bytes_read = fh.tell()
                    current_line = raw_line.rstrip("\n").rstrip("\r")
                    if not current_line:
                        # 空行静默跳过（不计数）
                        continue

                    should_flush = False
                    try:
                        record = parse_jsonl_entry(current_line)
                        if record is None:
                            raise ValueError("Sysdig entry could not be parsed")
                        self._validate_parsed_entry(record)

                        if record.get("direction") == ">":
                            self._store_incomplete_start(record)
                        else:
                            self._processed_event_lines += 1
                            self._process_event(record)
                            should_flush = self._should_flush_buffered_records()
                    except Exception as e:
                        self._log_skipped_line(self._scanned_lines, current_line, e)

                    if should_flush:
                        self._flush_buffered_records(False)

                    if self._scanned_lines % _PROGRESS_CHECK_LINE_INTERVAL == 0:
                        self._maybe_report_progress(False, "parsing")

                self._bytes_read = self._total_log_bytes
                self._maybe_report_progress(True, "parsing")

        except FileNotFoundError:
            parse_failure = Exception(f"Failed to open sysdig log file: {self._log_file}")
        except Exception as e:
            parse_failure = e

        if parse_failure:
            raise parse_failure

        try:
            print(f"log line#: {self._processed_event_lines}")
            print(
                f"np: {self._edge_totals['n2p']} "
                f"pn: {self._edge_totals['p2n']} "
                f"pf: {self._edge_totals['p2f']} "
                f"fp: {self._edge_totals['f2p']} "
                f"pp: {self._edge_totals['p2p']}"
            )
            print(
                f"n:{len(self._networks)} f:{len(self._files)} p:{len(self._processes)}"
            )
            self._print_pairing_summary()
            print(f"skipped log line#: {self._skipped_log_lines}")
            print(f"incomplete network (no full 4-tuple): {self._incomplete_network_count}")
            print(f"no object (pipe/socket/anon_inode): {self._no_object_count}")
            print(
                f"network protocol conflicts (kept first): "
                f"{self._network_protocol_conflicts}"
            )
            self._print_skipped_line_summary()
            self._flush_buffered_records(True)
        finally:
            # 无论成功还是中途异常，都要输出 writer 统计并关闭驱动，
            # 避免连接句柄泄漏到进程退出。
            if self._neo4j_writer is not None:
                self._neo4j_writer.print_summary()
                self._neo4j_writer.close()
                self._neo4j_writer = None

        end_date = datetime.now()
        print(f"Log parse end::::::::::::::::{end_date}")

    # ==================================================================
    # Validation
    # ==================================================================
    def _validate_parsed_entry(self, record: Dict[str, str]) -> None:
        for field in ("eventno", "timestamp", "cpu", "process", "pid",
                      "direction", "event", "latency", "exepath", "args"):
            if field not in record:
                raise ValueError(f"Missing parsed field: {field}")

        int(record["eventno"])
        # Validate timestamp format
        ts = record["timestamp"]
        ts_parts = ts.split(".")
        if len(ts_parts) < 2:
            raise ValueError(f"Timestamp has no nanosecond part: {ts}")
        int(ts_parts[0])
        int(ts_parts[1])

        direction = record["direction"]
        if direction not in (">", "<"):
            raise ValueError(f"Unsupported syscall direction: {direction}")

        # 无进程上下文的记录（proc.pid/proc.name 为 JSON null，典型如内核调度
        # switch 事件）：无法归属到任何进程，永远不会产生边，只会堆积为永不
        # 配对的 pending。按精确理由跳过，保持跳过统计可审计。
        if not record["pid"] or not record["process"]:
            raise ValueError(
                "Record has no process context (proc.pid/proc.name is null)"
            )

        args = record["args"]
        extract_file_and_socket(args)
        extract_size(args)

    # ==================================================================
    # Enter/exit pairing
    # ==================================================================
    def _store_incomplete_start(self, record: Dict[str, str]) -> None:
        self._pairing_start_records += 1
        ts = record.get("timestamp", "0.0")
        start_ns = self._parse_timestamp_ns(ts)
        tid = record.get("pid", "0")
        event = record.get("event", "")

        event_key = _EventKey(start_ns, tid, event)
        thread_key = _ThreadEventKey(tid, event)

        pending = _PendingStart(event_key, thread_key, record)

        if event_key in self._incomplete_events:
            self._pairing_start_key_collisions += 1
        self._incomplete_events.setdefault(event_key, deque()).append(pending)
        self._incomplete_events_by_thread.setdefault(thread_key, deque()).append(pending)

    def _process_event(self, record: Dict[str, str]) -> None:
        self._pairing_end_records += 1
        ts = record.get("timestamp", "0.0")
        end_ns = self._parse_timestamp_ns(ts)
        latency_str = record.get("latency", "0")
        latency_ns = int(latency_str) if latency_str.lstrip('-').isdigit() else 0
        expected_start_ns = end_ns - latency_ns
        tid = record.get("pid", "0")
        event = record.get("event", "")

        # Step 1: exact match by EventKey
        event_key = _EventKey(expected_start_ns, tid, event)
        pending = self._pop_pending_start(event_key)
        if pending is not None:
            self._pairing_exact_matches += 1
        else:
            # Step 2: merged tolerance fallback (time-checked, ambiguity-aware).
            # Replaces the former two-step fallback: the blind FIFO pop (which
            # paired exits with time-inconsistent pendings) and the unreachable
            # dict-scan tolerance level. A wrong partner is never consumed:
            # a missing edge is preferred over a wrong edge.
            pending = self._pair_by_latency_tolerance(end_ns, latency_ns, tid, event)

        if pending is None:
            # Step 3: dummy start
            # 直接构造一个最小化的合成进入记录(args=!dummy!,无 fd 上下文)。
            self._pairing_dummy_starts += 1
            self._pairing_dummy_by_event[event] = (
                self._pairing_dummy_by_event.get(event, 0) + 1
            )
            dummy_record = {
                "raw": record.get("raw", ""),
                "eventno": "0",
                "timestamp": record["timestamp"],
                "cpu": record.get("cpu", "0"),
                "process": record.get("process", ""),
                "pid": record.get("pid", "0"),
                "direction": ">",
                "event": record.get("event", ""),
                "cwd": record.get("cwd", ""),
                "latency": record.get("latency", "0"),
                "exepath": record.get("exepath", ""),
                "args": "!dummy!",
                "proc_args": record.get("proc_args", ""),
                "l4proto": record.get("l4proto", ""),
            }
            # event_key 即上方的精确匹配键（expected_start_ns/tid/event）
            pending = _PendingStart(event_key, _ThreadEventKey(tid, event), dummy_record)

        # Extract entities from both start and end records
        start_rec = pending.entry
        end_rec = record

        start_entities = self._extract_entities(start_rec)
        end_entities = self._extract_entities(end_rec)

        # Build fingerprint and lookup handler
        fp = Fingerprint.to_fingerprint(
            start_rec.get("event", ""),
            start_entities[1] if len(start_entities) > 1 else None,
            end_entities[1] if len(end_entities) > 1 else None,
        )
        handler = self._syscall_handlers.get(fp)
        if handler is not None:
            handler.react(start_rec, end_rec, start_entities, end_entities)
        else:
            # Unmatched fingerprint — log as skipped
            self._log_skipped_line(
                self._scanned_lines,
                start_rec.get("raw", ""),
                f"Unmatched fingerprint: {fp}",
            )

    def _pair_by_latency_tolerance(
        self, end_ns: int, latency_ns: int, tid: str, event: str
    ) -> Optional[_PendingStart]:
        """Single fallback layer: time-checked pairing with ambiguity rejection.

        Sysdig computes evt.latency from the very two records of a pair, so the
        true partner always satisfies
        |observed_latency - declared_latency| <= tolerance.  Candidates that
        fail this check are wrong partners (their own exit was lost) and are
        deliberately left unconsumed so their real exit can still pair later.

        - 0 candidates  -> no pairing (caller falls back to a dummy start)
        - 1 candidate   -> pair
        - >1 candidates -> pair the best only if strictly better than the
          runner-up; otherwise ambiguous, nothing is consumed.
        """
        thread_dq = self._incomplete_events_by_thread.get(_ThreadEventKey(tid, event))
        if not thread_dq:
            self._pairing_fallback_no_partner += 1
            return None

        candidates: List[Tuple[_PendingStart, int]] = []
        for pending in thread_dq:
            if pending.start_ns > end_ns:
                continue
            delta = abs((end_ns - pending.start_ns) - latency_ns)
            if delta <= self._pairing_tolerance_ns:
                candidates.append((pending, delta))

        if not candidates:
            self._pairing_fallback_rejected += 1
            return None
        if len(candidates) == 1:
            self._pairing_fallback_matched += 1
            return self._pop_pending_start(candidates[0][0].key)
        candidates.sort(key=lambda x: x[1])
        if candidates[0][1] < candidates[1][1]:
            self._pairing_fallback_matched += 1
            return self._pop_pending_start(candidates[0][0].key)
        self._pairing_ambiguous_fallbacks += 1
        return None

    def _pop_pending_start(self, key: _EventKey) -> Optional[_PendingStart]:
        dq = self._incomplete_events.get(key)
        if dq is None:
            return None
        pending = dq.popleft()
        if not dq:
            del self._incomplete_events[key]
        # Also remove from thread index
        thread_key = pending.thread_event_key
        thread_dq = self._incomplete_events_by_thread.get(thread_key)
        if thread_dq:
            # Remove the first matching entry
            new_dq = deque()
            removed = False
            for p in thread_dq:
                if not removed and p is pending:
                    removed = True
                    continue
                new_dq.append(p)
            if new_dq:
                self._incomplete_events_by_thread[thread_key] = new_dq
            else:
                del self._incomplete_events_by_thread[thread_key]
        return pending

    # ==================================================================
    # Entity extraction
    # ==================================================================
    def _extract_entities(
        self, record: Dict[str, str]
    ) -> List[Optional[Entity]]:
        entities: List[Optional[Entity]] = [None, None]
        pid = record.get("pid", "")
        process_name = record.get("process", "")
        process_key = pid + process_name
        exe_path = record.get("exepath", "")
        proc_args = record.get("proc_args", "")
        cwd = record.get("cwd", "")
        entities[0] = self._get_or_create_process(
            process_key, pid, process_name, exe_path,
            args=proc_args, cwd=cwd,
        )

        args = record.get("args", "")
        file_socket = extract_file_and_socket(args)
        process_file = extract_process_file(args)

        if "path" in file_socket:
            path = file_socket["path"]
            entities[1] = self._get_or_create_file(path, path)
        elif process_file is not None:
            entities[1] = self._get_or_create_file(process_file, process_file)
        elif "pipe" in file_socket:
            # 管道（pipe）：按设计不构造 File 顶点、也不建边 -> NO_OBJECT
            self._no_object_count += 1
            entities[1] = None
        elif (
            "sip" in file_socket
            and "sport" in file_socket
            and "dip" in file_socket
            and "dport" in file_socket
        ):
            entities[1] = self._get_or_create_network(
                file_socket["sip"], file_socket["sport"],
                file_socket["dip"], file_socket["dport"],
                protocol=record.get("l4proto", ""),
            )
        elif "socket" in file_socket:
            # socket 但无完整四元组（如 unix socket `ffff->ffff`、内核 fd 地址）
            self._incomplete_network_count += 1
            entities[1] = None
        else:
            entities[1] = None

        return entities

    # ==================================================================
    # Entity factories
    # ==================================================================
    def _get_or_create_process(
        self,
        process_key: str,
        pid: str,
        process_name: str,
        exe_path: str,
        args: str = "",
        cwd: str = "",
    ) -> Process:
        normalized_exe = self._normalize_optional_text(exe_path)
        normalized_args = self._normalize_optional_text(args)
        normalized_cwd = self._normalize_optional_text(cwd)
        proc = self._processes.get(process_key)
        if proc is not None:
            # 首个非空 wins：已设置的属性不被后续记录覆盖（与 exepath 同规则）
            updated = False
            if proc.exe_path is None and normalized_exe is not None:
                proc.exe_path = normalized_exe
                updated = True
            if proc.args is None and normalized_args is not None:
                proc.args = normalized_args
                updated = True
            if proc.cwd is None and normalized_cwd is not None:
                proc.cwd = normalized_cwd
                updated = True
            if updated:
                # 回填后重新标脏，随下一轮 flush 写库
                self._pending_processes[process_key] = proc
            return proc

        created = Process(pid, process_name, normalized_exe,
                          normalized_args, normalized_cwd)
        self._processes[process_key] = created
        self._pending_processes[process_key] = created
        return created

    @staticmethod
    def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        return normalized if normalized else None

    def _get_or_create_file(self, file_key: str, path: str) -> FileEntity:
        f = self._files.get(file_key)
        if f is not None:
            return f
        created = FileEntity(path)
        self._files[file_key] = created
        self._pending_files[file_key] = created
        return created

    def _get_or_create_network(
        self,
        src_ip: str,
        src_port: str,
        dst_ip: str,
        dst_port: str,
        protocol: str = "",
    ) -> NetworkEntity:
        # fd.l4proto 为 null/<NA>/空 时视为解析不出来，不写入 protocol
        normalized_protocol = self._normalize_optional_text(protocol)
        if normalized_protocol is not None and normalized_protocol in _L4PROTO_NOT_APPLICABLE:
            normalized_protocol = None
        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        n = self._networks.get(key)
        if n is not None:
            if n.protocol is None and normalized_protocol is not None:
                n.protocol = normalized_protocol
                self._pending_networks[key] = n
            elif (
                n.protocol is not None
                and normalized_protocol is not None
                and n.protocol != normalized_protocol
            ):
                # 同一四元组出现不同协议：保留首个，计数上报
                self._network_protocol_conflicts += 1
            return n
        created = NetworkEntity(src_ip, dst_ip, src_port, dst_port, normalized_protocol)
        self._networks[key] = created
        self._pending_networks[key] = created
        return created

    # ==================================================================
    # Action handlers (called by SystemCall.react)
    # ==================================================================
    def _update_p2p_links(
        self,
        start_rec: Dict[str, str],
        end_rec: Dict[str, str],
        start_entities: List[Optional[Entity]],
        end_entities: List[Optional[Entity]],
    ) -> None:
        end_time = end_rec.get("timestamp", "0.0")
        end_ns = self._parse_timestamp_ns(end_time)
        key = end_rec.get("pid", "") + end_rec.get("process", "")

        forward_edge = self._forward_flow.get(key)
        if forward_edge is not None and forward_edge.end_ns < end_ns:
            forward_edge.end_ns = end_ns

    def _make_edge_action(self, rel: str, src_idx: int, dst_idx: int) -> Action:
        """Build the edge action shared by the four MetaConfig-driven directions.

        两端实体都取自进入记录（start_entities[0]=Process，[1]=File/Network），
        (src_idx, dst_idx) 决定边方向；size 取自退出记录 args 的 res=，
        res 缺失或为负（size == -1）时不建边。
        """

        def action(
            start_rec: Dict[str, str],
            end_rec: Dict[str, str],
            start_entities: List[Optional[Entity]],
            end_entities: List[Optional[Entity]],
        ) -> None:
            first_node = EntityNode(start_entities[0])
            second_node = EntityNode(start_entities[1])
            start_ns = self._parse_timestamp_ns(start_rec.get("timestamp", "0.0"))
            end_ns = self._parse_timestamp_ns(end_rec.get("timestamp", "0.0"))
            size = extract_size(end_rec.get("args", ""))
            if size != -1:
                edge = EventEdge(
                    first_node if src_idx == 0 else second_node,
                    first_node if dst_idx == 0 else second_node,
                    self._next_event_id(),
                    start_rec.get("event", ""),
                    size,
                    start_ns,
                    end_ns,
                )
                self._queue_edge(rel, edge)

        return action

    # ==================================================================
    # Edge queue helpers
    # ==================================================================
    def _queue_edge(self, rel: str, edge: EventEdge) -> None:
        """Buffer one edge of the given relation type and bump its total."""
        self._edge_queues[rel].append(edge)
        self._edge_totals[rel] += 1

    # ==================================================================
    # Flush
    # ==================================================================
    def _should_flush_buffered_records(self) -> bool:
        # p2p 边不计入 flush 阈值，只在导入结束的最终 flush 写入。
        total = sum(len(self._edge_queues[rel]) for rel in ("p2f", "f2p", "p2n", "n2p"))
        return total >= self._flush_edge_limit

    def _clear_edge_queues(self, include_p2p: bool) -> None:
        """Empty the buffered edge queues; p2p only when included in the flush."""
        for rel in ("p2f", "f2p", "p2n", "n2p"):
            self._edge_queues[rel].clear()
        if include_p2p:
            self._edge_queues["p2p"].clear()

    def _flush_buffered_records(self, include_process_events: bool) -> None:
        has_pending_nodes = (
            bool(self._pending_files)
            or bool(self._pending_processes)
            or bool(self._pending_networks)
        )
        has_buffered_edges = any(
            self._edge_queues[rel] for rel in ("p2f", "f2p", "p2n", "n2p")
        )
        has_process_edges = include_process_events and bool(self._edge_queues["p2p"])

        if not has_pending_nodes and not has_buffered_edges and not has_process_edges:
            return

        self._flush_rounds += 1
        flush_start = int(time.time() * 1000)
        self._maybe_report_progress(
            True, "final-flush-start" if include_process_events else "flush-start"
        )
        print(
            f"Flushing parser buffers #{self._flush_rounds} "
            f"files={len(self._pending_files)} "
            f"processes={len(self._pending_processes)} "
            f"networks={len(self._pending_networks)} "
            f"fp={len(self._edge_queues['f2p'])} "
            f"pf={len(self._edge_queues['p2f'])} "
            f"np={len(self._edge_queues['n2p'])} "
            f"pn={len(self._edge_queues['p2n'])} "
            f"pp={len(self._edge_queues['p2p']) if include_process_events else 0}"
        )

        if self._dry_run:
            self._pending_files.clear()
            self._pending_processes.clear()
            self._pending_networks.clear()
            self._clear_edge_queues(include_process_events)
            elapsed = int(time.time() * 1000) - flush_start
            print(
                f"Flush #{self._flush_rounds} [dry-run] skipped DB write, "
                f"completed in {self._format_duration(elapsed)}."
            )
            return

        self._flush_neo4j(include_process_events)

    def _flush_neo4j(self, include_process_events: bool) -> None:
        """Write the current buffers into Neo4j (vertices first, then edges).

        The writer is created lazily so dry-run runs never touch Neo4j.
        Vertices are MERGEd idempotently; edges are MERGEd on (event_id) so a
        repeated run does not create duplicates. Buffers are cleared afterwards
        so the next flush round starts empty.
        """
        if self._neo4j_writer is None:
            self._neo4j_writer = Neo4jWriter()
            self._neo4j_writer.create_schema()

        writer = self._neo4j_writer

        flush_start = int(time.time() * 1000)
        writer.insert_processes(self._pending_processes.values())
        writer.insert_files(self._pending_files.values())
        writer.insert_networks(self._pending_networks.values())

        if include_process_events:
            writer.insert_edges(self._edge_queues["p2p"], "p2p")
        writer.insert_edges(self._edge_queues["p2f"], "p2f")
        writer.insert_edges(self._edge_queues["f2p"], "f2p")
        writer.insert_edges(self._edge_queues["p2n"], "p2n")
        writer.insert_edges(self._edge_queues["n2p"], "n2p")

        self._pending_files.clear()
        self._pending_processes.clear()
        self._pending_networks.clear()
        self._clear_edge_queues(include_process_events)

        elapsed = int(time.time() * 1000) - flush_start
        print(f"Flush #{self._flush_rounds} [neo4j] completed in {self._format_duration(elapsed)}.")

    # ==================================================================
    # Progress reporting
    # ==================================================================
    def _maybe_report_progress(self, force: bool, phase: str) -> None:
        now = int(time.time() * 1000)
        if not force and now - self._last_progress_report_millis < self._progress_interval_millis:
            return
        self._last_progress_report_millis = now

        safe_bytes = (
            min(self._bytes_read, self._total_log_bytes)
            if self._total_log_bytes > 0
            else self._bytes_read
        )
        elapsed = max(1, now - self._parse_start_millis)
        progress = (
            (safe_bytes * 100.0 / self._total_log_bytes)
            if self._total_log_bytes > 0
            else 0.0
        )
        mb_per_sec = (safe_bytes / 1048576.0) / (elapsed / 1000.0)
        if safe_bytes > 0 and self._total_log_bytes > safe_bytes:
            eta = self._format_duration(
                int(elapsed * (self._total_log_bytes - safe_bytes) / safe_bytes)
            )
        else:
            eta = "00:00:00"

        print(
            f"[ImportProgress][{phase}] "
            f"{progress:.1f}% "
            f"bytes={self._format_bytes(safe_bytes)}/"
            f"{self._format_bytes(self._total_log_bytes)} "
            f"scannedLines={self._scanned_lines} "
            f"processedEvents={self._processed_event_lines} "
            f"rate={mb_per_sec:.2f} MB/s eta={eta} "
            f"flushes={self._flush_rounds}"
        )

    # ==================================================================
    # Skipped line logging
    # ==================================================================
    def _log_skipped_line(
        self, line_no: int, line: str, reason: object
    ) -> None:
        self._skipped_log_lines += 1
        reason_str = str(reason)
        self._skipped_reason_counts[reason_str] = (
            self._skipped_reason_counts.get(reason_str, 0) + 1
        )
        samples = self._skipped_reason_samples.setdefault(reason_str, [])
        if len(samples) < _SKIP_SAMPLE_LIMIT_PER_REASON:
            samples.append(line)

    def _print_skipped_line_summary(self) -> None:
        if not self._skipped_reason_counts:
            return
        sorted_reasons = sorted(
            self._skipped_reason_counts.items(),
            key=lambda x: -x[1],
        )[:_SKIP_SUMMARY_REASON_LIMIT]
        print("Skipped line summary (top reasons):")
        for reason, count in sorted_reasons:
            samples = self._skipped_reason_samples.get(reason, [])
            print(f"  [{count}x] {reason}")
            for s in samples:
                print(f"    sample: {s[:200]}")

    def _print_pairing_summary(self) -> None:
        print(
            f"pairing: startRecords={self._pairing_start_records} "
            f"endRecords={self._pairing_end_records} "
            f"exactMatches={self._pairing_exact_matches} "
            f"tolerancePaired={self._pairing_fallback_matched} "
            f"toleranceRejected={self._pairing_fallback_rejected} "
            f"noPendingPartner={self._pairing_fallback_no_partner} "
            f"dummyStarts={self._pairing_dummy_starts} "
            f"startKeyCollisions={self._pairing_start_key_collisions} "
            f"ambiguousFallbacks={self._pairing_ambiguous_fallbacks}"
        )
        if self._pairing_dummy_by_event:
            top = sorted(self._pairing_dummy_by_event.items(), key=lambda x: -x[1])[:10]
            breakdown = ", ".join(f"{name}={count}" for name, count in top)
            print(f"dummy starts by syscall (top {len(top)}): {breakdown}")

    # ==================================================================
    # Configuration resolution
    # ==================================================================
    def _resolve_flush_edge_limit(self) -> int:
        raw = os.environ.get(_FLUSH_EDGE_LIMIT_ENV)
        if raw is not None:
            try:
                v = int(raw.strip())
                if v > 0:
                    return v
            except ValueError:
                pass
        return _DEFAULT_FLUSH_EDGE_LIMIT

    def _resolve_progress_interval_millis(self) -> int:
        raw = os.environ.get(_PROGRESS_INTERVAL_SECONDS_ENV)
        if raw is not None:
            try:
                v = int(raw.strip())
                if v > 0:
                    return v * 1000
            except ValueError:
                pass
        return _DEFAULT_PROGRESS_INTERVAL_SECONDS * 1000

    def _resolve_pairing_tolerance_ns(self) -> int:
        raw = os.environ.get(_PAIRING_TOLERANCE_NS_ENV)
        if raw is not None:
            try:
                v = int(raw.strip())
                if v >= 0:
                    return v
            except ValueError:
                pass
        return _PAIRING_FALLBACK_TOLERANCE_NANOS

    @staticmethod
    def _validate_db_target(db_str: str) -> None:
        if db_str != "neo4j":
            raise ValueError(
                f"Unsupported database backend '{db_str}'. Supported: neo4j"
            )

    @staticmethod
    def _resolve_dry_run_env() -> bool:
        raw = os.environ.get(_DRY_RUN_ENV)
        return raw is not None and raw.strip().lower() in ("1", "true", "yes")

    # ==================================================================
    # Formatting helpers
    # ==================================================================
    @staticmethod
    def _format_bytes(bytes_: int) -> str:
        if bytes_ <= 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(bytes_)
        ui = 0
        while value >= 1024.0 and ui < len(units) - 1:
            value /= 1024.0
            ui += 1
        return f"{value:.2f} {units[ui]}"

    @staticmethod
    def _format_duration(duration_millis: int) -> str:
        total_seconds = max(0, duration_millis // 1000)
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
