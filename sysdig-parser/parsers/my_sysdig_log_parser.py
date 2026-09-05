import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable, Dict, Deque, List, Optional, Tuple

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
from .utils import Utils
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


class _EventKey:
    """Primary key for pairing enter/exit records: (start_ns, tid, event)."""

    __slots__ = ("start_ns", "tid", "event")

    def __init__(self, start_ns: int, tid: str, event: str) -> None:
        self.start_ns = start_ns
        self.tid = tid
        self.event = event

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _EventKey):
            return NotImplemented
        return (
            self.start_ns == other.start_ns
            and self.tid == other.tid
            and self.event == other.event
        )

    def __hash__(self) -> int:
        return hash((self.start_ns, self.tid, self.event))


class _ThreadEventKey:
    """Secondary key for pairing: (tid, event) without timestamp."""

    __slots__ = ("tid", "event")

    def __init__(self, tid: str, event: str) -> None:
        self.tid = tid
        self.event = event

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _ThreadEventKey):
            return NotImplemented
        return self.tid == other.tid and self.event == other.event

    def __hash__(self) -> int:
        return hash((self.tid, self.event))


class _PendingStart:
    __slots__ = ("key", "thread_event_key", "entry", "start_ns")

    def __init__(
        self,
        key: _EventKey,
        thread_event_key: _ThreadEventKey,
        entry: Dict[str, str],
    ) -> None:
        self.key = key
        self.thread_event_key = thread_event_key
        self.entry = entry
        self.start_ns = key.start_ns


class MySysdigLogParser:
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
        self._answering: Dict[Fingerprint, SystemCall] = {}
        self._forward_flow: Dict[str, EventEdge] = {}

        # --- edge queues ---
        self._process_file_lst: List[EventEdge] = []
        self._file_process_lst: List[EventEdge] = []
        self._process_network_lst: List[EventEdge] = []
        self._network_process_lst: List[EventEdge] = []
        self._process_process_lst: List[EventEdge] = []

        # --- counters ---
        self._event_id = start_event_id
        self._flush_rounds = 0
        self._total_process_file_edges = 0
        self._total_file_process_edges = 0
        self._total_process_network_edges = 0
        self._total_network_process_edges = 0
        self._total_process_process_edges = 0
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
        # --- FtoP (File → Process) ---
        f2p_factory = SystemCallFactory(FileEntity, None)
        f2p_factory.add_action(self._update_p2p_links).add_action(self._add_f2p_event)
        for sc_name in MetaConfig.ftop_system_call:
            sc = f2p_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- PtoF (Process → File) ---
        p2f_factory = SystemCallFactory(FileEntity, None)
        p2f_factory.add_action(self._update_p2p_links).add_action(self._add_p2f_event)
        for sc_name in MetaConfig.ptof_system_call:
            sc = p2f_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- NtoP (Network → Process) ---
        n2p_factory = SystemCallFactory(NetworkEntity, None)
        n2p_factory.add_action(self._update_p2p_links).add_action(self._add_n2p_event)
        for sc_name in MetaConfig.ntop_system_call:
            sc = n2p_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- PtoN (Process → Network) ---
        p2n_factory = SystemCallFactory(NetworkEntity, None)
        p2n_factory.add_action(self._update_p2p_links).add_action(self._add_p2n_event)
        for sc_name in MetaConfig.pton_system_call:
            sc = p2n_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- execve (special: PtoP + file edge) ---
        def _execve_action(
            m_start: Dict[str, str],
            m_end: Dict[str, str],
            e_start: List[Optional[Entity]],
            e_end: List[Optional[Entity]],
        ) -> None:
            p_start = e_start[0]  # Process
            p_end = e_end[0]  # Process
            p_end_node = EntityNode(p_end)
            f = e_start[1]  # FileEntity (executable)
            file_node = EntityNode(f)
            exe_path = m_start.get("exepath", "")
            ts_start = m_start.get("timestamp", "0.0")
            ts_end = m_end.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            args = m_end.get("args", "")

            if "res=0" in args:
                if f.path != "<NA>":
                    e = EventEdge(
                        file_node, p_end_node, self._next_event_id(),
                        "execve", 0, start_ns, end_ns,
                    )
                    self._queue_file_process_edge(e)

                parent_match = _PARENT_PATTERN.search(args)
                if parent_match:
                    pid_parent = parent_match.group("parentPID")
                    name_parent = parent_match.group("parent")
                    key_parent = pid_parent + name_parent
                    parent = self._get_or_create_process(
                        key_parent, pid_parent, name_parent, exe_path
                    )
                    parent_node = EntityNode(parent)
                    forward_link = EventEdge(
                        parent_node, p_end_node, self._next_event_id(),
                        "execve", 0, start_ns, end_ns,
                    )
                    self._queue_process_process_edge(forward_link)
                    self._forward_flow[key_parent] = forward_link

        execve_sc = SystemCall(
            Fingerprint("execve", FileEntity, None),
        ).add_action(_execve_action)
        self._answering[execve_sc.finger_print] = execve_sc

        # --- accept (special: NtoP) ---
        def _accept_action(
            m_start: Dict[str, str],
            m_end: Dict[str, str],
            e_start: List[Optional[Entity]],
            e_end: List[Optional[Entity]],
        ) -> None:
            p = e_end[0]  # Process
            p_node = EntityNode(p)
            n = e_end[1]  # NetworkEntity
            if n is None:
                # 无完整五元组的 accept（如内核 fd 地址）-> 不建边，可审计
                self._incomplete_network_count += 1
                return
            n_node = EntityNode(n)
            ts_end = m_end.get("timestamp", "0.0")
            end_ns = self._parse_timestamp_ns(ts_end)

            np_edge = EventEdge(
                n_node, p_node, self._next_event_id(),
                "accept", 0, end_ns, end_ns,
            )
            self._queue_network_process_edge(np_edge)

        accept_sc = SystemCall(
            Fingerprint("accept", None, NetworkEntity),
        ).add_action(_accept_action)
        self._answering[accept_sc.finger_print] = accept_sc

        # --- fcntl (special: NtoP) ---
        def _fcntl_action(
            m_start: Dict[str, str],
            m_end: Dict[str, str],
            e_start: List[Optional[Entity]],
            e_end: List[Optional[Entity]],
        ) -> None:
            ts_start = m_start.get("timestamp", "0.0")
            ts_end = m_end.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            p = e_end[0]  # Process
            p_node = EntityNode(p)
            n = e_end[1]  # NetworkEntity
            if n is None:
                self._incomplete_network_count += 1
                return
            n_node = EntityNode(n)

            np_edge = EventEdge(
                n_node, p_node, self._next_event_id(),
                "fcntl", 0, start_ns, end_ns,
            )
            self._queue_network_process_edge(np_edge)

        fcntl_sc = SystemCall(
            Fingerprint("fcntl", None, NetworkEntity),
        ).add_action(_fcntl_action)
        self._answering[fcntl_sc.finger_print] = fcntl_sc

        # --- rename (special: PtoF + FtoP) ---
        def _rename_action(
            m_start: Dict[str, str],
            m_end: Dict[str, str],
            e_start: List[Optional[Entity]],
            e_end: List[Optional[Entity]],
        ) -> None:
            ts_start = m_start.get("timestamp", "0.0")
            ts_end = m_end.get("timestamp", "0.0")
            start_ns = self._parse_timestamp_ns(ts_start)
            end_ns = self._parse_timestamp_ns(ts_end)
            args = m_end.get("args", "")
            rename_match = _RENAME_PATHS.search(args)
            if not rename_match:
                return

            old_path = self._normalize_rename_path(rename_match.group("old"))
            new_path = self._normalize_rename_path(rename_match.group("new"))

            p = e_start[0]  # Process
            p_node = EntityNode(p)

            old_file = self._get_or_create_file(old_path, old_path)
            old_f_node = EntityNode(old_file)
            fp_edge = EventEdge(
                old_f_node, p_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns,
            )
            self._queue_file_process_edge(fp_edge)

            new_file = self._get_or_create_file(new_path, new_path)
            new_f_node = EntityNode(new_file)
            pf_edge = EventEdge(
                p_node, new_f_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns,
            )
            self._queue_process_file_edge(pf_edge)

        rename_sc = SystemCall(
            Fingerprint("rename", None, None),
        ).add_action(_rename_action)
        self._answering[rename_sc.finger_print] = rename_sc

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

        lines = 0
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
                        line_map = Utils.parse_jsonl_entry(current_line)
                        if line_map is None:
                            raise ValueError("Sysdig entry could not be parsed")
                        self._validate_parsed_entry(line_map)

                        if line_map.get("direction") == ">":
                            self._store_incomplete_start(line_map)
                        else:
                            lines += 1
                            self._processed_event_lines = lines
                            self._process_event(line_map)
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
            print(f"log line#: {lines}")
            print(
                f"np: {self._total_network_process_edges} "
                f"pn: {self._total_process_network_edges} "
                f"pf: {self._total_process_file_edges} "
                f"fp: {self._total_file_process_edges} "
                f"pp: {self._total_process_process_edges}"
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
    def _validate_parsed_entry(self, line_map: Dict[str, str]) -> None:
        for field in ("eventno", "timestamp", "cpu", "process", "pid",
                      "direction", "event", "latency", "exepath", "args"):
            if field not in line_map:
                raise ValueError(f"Missing parsed field: {field}")

        int(line_map["eventno"])
        # Validate timestamp format
        ts = line_map["timestamp"]
        ts_parts = ts.split(".")
        if len(ts_parts) < 2:
            raise ValueError(f"Timestamp has no nanosecond part: {ts}")
        int(ts_parts[0])
        int(ts_parts[1])

        direction = line_map["direction"]
        if direction not in (">", "<"):
            raise ValueError(f"Unsupported syscall direction: {direction}")

        # 无进程上下文的记录（proc.pid/proc.name 为 JSON null，典型如内核调度
        # switch 事件）：无法归属到任何进程，永远不会产生边，只会堆积为永不
        # 配对的 pending。按精确理由跳过，保持跳过统计可审计。
        if not line_map["pid"] or not line_map["process"]:
            raise ValueError(
                "Record has no process context (proc.pid/proc.name is null)"
            )

        args = line_map["args"]
        Utils.extract_file_and_socket(args)
        Utils.extract_size(args)

    # ==================================================================
    # Enter/exit pairing
    # ==================================================================
    def _store_incomplete_start(self, line_map: Dict[str, str]) -> None:
        self._pairing_start_records += 1
        ts = line_map.get("timestamp", "0.0")
        start_ns = self._parse_timestamp_ns(ts)
        tid = line_map.get("pid", "0")
        event = line_map.get("event", "")

        event_key = _EventKey(start_ns, tid, event)
        thread_key = _ThreadEventKey(tid, event)

        pending = _PendingStart(event_key, thread_key, line_map)

        if event_key in self._incomplete_events:
            self._pairing_start_key_collisions += 1
        self._incomplete_events.setdefault(event_key, deque()).append(pending)
        self._incomplete_events_by_thread.setdefault(thread_key, deque()).append(pending)

    def _process_event(self, line_map: Dict[str, str]) -> None:
        self._pairing_end_records += 1
        ts = line_map.get("timestamp", "0.0")
        end_ns = self._parse_timestamp_ns(ts)
        latency_str = line_map.get("latency", "0")
        latency_ns = int(latency_str) if latency_str.lstrip('-').isdigit() else 0
        expected_start_ns = end_ns - latency_ns
        tid = line_map.get("pid", "0")
        event = line_map.get("event", "")

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
            _evt_name = line_map.get("event", "")
            self._pairing_dummy_by_event[_evt_name] = (
                self._pairing_dummy_by_event.get(_evt_name, 0) + 1
            )
            dummy_entry = {
                "raw": line_map.get("raw", ""),
                "eventno": "0",
                "timestamp": line_map["timestamp"],
                "cpu": line_map.get("cpu", "0"),
                "process": line_map.get("process", ""),
                "pid": line_map.get("pid", "0"),
                "direction": ">",
                "event": line_map.get("event", ""),
                "cwd": line_map.get("cwd", ""),
                "latency": line_map.get("latency", "0"),
                "exepath": line_map.get("exepath", ""),
                "args": "!dummy!",
                "proc_args": line_map.get("proc_args", ""),
                "l4proto": line_map.get("l4proto", ""),
            }
            sync_key = _EventKey(expected_start_ns, tid, event)
            pending = _PendingStart(sync_key, _ThreadEventKey(tid, event), dummy_entry)

        # Extract entities from both start and end records
        m_start = pending.entry
        m_end = line_map

        e_start = self._extract_entities(m_start)
        e_end = self._extract_entities(m_end)

        # Build fingerprint and lookup handler
        fp = Fingerprint.to_fingerprint(
            m_start.get("event", ""),
            e_start[1] if len(e_start) > 1 else None,
            e_end[1] if len(e_end) > 1 else None,
        )
        handler = self._answering.get(fp)
        if handler is not None:
            handler.react(m_start, m_end, e_start, e_end)
        else:
            # Unmatched fingerprint — log as skipped
            self._log_skipped_line(
                self._scanned_lines,
                m_start.get("raw", ""),
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
        self, m: Dict[str, str]
    ) -> List[Optional[Entity]]:
        res: List[Optional[Entity]] = [None, None]
        pid = m.get("pid", "")
        process_name = m.get("process", "")
        process_key = pid + process_name
        exe_path = m.get("exepath", "")
        proc_args = m.get("proc_args", "")
        cwd = m.get("cwd", "")
        res[0] = self._get_or_create_process(
            process_key, pid, process_name, exe_path,
            args=proc_args, cwd=cwd,
        )

        args = m.get("args", "")
        file_socket = Utils.extract_file_and_socket(args)
        process_file = Utils.extract_process_file(args)

        if "path" in file_socket:
            path = file_socket["path"]
            res[1] = self._get_or_create_file(path, path)
        elif process_file is not None:
            res[1] = self._get_or_create_file(process_file, process_file)
        elif "pipe" in file_socket:
            # 管道（pipe）：按设计不构造 File 顶点、也不建边 -> NO_OBJECT
            self._no_object_count += 1
            res[1] = None
        elif (
            "sip" in file_socket
            and "sport" in file_socket
            and "dip" in file_socket
            and "dport" in file_socket
        ):
            res[1] = self._get_or_create_network(
                file_socket["sip"], file_socket["sport"],
                file_socket["dip"], file_socket["dport"],
                protocol=m.get("l4proto", ""),
            )
        elif "socket" in file_socket:
            # socket 但无完整四元组（如 unix socket `ffff->ffff`、内核 fd 地址）
            self._incomplete_network_count += 1
            res[1] = None
        else:
            res[1] = None

        return res

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
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        end_time = m_end.get("timestamp", "0.0")
        end_ns = self._parse_timestamp_ns(end_time)
        key = m_end.get("pid", "") + m_end.get("process", "")

        ff = self._forward_flow.get(key)
        if ff is not None and ff.end_ns < end_ns:
            ff.end_ns = end_ns

    def _add_p2f_event(
        self,
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        p = e_start[0]
        p_node = EntityNode(p)
        f = e_start[1]
        f_node = EntityNode(f)
        ts_start = m_start.get("timestamp", "0.0")
        ts_end = m_end.get("timestamp", "0.0")
        event = m_start.get("event", "")
        start_ns = self._parse_timestamp_ns(ts_start)
        end_ns = self._parse_timestamp_ns(ts_end)
        args = m_end.get("args", "")
        size = Utils.extract_size(args)
        if size != -1:
            e = EventEdge(
                p_node, f_node, self._next_event_id(),
                event, size, start_ns, end_ns,
            )
            self._queue_process_file_edge(e)

    def _add_f2p_event(
        self,
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        p = e_start[0]
        p_node = EntityNode(p)
        f = e_start[1]
        f_node = EntityNode(f)
        ts_start = m_start.get("timestamp", "0.0")
        ts_end = m_end.get("timestamp", "0.0")
        event = m_start.get("event", "")
        start_ns = self._parse_timestamp_ns(ts_start)
        end_ns = self._parse_timestamp_ns(ts_end)
        args = m_end.get("args", "")
        size = Utils.extract_size(args)
        if size != -1:
            e = EventEdge(
                f_node, p_node, self._next_event_id(),
                event, size, start_ns, end_ns,
            )
            self._queue_file_process_edge(e)

    def _add_p2n_event(
        self,
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        p = e_start[0]
        p_node = EntityNode(p)
        n = e_start[1]
        n_node = EntityNode(n)
        ts_start = m_start.get("timestamp", "0.0")
        ts_end = m_end.get("timestamp", "0.0")
        event = m_start.get("event", "")
        start_ns = self._parse_timestamp_ns(ts_start)
        end_ns = self._parse_timestamp_ns(ts_end)
        args = m_end.get("args", "")
        size = Utils.extract_size(args)
        if size != -1:
            e = EventEdge(
                p_node, n_node, self._next_event_id(),
                event, size, start_ns, end_ns,
            )
            self._queue_process_network_edge(e)

    def _add_n2p_event(
        self,
        m_start: Dict[str, str],
        m_end: Dict[str, str],
        e_start: List[Optional[Entity]],
        e_end: List[Optional[Entity]],
    ) -> None:
        p = e_start[0]
        p_node = EntityNode(p)
        n = e_start[1]
        n_node = EntityNode(n)
        ts_start = m_start.get("timestamp", "0.0")
        ts_end = m_end.get("timestamp", "0.0")
        event = m_start.get("event", "")
        start_ns = self._parse_timestamp_ns(ts_start)
        end_ns = self._parse_timestamp_ns(ts_end)
        args = m_end.get("args", "")
        size = Utils.extract_size(args)
        if size != -1:
            e = EventEdge(
                n_node, p_node, self._next_event_id(),
                event, size, start_ns, end_ns,
            )
            self._queue_network_process_edge(e)

    # ==================================================================
    # Edge queue helpers
    # ==================================================================
    def _queue_process_file_edge(self, edge: EventEdge) -> None:
        self._process_file_lst.append(edge)
        self._total_process_file_edges += 1

    def _queue_file_process_edge(self, edge: EventEdge) -> None:
        self._file_process_lst.append(edge)
        self._total_file_process_edges += 1

    def _queue_process_network_edge(self, edge: EventEdge) -> None:
        self._process_network_lst.append(edge)
        self._total_process_network_edges += 1

    def _queue_network_process_edge(self, edge: EventEdge) -> None:
        self._network_process_lst.append(edge)
        self._total_network_process_edges += 1

    def _queue_process_process_edge(self, edge: EventEdge) -> None:
        self._process_process_lst.append(edge)
        self._total_process_process_edges += 1

    # ==================================================================
    # Flush
    # ==================================================================
    def _should_flush_buffered_records(self) -> bool:
        total = (
            len(self._process_file_lst)
            + len(self._file_process_lst)
            + len(self._process_network_lst)
            + len(self._network_process_lst)
        )
        return total >= self._flush_edge_limit

    def _flush_buffered_records(self, include_process_events: bool) -> None:
        has_pending_nodes = (
            bool(self._pending_files)
            or bool(self._pending_processes)
            or bool(self._pending_networks)
        )
        has_buffered_edges = (
            bool(self._process_file_lst)
            or bool(self._file_process_lst)
            or bool(self._process_network_lst)
            or bool(self._network_process_lst)
        )
        has_process_edges = include_process_events and bool(self._process_process_lst)

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
            f"fp={len(self._file_process_lst)} "
            f"pf={len(self._process_file_lst)} "
            f"np={len(self._network_process_lst)} "
            f"pn={len(self._process_network_lst)} "
            f"pp={len(self._process_process_lst) if include_process_events else 0}"
        )

        if self._dry_run:
            self._pending_files.clear()
            self._pending_processes.clear()
            self._pending_networks.clear()
            self._process_file_lst.clear()
            self._file_process_lst.clear()
            self._process_network_lst.clear()
            self._network_process_lst.clear()
            if include_process_events:
                self._process_process_lst.clear()
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
            writer.insert_p2p_edges(self._process_process_lst)
        writer.insert_p2f_edges(self._process_file_lst)
        writer.insert_f2p_edges(self._file_process_lst)
        writer.insert_p2n_edges(self._process_network_lst)
        writer.insert_n2p_edges(self._network_process_lst)

        self._pending_files.clear()
        self._pending_processes.clear()
        self._pending_networks.clear()
        self._process_file_lst.clear()
        self._file_process_lst.clear()
        self._process_network_lst.clear()
        self._network_process_lst.clear()
        if include_process_events:
            self._process_process_lst.clear()

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
