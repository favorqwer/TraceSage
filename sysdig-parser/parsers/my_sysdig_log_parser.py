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
from .postgres import Postgres

_DEFAULT_FLUSH_EDGE_LIMIT = 50000
_FLUSH_EDGE_LIMIT_ENV = "PROGQL_SYSDIG_FLUSH_EDGE_LIMIT"
_FLUSH_EDGE_LIMIT_PROPERTY = "progql.sysdig.flush.edge.limit"

_DEFAULT_PROGRESS_INTERVAL_SECONDS = 15
_PROGRESS_INTERVAL_SECONDS_ENV = "PROGQL_SYSDIG_PROGRESS_INTERVAL_SECONDS"
_PROGRESS_INTERVAL_SECONDS_PROPERTY = "progql.sysdig.progress.interval.seconds"

_PROGRESS_CHECK_LINE_INTERVAL = 5000
_SKIP_SAMPLE_LIMIT_PER_REASON = 3
_SKIP_SUMMARY_REASON_LIMIT = 10
_PAIRING_FALLBACK_TOLERANCE_NANOS = 1000

_RENAME_PATHS = re.compile(
    r"oldpath=(?P<old>.+?) newpath=(?P<new>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)"
)
_PARENT_PATTERN = re.compile(r"ptid=(?P<parentPID>\d+)\((?P<parent>.+?)\)")


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
    extracts entities, generates provenance edges, and flushes to PostgreSQL."""

    def __init__(
        self,
        log_file: str,
        db_str: str,
        host_id: int,
        start_uid: int,
        start_event_id: int,
    ) -> None:
        self._log_file = log_file
        self._db_str = db_str
        self._host_id = host_id

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
        self._repu = 0.0
        self._uid = start_uid
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
        self._pairing_fallback_matches = 0
        self._pairing_dummy_starts = 0
        self._pairing_start_key_collisions = 0
        self._pairing_ambiguous_fallbacks = 0

        self._flush_edge_limit = self._resolve_flush_edge_limit()
        self._progress_interval_millis = self._resolve_progress_interval_millis()

        self._register_system_calls()

    # ==================================================================
    # System call registration
    # ==================================================================
    def _register_system_calls(self) -> None:
        # --- FtoP (File → Process) ---
        f2p_factory = SystemCallFactory("FtoP", FileEntity, None)
        f2p_factory.add_action(self._update_p2p_links).add_action(self._add_f2p_event)
        for sc_name in MetaConfig.ftop_system_call:
            sc = f2p_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- PtoF (Process → File) ---
        p2f_factory = SystemCallFactory("PtoF", FileEntity, None)
        p2f_factory.add_action(self._update_p2p_links).add_action(self._add_p2f_event)
        for sc_name in MetaConfig.ptof_system_call:
            sc = p2f_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- NtoP (Network → Process) ---
        n2p_factory = SystemCallFactory("NtoP", NetworkEntity, None)
        n2p_factory.add_action(self._update_p2p_links).add_action(self._add_n2p_event)
        for sc_name in MetaConfig.ntop_system_call:
            sc = n2p_factory.get_system_call(sc_name)
            self._answering[sc.finger_print] = sc

        # --- PtoN (Process → Network) ---
        p2n_factory = SystemCallFactory("PtoN", NetworkEntity, None)
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
            event_no_start = m_start.get("eventno", "0")
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
                        "execve", 0, start_ns, end_ns, int(event_no_start),
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
                        "execve", 0, start_ns, end_ns, int(event_no_start),
                    )
                    self._queue_process_process_edge(forward_link)
                    self._forward_flow[key_parent] = forward_link

        execve_sc = SystemCall(
            "execve", "PtoP",
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
            event_no_end = m_end.get("eventno", "0")

            np_edge = EventEdge(
                n_node, p_node, self._next_event_id(),
                "accept", 0, end_ns, end_ns, int(event_no_end),
            )
            self._queue_network_process_edge(np_edge)

        accept_sc = SystemCall(
            "accept", "NtoP",
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
            event_no = m_start.get("eventno", "0")
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
                "fcntl", 0, start_ns, end_ns, int(event_no),
            )
            self._queue_network_process_edge(np_edge)

        fcntl_sc = SystemCall(
            "fcntl", "NtoP",
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
            event_no_start = m_start.get("eventno", "0")

            old_file = self._get_or_create_file(old_path, old_path)
            old_f_node = EntityNode(old_file)
            fp_edge = EventEdge(
                old_f_node, p_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns, int(event_no_start),
            )
            self._queue_file_process_edge(fp_edge)

            event_no_end = m_end.get("eventno", "0")
            new_file = self._get_or_create_file(new_path, new_path)
            new_f_node = EntityNode(new_file)
            pf_edge = EventEdge(
                p_node, new_f_node, self._next_event_id(),
                "rename", 0, start_ns, end_ns, int(event_no_end),
            )
            self._queue_process_file_edge(pf_edge)

        rename_sc = SystemCall(
            "rename", "PtoF",
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

    def _next_uid(self) -> int:
        v = self._uid
        self._uid += 1
        return v

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
            f"progressInterval={self._progress_interval_millis // 1000}s"
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

                    # Skip continuation lines and lines without exepath
                    if current_line.startswith("....") or "exepath" not in current_line:
                        continue

                    should_flush = False
                    try:
                        line_map = Utils.parse_entry(current_line)
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
        self._print_skipped_line_summary()
        self._flush_buffered_records(True)

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
        matched = pending is not None

        if matched:
            self._pairing_exact_matches += 1
        else:
            # Step 2: fallback to thread + event name
            thread_key = _ThreadEventKey(tid, event)
            thread_queue = self._incomplete_events_by_thread.get(thread_key)
            if thread_queue:
                pending = thread_queue.popleft()
                if pending.key in self._incomplete_events:
                    del self._incomplete_events[pending.key]
                self._pairing_fallback_matches += 1
                matched = True

        if not matched:
            # Step 3: tolerance fallback (within 1000ns)
            candidates = []
            # Fallback: find best match by latency delta
            for ek, dq in self._incomplete_events.items():
                if ek.tid == tid and ek.event == event:
                    if ek.start_ns > end_ns:
                        continue
                    observed_latency = end_ns - ek.start_ns
                    delta = abs(observed_latency - latency_ns)
                    if delta <= _PAIRING_FALLBACK_TOLERANCE_NANOS:
                        candidates.append((ek, delta))
            if len(candidates) == 1:
                pending = self._pop_pending_start(candidates[0][0])
                self._pairing_fallback_matches += 1
                matched = True
            elif len(candidates) > 1:
                # Pick best (lowest delta), reject if ambiguous
                candidates.sort(key=lambda x: x[1])
                if candidates[0][1] < candidates[1][1]:
                    pending = self._pop_pending_start(candidates[0][0])
                    self._pairing_fallback_matches += 1
                    matched = True
                else:
                    self._pairing_ambiguous_fallbacks += 1

        if not matched:
            # Step 4: dummy start
            self._pairing_dummy_starts += 1
            # Java creates a synthetic dummy entry string and re-parses it
            dummy_raw = "0 %s.%09d %s %s (%s) > %s cwd=%s !dummy!  latency=%s exepath=%s" % (
                expected_start_ns // 1000000000,
                expected_start_ns % 1000000000,
                line_map.get("cpu", "0"),
                line_map.get("process", ""),
                line_map.get("pid", "0"),
                line_map.get("event", ""),
                line_map.get("cwd", ""),
                line_map.get("latency", "0"),
                line_map.get("exepath", ""),
            )
            dummy_entry = Utils.parse_entry(dummy_raw)
            if dummy_entry is None:
                dummy_entry = dict(line_map)
            dummy_entry["timestamp"] = line_map["timestamp"]
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
        res[0] = self._get_or_create_process(process_key, pid, process_name, exe_path)

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
        self, process_key: str, pid: str, process_name: str, exe_path: str
    ) -> Process:
        normalized_exe = self._normalize_optional_text(exe_path)
        proc = self._processes.get(process_key)
        if proc is not None:
            if proc.exe_path is None and normalized_exe is not None:
                proc.exe_path = normalized_exe
                self._pending_processes[process_key] = proc
            return proc

        created = Process(
            self._repu, pid, None, None, process_name,
            self._next_uid(), normalized_exe,
        )
        created.host = self._resolve_host_name()
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
        created = FileEntity(self._repu, None, None, path, self._next_uid())
        created.host = self._resolve_host_name()
        self._files[file_key] = created
        self._pending_files[file_key] = created
        return created

    def _get_or_create_network(
        self, src_ip: str, src_port: str, dst_ip: str, dst_port: str
    ) -> NetworkEntity:
        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        n = self._networks.get(key)
        if n is not None:
            return n
        created = NetworkEntity(
            self._repu, src_ip, dst_ip, src_port, dst_port, self._next_uid()
        )
        created.host = self._resolve_host_name()
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
        event_no = m_start.get("eventno", "0")
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
                event, size, start_ns, end_ns, int(event_no),
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
        event_no = m_start.get("eventno", "0")
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
                event, size, start_ns, end_ns, int(event_no),
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
        event_no = m_start.get("eventno", "0")
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
                event, size, start_ns, end_ns, int(event_no),
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
        event_no = m_start.get("eventno", "0")
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
                event, size, start_ns, end_ns, int(event_no),
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

        pg = Postgres(
            dict(self._pending_files),
            dict(self._pending_networks),
            dict(self._pending_processes),
            list(self._process_file_lst),
            list(self._process_network_lst),
            list(self._process_process_lst) if include_process_events else [],
            list(self._file_process_lst),
            list(self._network_process_lst),
            self._db_str,
            self._host_id,
        )
        pg.insert_records()

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
        print(f"Flush #{self._flush_rounds} completed in {self._format_duration(elapsed)}.")

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
            f"fallbackMatches={self._pairing_fallback_matches} "
            f"dummyStarts={self._pairing_dummy_starts} "
            f"startKeyCollisions={self._pairing_start_key_collisions} "
            f"ambiguousFallbacks={self._pairing_ambiguous_fallbacks}"
        )

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

    def _resolve_host_name(self) -> str:
        return str(self._host_id) if self._host_id > 0 else ""

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
