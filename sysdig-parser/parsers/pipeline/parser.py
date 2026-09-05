"""Core parser: streams a Sysdig JSONL log, pairs enter/exit records,
extracts entities, generates provenance edges, and flushes buffers to Neo4j.

The heavy lifting lives in the collaborators:
    PairingBuffer      enter/exit pairing (pipeline/pairing.py)
    EntityRegistry     vertex dedup/extraction (pipeline/entity_registry.py)
    EdgeQueues         edge buffering + flush threshold (pipeline/edge_queue.py)
    build_handlers     syscall dispatch table (dispatch/handlers.py)
This class owns the main loop, flush orchestration, and writer lifecycle.
"""

import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from ..config import (
    resolve_dry_run,
    resolve_flush_edge_limit,
    resolve_pairing_tolerance_ns,
    resolve_progress_interval_millis,
)
from ..dispatch.handlers import build_handlers
from ..dispatch.system_call import Fingerprint, SystemCall
from ..jsonl.record import parse_jsonl_entry, validate_parsed_entry
from ..model.entities import Entity
from ..model.event_edge import EventEdge
from ..reporting import ProgressReporter, SkipLineLogger, format_bytes, format_duration
from ..storage.neo4j_writer import Neo4jWriter
from .edge_queue import EdgeQueues
from .entity_registry import EntityRegistry
from .pairing import PairingBuffer

_PROGRESS_CHECK_LINE_INTERVAL = 5000


class SysdigLogParser:
    """Reads a Sysdig JSONL log and writes the provenance graph to Neo4j."""

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
        self._dry_run = dry_run or resolve_dry_run()

        # --- pipeline collaborators ---
        self._registry = EntityRegistry()
        self._pairing = PairingBuffer(resolve_pairing_tolerance_ns())
        self._edge_queues = EdgeQueues()
        self._skip_logger = SkipLineLogger()
        self._progress = ProgressReporter(resolve_progress_interval_millis())

        # --- counters ---
        self._event_id = start_event_id
        self._flush_rounds = 0
        self._total_log_bytes = 0
        self._bytes_read = 0
        self._scanned_lines = 0
        self._processed_event_lines = 0

        self._flush_edge_limit = resolve_flush_edge_limit()
        self._progress_interval_millis = resolve_progress_interval_millis()

        self._syscall_handlers: Dict[Fingerprint, SystemCall] = build_handlers(self)

    # ==================================================================
    # ParserContext protocol (used by syscall actions)
    # ==================================================================
    def next_event_id(self) -> int:
        v = self._event_id
        self._event_id += 1
        return v

    def queue_edge(self, rel: str, edge: EventEdge) -> None:
        self._edge_queues.queue(rel, edge)

    def get_or_create_process(self, process_key, pid, process_name, exe_path):
        return self._registry.get_or_create_process(
            process_key, pid, process_name, exe_path
        )

    def get_or_create_file(self, file_key, path):
        return self._registry.get_or_create_file(file_key, path)

    def register_forward_flow(self, key: str, edge: EventEdge) -> None:
        self._edge_queues.register_forward(key, edge)

    def extend_forward_flow(self, key: str, end_ns: int) -> None:
        self._edge_queues.extend_forward(key, end_ns)

    def note_incomplete_network(self) -> None:
        self._registry.note_incomplete_network()

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
        self._progress.begin()

        print(
            f"Import config: logSize={format_bytes(self._total_log_bytes)}, "
            f"flushEdgeLimit={self._flush_edge_limit}, "
            f"progressInterval={self._progress_interval_millis // 1000}s, "
            f"pairingToleranceNs={self._pairing.tolerance_ns}, "
            f"dryRun={self._dry_run}"
        )
        self._report_progress(True, "startup")

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
                        validate_parsed_entry(record)

                        if record.get("direction") == ">":
                            self._pairing.add_start(record)
                        else:
                            self._processed_event_lines += 1
                            self._process_event(record)
                            should_flush = self._edge_queues.should_flush(
                                self._flush_edge_limit
                            )
                    except Exception as e:
                        self._skip_logger.log(self._scanned_lines, current_line, e)

                    if should_flush:
                        self._flush_buffered_records(False)

                    if self._scanned_lines % _PROGRESS_CHECK_LINE_INTERVAL == 0:
                        self._report_progress(False, "parsing")

                self._bytes_read = self._total_log_bytes
                self._report_progress(True, "parsing")

        except FileNotFoundError:
            parse_failure = Exception(f"Failed to open sysdig log file: {self._log_file}")
        except Exception as e:
            parse_failure = e

        if parse_failure:
            raise parse_failure

        try:
            print(f"log line#: {self._processed_event_lines}")
            print(
                f"np: {self._edge_queues.totals['n2p']} "
                f"pn: {self._edge_queues.totals['p2n']} "
                f"pf: {self._edge_queues.totals['p2f']} "
                f"fp: {self._edge_queues.totals['f2p']} "
                f"pp: {self._edge_queues.totals['p2p']}"
            )
            print(
                f"n:{self._registry.network_count} "
                f"f:{self._registry.file_count} "
                f"p:{self._registry.process_count}"
            )
            self._pairing.print_summary()
            print(f"skipped log line#: {self._skip_logger.skipped_count}")
            print(
                f"incomplete network (no full 4-tuple): "
                f"{self._registry.incomplete_network_count}"
            )
            print(f"no object (pipe/socket/anon_inode): {self._registry.no_object_count}")
            print(
                f"network protocol conflicts (kept first): "
                f"{self._registry.network_protocol_conflicts}"
            )
            self._skip_logger.print_summary()
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
    # Event processing
    # ==================================================================
    def _process_event(self, record: Dict[str, str]) -> None:
        start_rec = self._pairing.take_start_record(record)

        # Extract entities from both start and end records
        start_entities = self._registry.extract_entities(start_rec)
        end_entities = self._registry.extract_entities(record)

        # Build fingerprint and lookup handler
        fp = Fingerprint.to_fingerprint(
            start_rec.get("event", ""),
            start_entities[1] if len(start_entities) > 1 else None,
            end_entities[1] if len(end_entities) > 1 else None,
        )
        handler = self._syscall_handlers.get(fp)
        if handler is not None:
            handler.react(start_rec, record, start_entities, end_entities)
        else:
            # Unmatched fingerprint — log as skipped
            self._skip_logger.log(
                self._scanned_lines,
                start_rec.get("raw", ""),
                f"Unmatched fingerprint: {fp}",
            )

    # ==================================================================
    # Flush
    # ==================================================================
    def _flush_buffered_records(self, include_process_events: bool) -> None:
        has_buffered_edges = any(
            self._edge_queues.edges(rel) for rel in ("p2f", "f2p", "p2n", "n2p")
        )
        has_process_edges = include_process_events and bool(self._edge_queues.edges("p2p"))

        if not self._registry.has_pending() and not has_buffered_edges and not has_process_edges:
            return

        self._flush_rounds += 1
        flush_start = int(time.time() * 1000)
        self._report_progress(
            True, "final-flush-start" if include_process_events else "flush-start"
        )
        print(
            f"Flushing parser buffers #{self._flush_rounds} "
            f"files={len(self._registry.pending_files)} "
            f"processes={len(self._registry.pending_processes)} "
            f"networks={len(self._registry.pending_networks)} "
            f"fp={len(self._edge_queues.edges('f2p'))} "
            f"pf={len(self._edge_queues.edges('p2f'))} "
            f"np={len(self._edge_queues.edges('n2p'))} "
            f"pn={len(self._edge_queues.edges('p2n'))} "
            f"pp={len(self._edge_queues.edges('p2p')) if include_process_events else 0}"
        )

        if self._dry_run:
            self._registry.clear_pending()
            self._edge_queues.clear(include_process_events)
            elapsed = int(time.time() * 1000) - flush_start
            print(
                f"Flush #{self._flush_rounds} [dry-run] skipped DB write, "
                f"completed in {format_duration(elapsed)}."
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
        writer.insert_processes(self._registry.pending_processes.values())
        writer.insert_files(self._registry.pending_files.values())
        writer.insert_networks(self._registry.pending_networks.values())

        if include_process_events:
            writer.insert_edges(self._edge_queues.edges("p2p"), "p2p")
        writer.insert_edges(self._edge_queues.edges("p2f"), "p2f")
        writer.insert_edges(self._edge_queues.edges("f2p"), "f2p")
        writer.insert_edges(self._edge_queues.edges("p2n"), "p2n")
        writer.insert_edges(self._edge_queues.edges("n2p"), "n2p")

        self._registry.clear_pending()
        self._edge_queues.clear(include_process_events)

        elapsed = int(time.time() * 1000) - flush_start
        print(f"Flush #{self._flush_rounds} [neo4j] completed in {format_duration(elapsed)}.")

    # ==================================================================
    # Progress reporting
    # ==================================================================
    def _report_progress(self, force: bool, phase: str) -> None:
        self._progress.maybe_report(
            force,
            phase,
            scanned_lines=self._scanned_lines,
            processed_event_lines=self._processed_event_lines,
            bytes_read=self._bytes_read,
            total_log_bytes=self._total_log_bytes,
            flush_rounds=self._flush_rounds,
        )

    # ==================================================================
    # Configuration
    # ==================================================================
    @staticmethod
    def _validate_db_target(db_str: str) -> None:
        if db_str != "neo4j":
            raise ValueError(
                f"Unsupported database backend '{db_str}'. Supported: neo4j"
            )
