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
        log_file: object,  # Union[str, ScapSource]
        db_str: str,
        start_event_id: int,
        dry_run: bool = False,
        neo4j_database: Optional[str] = None,
        scenario_name: Optional[str] = None,
    ) -> None:
        self._log_source = log_file
        self._scenario_name = scenario_name
        self._log_file = getattr(self._log_source, "scap_path", str(self._log_source))
        # 目标 Neo4j 数据库（None 时由 Neo4jWriter 回落到 NEO4J_DATABASE/neo4j）。
        # 每个攻击场景导入独立数据库，event_id 从 1 开始且仅在场景库内唯一。
        self._neo4j_database = neo4j_database
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

        # 出现在边端点上的顶点键（全量累积）。实体在 extract_entities 阶段
        # 就进入 pending（早于"该事件是否建边"的判断），不过滤会把从未参与
        # 任何边的孤立顶点写进图库；flush 时按本集合过滤。
        self._edge_vertex_keys = {"process": set(), "file": set(), "network": set()}

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
        self._record_edge_vertices(edge)
        self._edge_queues.queue(rel, edge)

    def _record_edge_vertices(self, edge: EventEdge) -> None:
        """登记一条边的两端顶点：键入 _edge_vertex_keys 供 flush 过滤孤立
        顶点，同时把端点标脏放回待写清单。

        后者是正确性不变式（见 EntityRegistry.mark_file_referenced）：
        顶点只在"第一次创建"时进入待写清单，而清单随每轮 flush 清空；
        若顶点创建后隔了 flush 边界才首次参与建边，不标脏则它永远不再
        入清单，写边时 MATCH 不到端点而静默丢边。前提：边端点实体必须
        来自 registry（extract_entities / get_or_create_*），当前所有
        建边路径均满足。"""
        for node in (edge.source, edge.sink):
            if node is None:
                continue
            if node.file is not None:
                self._edge_vertex_keys["file"].add(node.file.path)
                self._registry.mark_file_referenced(node.file)
            elif node.network is not None:
                self._edge_vertex_keys["network"].add(node.network.src_and_dst_ip)
                self._registry.mark_network_referenced(node.network)
            elif node.process is not None:
                self._edge_vertex_keys["process"].add(node.process.pid_and_name)
                self._registry.mark_process_referenced(node.process)

    def get_or_create_process(self, process_key, pid, process_name, exe_path):
        return self._registry.get_or_create_process(
            process_key, pid, process_name, exe_path
        )

    def get_or_create_file(self, file_key, path):
        return self._registry.get_or_create_file(file_key, path)

    def entity_from_descriptor(self, record, file_socket):
        """fd 描述符 dict -> 实体（供 sendfile 这类双 fd 系统调用复用）。"""
        return self._registry.entity_from_descriptor(record, file_socket)

    def get_or_create_network(self, sip, sport, dip, dport, protocol=""):
        return self._registry.get_or_create_network(
            sip, sport, dip, dport, protocol=protocol
        )

    def register_forward_flow(self, key: str, edge: EventEdge) -> None:
        self._edge_queues.register_forward(key, edge)

    def extend_forward_flow(self, key: str, end_ns: int) -> None:
        self._edge_queues.extend_forward(key, end_ns)

    def note_incomplete_network(self) -> None:
        self._registry.note_incomplete_network()

    def note_connect_in_progress(self) -> None:
        self._registry.note_connect_in_progress()

    # ==================================================================
    # Main parsing loop
    # ==================================================================
    def parse_entry(self) -> None:
        start_date = datetime.now()
        print(f"Log parse Start::::::::::::::::{start_date}")

        src = self._log_source
        if hasattr(src, "stream_lines"):
            scap_p = getattr(src, "scap_path", "stream.scap")
            if os.path.exists(scap_p):
                self._total_log_bytes = os.path.getsize(scap_p)
            else:
                self._total_log_bytes = 0
            scenario = self._scenario_name or os.path.splitext(os.path.basename(scap_p))[0]
            line_iterator = src.stream_lines()
        else:
            log_str = str(src)
            self._total_log_bytes = os.path.getsize(log_str) if os.path.exists(log_str) else 0
            scenario = self._scenario_name or os.path.splitext(os.path.basename(log_str))[0]
            line_iterator = open(log_str, "rb", buffering=1024 * 1024)

        self._bytes_read = 0
        self._scanned_lines = 0
        self._processed_event_lines = 0
        self._progress.begin()

        print(
            f"Import config: scenario={scenario}, "
            f"neo4jDatabase={self._neo4j_database or '<NEO4J_DATABASE/neo4j>'}, "
            f"source={src}, "
            f"logSize={format_bytes(self._total_log_bytes)}, "
            f"flushEdgeLimit={self._flush_edge_limit}, "
            f"progressInterval={self._progress_interval_millis // 1000}s, "
            f"pairingToleranceNs={self._pairing.tolerance_ns}, "
            f"dryRun={self._dry_run}"
        )
        self._report_progress(True, "startup")

        parse_failure: Optional[Exception] = None

        try:
            for raw_line in line_iterator:
                if not raw_line:
                    continue
                self._scanned_lines += 1
                if isinstance(raw_line, str):
                    current_line = raw_line.rstrip("\n").rstrip("\r").encode("utf-8")
                    self._bytes_read += len(current_line)
                else:
                    current_line = raw_line.rstrip(b"\n").rstrip(b"\r")
                    self._bytes_read += len(current_line)
                if not current_line:
                    continue

                should_flush = False
                try:
                    record = parse_jsonl_entry(current_line)
                    if record is None:
                        raise ValueError("Sysdig entry could not be parsed")
                    validate_parsed_entry(record)

                    if record.get("direction") == ">":
                        self._registry.observe_fd_start(record)
                        self._pairing.add_start(record)
                    else:
                        self._processed_event_lines += 1
                        self._process_event(record)
                        should_flush = self._edge_queues.should_flush(
                            self._flush_edge_limit
                        )
                except UnicodeDecodeError:
                    raise
                except Exception as e:
                    self._skip_logger.log(self._scanned_lines, current_line, e)

                if should_flush:
                    self._flush_buffered_records(False)

                if self._scanned_lines % _PROGRESS_CHECK_LINE_INTERVAL == 0:
                    self._report_progress(False, "parsing")

            if hasattr(line_iterator, "close"):
                line_iterator.close()
            self._report_progress(True, "parsing")

        except FileNotFoundError:
            parse_failure = Exception(f"Failed to open sysdig log file: {self._log_file}")
        except Exception as e:
            parse_failure = e

        if parse_failure:
            # 失败路径不做最终 flush（避免写入半份数据），但仍要关闭驱动：
            # 批量导入 fail-fast 时不能把连接句柄泄漏给后续场景。
            if self._neo4j_writer is not None:
                self._neo4j_writer.close()
                self._neo4j_writer = None
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
            print(
                f"connect EINPROGRESS edges built (non-blocking connect): "
                f"{self._registry.connect_in_progress_count}"
            )
            print(
                f"no object (unmodeled fd: eventfd/anon_inode/dir/...): "
                f"{self._registry.no_object_count}"
            )
            ua = self._registry.unix_audit
            print(
                f"unix socket (filesystem-path model): "
                f"path={ua['unix_path']} "
                f"fdtableResolved={ua['unix_resolved_via_fdtable']} "
                f"unresolved={ua['unix_unresolved']} "
                f"abstractSkipped={ua['unix_abstract_skipped']} "
                f"netlinkSkipped={ua['netlink_skipped']}"
            )
            print(
                f"network protocol conflicts (kept first): "
                f"{self._registry.network_protocol_conflicts}"
            )
            ft = self._registry.fd_table_stats()
            print(
                f"pipe fd-table: registered={ft['pipes_registered']} "
                f"forkInherited={ft['fork_inherited']} "
                f"dupCopied={ft['dup_copied']} fcntlDupfd={ft['fcntl_dupfd']} "
                f"closeInvalidated={ft['close_invalidated']} "
                f"fdOverwritten={ft['fd_overwritten']} "
                f"resolved={ft['resolve_hits']} "
                f"fallbackSentinel={ft['resolve_misses']}"
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
        # 供批量导入汇总：各场景的处理行数、顶点/边规模与耗时。
        return {
            "scenario": os.path.splitext(os.path.basename(self._log_file))[0],
            "processed_event_lines": self._processed_event_lines,
            "skipped_lines": self._skip_logger.skipped_count,
            "vertices": {
                "process": self._registry.process_count,
                "file": self._registry.file_count,
                "network": self._registry.network_count,
            },
            "edges": dict(self._edge_queues.totals),
            "flush_rounds": self._flush_rounds,
            "elapsed_seconds": (end_date - start_date).total_seconds(),
            "dry_run": self._dry_run,
        }

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

        # fd 生命周期表退出侧钩子（pipe 登记 / clone 继承 / dup、fcntl
        # 完成复制）放在实体抽取与分发之后：close/dup 事件自身的抽取仍
        # 能看到操作前的映射状态。
        self._registry.observe_fd_end(record)

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
            self._neo4j_writer = Neo4jWriter(database=self._neo4j_database)
            self._neo4j_writer.create_schema()

        writer = self._neo4j_writer

        used = self._edge_vertex_keys
        processes = [
            p for k, p in self._registry.pending_processes.items()
            if k in used["process"]
        ]
        files = [
            f for k, f in self._registry.pending_files.items()
            if k in used["file"]
        ]
        networks = [
            n for k, n in self._registry.pending_networks.items()
            if k in used["network"]
        ]

        flush_start = int(time.time() * 1000)
        writer.insert_processes(processes)
        writer.insert_files(files)
        writer.insert_networks(networks)

        if include_process_events:
            # 终轮之后再无 flush：仍未被任何边引用的 pending 顶点确定不会
            # 入库，这里给出确定的跳过数供审计。
            skipped_files = sum(
                1 for k in self._registry.pending_files if k not in used["file"]
            )
            skipped_processes = sum(
                1 for k in self._registry.pending_processes
                if k not in used["process"]
            )
            skipped_networks = sum(
                1 for k in self._registry.pending_networks
                if k not in used["network"]
            )
            print(
                f"Edge-less vertices not written: "
                f"files={skipped_files} processes={skipped_processes} "
                f"networks={skipped_networks}"
            )

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
