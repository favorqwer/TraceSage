import os
from datetime import datetime
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import execute_batch

from .file_entity import FileEntity
from .network_entity import NetworkEntity
from .process import Process
from .event_edge import EventEdge

_DEFAULT_BATCH_SIZE = 10000
_BATCH_SIZE_ENV = "PROGQL_POSTGRES_BATCH_SIZE"


class Postgres:
    def __init__(self, file_map, network_map, process_map,
                 process_file_lst, process_network_lst, process_process_lst,
                 file_process_lst, network_process_lst, db_str, host_id):
        self._file_map = file_map
        self._network_map = network_map
        self._process_map = process_map
        self._process_file_lst = process_file_lst
        self._process_network_lst = process_network_lst
        self._process_process_lst = process_process_lst
        self._file_process_lst = file_process_lst
        self._network_process_lst = network_process_lst
        self._host_id = host_id
        self._is_multi = host_id > 0
        self._db_hostid = host_id if host_id > 0 else 0
        self._batch_size = Postgres._resolve_batch_size()

        parts = db_str.split("/", 1)
        if len(parts) != 2 or parts[0] != "postgres" or not parts[1].strip():
            raise ValueError(
                f"Unsupported database backend '{db_str}'. "
                "sysdig-parser only supports postgres/<dbName>."
            )
        self._db_url = f"postgresql://localhost:5432/{parts[1]}"
        self._username = os.environ.get("PG_USER", "postgres")
        self._password = os.environ.get("PG_PASSWORD", "12345678")

    def insert_records(self):
        self._batch_insert_files()
        self._batch_insert_processes()
        self._batch_insert_networks()
        self._insert_process_events()
        self._insert_file_events(self._process_file_lst)
        self._insert_file_events(self._file_process_lst)
        self._insert_network_events(self._process_network_lst)
        self._insert_network_events(self._network_process_lst)

    def _get_conn(self):
        return psycopg2.connect(self._db_url, user=self._username, password=self._password)

    def _batch_insert_files(self):
        if not self._file_map:
            return
        sql = ("INSERT INTO file (id,ownergroupid,hostname,hostid,name,owneruserid) "
               "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING")
        self._log_batch_start("file")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = [(int(f.uniq_id), f.group_id, self._resolve_host_name(f.host),
                             self._db_hostid, f.path, f.user_id) for f in self._file_map.values()]
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("file")

    def _batch_insert_processes(self):
        if not self._process_map:
            return
        sql = ("INSERT INTO process (id,exename,ownergroupid,hostname,hostid,pid,owneruserid) "
               "VALUES (%s,%s,%s,%s,%s,%s,%s) "
               "ON CONFLICT (id) DO UPDATE SET exename=EXCLUDED.exename "
               "WHERE (process.exename IS NULL OR process.exename='') "
               "AND EXCLUDED.exename IS NOT NULL")
        self._log_batch_start("process")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = []
                    for p in self._process_map.values():
                        exe = p.exe_path if p.exe_path else None
                        pid_norm = self._normalize_pid(p.pid)
                        rows.append((int(p.uniq_id), exe, p.group_id,
                                     self._resolve_host_name(p.host), self._db_hostid,
                                     pid_norm, p.uid))
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("process")

    def _batch_insert_networks(self):
        if not self._network_map:
            return
        sql = ("INSERT INTO network (id,dstip,dstport,hostname,hostid,srcip,srcport) "
               "VALUES (%s,%s::cidr,%s,%s,%s,%s::cidr,%s) ON CONFLICT (id) DO NOTHING")
        self._log_batch_start("network")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = []
                    for n in self._network_map.values():
                        rows.append((
                            int(n.uniq_id),
                            self._empty_to_null(n.dst_address),
                            self._parse_port(n.dst_port),
                            self._resolve_host_name(n.host),
                            self._db_hostid,
                            self._empty_to_null(n.src_address),
                            self._parse_port(n.src_port),
                        ))
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("network")

    def _insert_process_events(self):
        if not self._process_process_lst:
            return
        sql = ("INSERT INTO processevent (id,starttime,endtime,srcid,dstid,optype,"
               "hostname,hostid,eventno) "
               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING")
        self._log_batch_start("process events")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = [(int(e.id), e.start_ns, e.end_ns, int(e.source.id), int(e.sink.id),
                             e.event, self._resolve_event_host(e), self._db_hostid, e.event_no)
                            for e in self._process_process_lst]
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("process events")

    def _insert_file_events(self, edges):
        if not edges:
            return
        sql = ("INSERT INTO fileevent (id,starttime,endtime,srcid,dstid,optype,"
               "hostname,hostid,amount,eventno) "
               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING")
        self._log_batch_start("file events")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = [(int(e.id), e.start_ns, e.end_ns, int(e.source.id), int(e.sink.id),
                             e.event, self._resolve_event_host(e), self._db_hostid,
                             e.size, e.event_no) for e in edges]
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("file events")

    def _insert_network_events(self, edges):
        if not edges:
            return
        sql = ("INSERT INTO networkevent (id,starttime,endtime,srcid,dstid,optype,"
               "hostname,hostid,amount,eventno) "
               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING")
        self._log_batch_start("network events")
        conn = self._get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    rows = [(int(e.id), e.start_ns, e.end_ns, int(e.source.id), int(e.sink.id),
                             e.event, self._resolve_event_host(e), self._db_hostid,
                             e.size, e.event_no) for e in edges]
                    execute_batch(cur, sql, rows, page_size=self._batch_size)
                    conn.commit()
        finally:
            conn.close()
        self._log_batch_end("network events")

    def _log_batch_start(self, label):
        print(f"Batch insert {label} start::::::::::::::::{datetime.now()}")

    def _log_batch_end(self, label):
        print(f"Batch insert {label} end::::::::::::::::{datetime.now()}")

    def _resolve_host_name(self, host):
        if host:
            return host
        return "" if not self._is_multi else str(self._host_id)

    def _resolve_event_host(self, edge):
        if edge.host:
            return edge.host
        if edge.source is not None:
            if edge.source.f is not None:
                return self._resolve_host_name(edge.source.f.host)
            if edge.source.n is not None:
                return self._resolve_host_name(edge.source.n.host)
            if edge.source.p is not None:
                return self._resolve_host_name(edge.source.p.host)
        return self._resolve_host_name("")

    @staticmethod
    def _parse_port(port):
        if not port:
            return 0
        return int(port)

    @staticmethod
    def _normalize_pid(raw_pid):
        if not raw_pid:
            return 0
        digits = "".join(ch for ch in raw_pid if ch.isdigit())
        if not digits:
            return 0
        return int(digits)

    @staticmethod
    def _empty_to_null(value):
        if value is None or value == "":
            return None
        return value

    @staticmethod
    def _resolve_batch_size():
        raw = os.environ.get(_BATCH_SIZE_ENV)
        if raw is not None:
            try:
                v = int(raw.strip())
                if v > 0:
                    return v
            except ValueError:
                pass
        return _DEFAULT_BATCH_SIZE
