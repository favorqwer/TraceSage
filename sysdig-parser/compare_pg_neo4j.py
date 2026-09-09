#!/usr/bin/env python3
"""Dev tool: content-level comparison of TraceSage imports in PostgreSQL vs Neo4j.

Both stores were imported from the SAME input (1_Multi_Stage_Data_Exfiltration.jsonl,
the first attack scenario; formerly named attack.jsonl) by the SAME parser.
This tool maps the two onto a common "entity-key edge" space and checks
multiset equality.

Normalized key space:
    File      normalized path
    Network   (src_ip, src_port:int, dst_ip, dst_port:int)  (IPs without cidr /32)
    Process   (pid:int, exepath)

Edges are compared as multisets of (src_key, dst_key, syscall, starttime, endtime,
amount) with the same normalization on both sides.

Usage:
    python compare_pg_neo4j.py [--pg-db 1_Multi_Stage_Data_Exfiltration]
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import psycopg2  # noqa: E402
from parsers.config import load_dotenv  # noqa: E402
from parsers.storage.neo4j_writer import Neo4jWriter  # noqa: E402

load_dotenv()

_PG_USER = os.environ.get("PG_USER", "postgres")
_PG_HOST = os.environ.get("PG_HOST", "localhost")
_PG_PORT = os.environ.get("PG_PORT", "5432")


def _require_env(name: str) -> str:
    """Fetch a required credential from the environment / .env; never default it."""
    value = os.environ.get(name)
    if not value:
        raise SystemExit(
            f"Missing required environment variable {name}. "
            "Set it in the environment or .env (credentials must not be hardcoded)."
        )
    return value


def _pg_conn(db: str):
    return psycopg2.connect(
        host=_PG_HOST, port=_PG_PORT, user=_PG_USER,
        password=_require_env("PG_PASSWORD"), dbname=db,
    )


def _norm_ip(ip) -> str:
    ip = (ip or "").strip()
    if ip.endswith("/32"):
        ip = ip[:-3]
    elif ip.endswith("/128"):
        ip = ip[:-4]
    return ip


def _norm_pid(pid) -> int:
    try:
        return int(pid)
    except (TypeError, ValueError):
        return -1


def _norm_exe(exe) -> str:
    return (exe or "").strip()


# ---------------------------------------------------------------------------
# PostgreSQL side
# ---------------------------------------------------------------------------
def load_pg(db: str):
    conn = _pg_conn(db)
    cur = conn.cursor()

    cur.execute("SELECT id, name FROM file")
    file_map = {r[0]: (r[1] or "") for r in cur.fetchall()}

    cur.execute("SELECT id, pid, exename FROM process")
    proc_map = {
        r[0]: (_norm_pid(r[1]), _norm_exe(r[2])) for r in cur.fetchall()
    }

    cur.execute("SELECT id, srcip, srcport, dstip, dstport FROM network")
    net_map = {}
    for rid, sip, sport, dip, dport in cur.fetchall():
        net_map[rid] = (
            _norm_ip(sip),
            int(sport) if sport is not None else 0,
            _norm_ip(dip),
            int(dport) if dport is not None else 0,
        )

    def pg_entity_key(eid, kind):
        """(entity-kind, key) for a src/dst id in the old PG schema."""
        if kind == "file":
            return ("File", file_map.get(eid, ""))
        if kind == "net":
            return ("Net", net_map.get(eid, (None, None, None, None)))
        if kind == "proc":
            return ("Proc", proc_map.get(eid, (-1, "")))
        raise ValueError(kind)

    def pg_resolve(eid):
        """Resolve an endpoint id against BOTH process/network/file maps
        (old PG networkevent mixes p->n and n->p directions, so either endpoint
        may be a process or a network)."""
        if eid in proc_map:
            return ("Proc", proc_map[eid])
        if eid in net_map:
            return ("Net", net_map[eid])
        if eid in file_map:
            return ("File", file_map[eid])
        return ("Proc", (-1, ""))

    def file_event_rows():
        # old PG: optype write -> src=Process dst=File (p->f); read -> src=File dst=Process
        cur.execute(
            "SELECT srcid, dstid, optype, starttime, endtime, amount FROM fileevent ORDER BY id"
        )
        for srcid, dstid, optype, st, et, amount in cur.fetchall():
            if optype == "write":
                yield (
                    pg_entity_key(srcid, "proc"), pg_entity_key(dstid, "file"),
                    optype, st, et, amount or 0,
                )
            else:
                # read / rename-old: File -> Process
                yield (
                    pg_entity_key(srcid, "file"), pg_entity_key(dstid, "proc"),
                    optype, st, et, amount or 0,
                )

    def net_event_rows():
        cur.execute(
            "SELECT srcid, dstid, optype, starttime, endtime, amount FROM networkevent ORDER BY id"
        )
        for srcid, dstid, optype, st, et, amount in cur.fetchall():
            src = pg_resolve(srcid)
            dst = pg_resolve(dstid)
            yield (src, dst, optype, st, et, amount or 0)

    def proc_event_rows():
        cur.execute(
            "SELECT srcid, dstid, optype, starttime, endtime FROM processevent ORDER BY id"
        )
        for srcid, dstid, optype, st, et in cur.fetchall():
            yield (pg_entity_key(srcid, "proc"), pg_entity_key(dstid, "proc"),
                   optype, st, et, 0)

    pg = {
        "files": set(file_map.values()),
        "processes": set(proc_map.values()),
        "networks": set(net_map.values()),
        "file_edges": list(file_event_rows()),
        "net_edges": list(net_event_rows()),
        "proc_edges": list(proc_event_rows()),
    }
    cur.close()
    conn.close()
    return pg


# ---------------------------------------------------------------------------
# Neo4j side
# ---------------------------------------------------------------------------
def load_neo4j():
    w = Neo4jWriter()
    try:
        return _load_neo4j(w)
    finally:
        w.close()


def _load_neo4j(w: Neo4jWriter):
    db = w.database
    d = w.driver

    def fetch(q):
        return list(d.execute_query(q, database_=db).records)

    files = {r["file_id"] for r in fetch("MATCH (n:File) RETURN n.file_id AS file_id")}
    nets = {
        (_norm_ip(r["lip"]), int(r["lport"]), _norm_ip(r["rip"]), int(r["rport"]))
        for r in fetch(
            "MATCH (n:Network) RETURN n.lip AS lip, n.lport AS lport, "
            "n.rip AS rip, n.rport AS rport"
        )
    }
    procs = {
        (_norm_pid(r["pid"]), _norm_exe(r["exepath"]))
        for r in fetch("MATCH (n:Process) RETURN n.pid AS pid, n.exepath AS exepath")
    }

    def edge_rows(rel, src_label, dst_label):
        q = (
            f"MATCH (a:{src_label})-[r:{rel}]->(b:{dst_label}) "
            "RETURN "
            "  a.file_id AS a_file, a.network_id AS a_net, a.pid AS a_pid, "
            "  a.exepath AS a_exe, "
            "  b.file_id AS b_file, b.network_id AS b_net, b.pid AS b_pid, "
            "  b.exepath AS b_exe, "
            "  r.syscall AS syscall, r.starttime AS st, r.endtime AS et, r.bytes AS bytes"
        )
        rows = []
        for rec in fetch(q):
            s = _neo_entity_key(
                rec["a_file"], rec["a_net"], rec["a_pid"], rec["a_exe"]
            )
            t = _neo_entity_key(
                rec["b_file"], rec["b_net"], rec["b_pid"], rec["b_exe"]
            )
            rows.append((s, t, rec["syscall"], rec["st"], rec["et"], rec["bytes"] or 0))
        return rows

    result = {
        "files": files,
        "processes": procs,
        "networks": nets,
        "file_edges": edge_rows("f2p", "File", "Process")
        + edge_rows("p2f", "Process", "File"),
        "net_edges": edge_rows("n2p", "Network", "Process")
        + edge_rows("p2n", "Process", "Network"),
        "proc_edges": edge_rows("p2p", "Process", "Process"),
    }
    return result


def _neo_entity_key(file_id, net_id, pid, exe):
    # 空串路径也归 File 桶（与 PG 侧空路径 File 对齐），
    # 不能用真值判断，否则 "" 会误入 Proc 分支。
    if file_id is not None:
        return ("File", file_id)
    if net_id:
        # "lip:lport->rip:rport" -> (ip, port:int, ip, port:int)
        try:
            src, dst = net_id.split("->", 1)
            sip, sport = src.rsplit(":", 1)
            dip, dport = dst.rsplit(":", 1)
            return ("Net", (_norm_ip(sip), int(sport), _norm_ip(dip), int(dport)))
        except Exception:
            return ("Net", ("", 0, "", 0))
    return ("Proc", (_norm_pid(pid), _norm_exe(exe)))


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------
def _diff_sets(name, a, b):
    ca, cb = Counter(a), Counter(b)
    only_a = ca - cb
    only_b = cb - ca
    out = []
    if only_a or only_b:
        out.append(
            f"{name}: PG={len(ca)} NEO4J={len(cb)}  "
            f"onlyPG={sum(only_a.values())} onlyNeo={sum(only_b.values())}"
        )
        if only_a:
            out.append("  onlyPG sample: " + str(list(only_a.elements())[:3]))
        if only_b:
            out.append("  onlyNeo sample: " + str(list(only_b.elements())[:3]))
    return out


def _diff_multisets(name, a, b):
    ca, cb = Counter(a), Counter(b)
    only_a = ca - cb
    only_b = cb - ca
    out = []
    if only_a or only_b:
        out.append(
            f"{name}: PG={len(a)} NEO4J={len(b)}  "
            f"onlyPG={sum(only_a.values())} onlyNeo={sum(only_b.values())}"
        )
        if only_a:
            out.append("  onlyPG sample: " + str(list(only_a.elements())[:2]))
        if only_b:
            out.append("  onlyNeo sample: " + str(list(only_b.elements())[:2]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pg-db", default="1_Multi_Stage_Data_Exfiltration")
    args = ap.parse_args()

    pg = load_pg(args.pg_db)
    neo = load_neo4j()

    print(f"PG({args.pg_db}):   files={len(pg['files'])} processes={len(pg['processes'])} "
          f"networks={len(pg['networks'])} fileEdges={len(pg['file_edges'])} "
          f"netEdges={len(pg['net_edges'])} procEdges={len(pg['proc_edges'])}")
    print(f"Neo4j:             files={len(neo['files'])} processes={len(neo['processes'])} "
          f"networks={len(neo['networks'])} fileEdges={len(neo['file_edges'])} "
          f"netEdges={len(neo['net_edges'])} procEdges={len(neo['proc_edges'])}")

    problems = []
    for name, a, b in [
        ("files", pg["files"], neo["files"]),
        ("processes", pg["processes"], neo["processes"]),
        ("networks", pg["networks"], neo["networks"]),
    ]:
        problems += _diff_sets(name, a, b)

    for name, a, b in [
        ("file edges", pg["file_edges"], neo["file_edges"]),
        ("net edges", pg["net_edges"], neo["net_edges"]),
        ("proc edges", pg["proc_edges"], neo["proc_edges"]),
    ]:
        problems += _diff_multisets(name, a, b)

    if problems:
        print("\n===== DIFFERENCES =====")
        print("\n".join(problems))
        return 1

    print("\nRESULT: PASS - PostgreSQL and Neo4j contain the same provenance graph "
          "(same input, normalized entity-key space)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
