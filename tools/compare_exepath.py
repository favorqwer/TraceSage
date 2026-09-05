#!/usr/bin/env python3
"""One-off: PG vs Neo4j comparison with process identity normalized to
exepath granularity (thread/tid attribution differences factored out)."""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sysdig-parser"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sysdig-parser" / "parsers"))

import psycopg2
from parsers.config import load_dotenv
from parsers.storage.neo4j_writer import Neo4jWriter

load_dotenv()


def norm_ip(ip):
    ip = (ip or "").strip()
    if ip.endswith("/32"):
        ip = ip[:-3]
    elif ip.endswith("/128"):
        ip = ip[:-4]
    return ip


def load_pg(db):
    conn = psycopg2.connect(host="localhost", port=5432, user="postgres",
                            password="12345678", dbname=db)
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM file")
    file_map = {r[0]: (r[1] or "") for r in cur.fetchall()}
    cur.execute("SELECT id, pid, exename FROM process")
    proc_map = {r[0]: (r[1] or "") for r in cur.fetchall()}  # key: pid only (原样还原)
    cur.execute("SELECT id, srcip, srcport, dstip, dstport FROM network")
    net_map = {}
    for rid, sip, sport, dip, dport in cur.fetchall():
        net_map[rid] = (norm_ip(sip), int(sport), norm_ip(dip), int(dport))

    def fkey(eid):
        return ("File", file_map.get(eid, ""))

    def nkey(eid):
        return ("Net", net_map.get(eid, ("", 0, "", 0)))

    def pkey(eid):
        return ("Proc", proc_map.get(eid, ""))

    def resolve(eid):
        if eid in proc_map:
            return pkey(eid)
        if eid in net_map:
            return nkey(eid)
        if eid in file_map:
            return fkey(eid)
        return ("Proc", "?")

    edges = {"file": Counter(), "net": Counter(), "proc": Counter()}
    cur.execute("SELECT srcid, dstid, optype, starttime, endtime, amount FROM fileevent")
    for srcid, dstid, optype, st, et, amount in cur.fetchall():
        if optype == "write":
            s, d = pkey(srcid), fkey(dstid)
        else:
            s, d = fkey(srcid), pkey(dstid)
        edges["file"][(s, d, optype, st, et, amount or 0)] += 1
    cur.execute("SELECT srcid, dstid, optype, starttime, endtime, amount FROM networkevent")
    for srcid, dstid, optype, st, et, amount in cur.fetchall():
        edges["net"][(resolve(srcid), resolve(dstid), optype, st, et, amount or 0)] += 1
    cur.execute("SELECT srcid, dstid, optype, starttime, endtime FROM processevent")
    for srcid, dstid, optype, st, et in cur.fetchall():
        edges["proc"][(pkey(srcid), pkey(dstid), optype, st, et, 0)] += 1
    conn.close()
    return {"files": set(file_map.values()), "procs": set(proc_map.values()),
            "nets": set(net_map.values()), "edges": edges}


def load_neo():
    w = Neo4jWriter()
    d = w._driver

    def fetch(q):
        return list(d.execute_query(q, database_=w._database).records)

    files = {r["file_id"] for r in fetch("MATCH (n:File) RETURN n.file_id AS file_id")}
    procs = {r["exepath"] or "" for r in fetch("MATCH (n:Process) RETURN n.exepath AS exepath")}
    nets = {(norm_ip(r["lip"]), int(r["lport"]), norm_ip(r["rip"]), int(r["rport"]))
            for r in fetch("MATCH (n:Network) RETURN n.lip AS lip, n.lport AS lport, "
                           "n.rip AS rip, n.rport AS rport")}

    def key(rec, side):
        if rec[f"{side}_file"]:
            return ("File", rec[f"{side}_file"])
        if rec[f"{side}_net"] is not None:
            net_id = rec[f"{side}_net"]
            try:
                src, dst = net_id.split("->", 1)
                sip, sport = src.rsplit(":", 1)
                dip, dport = dst.rsplit(":", 1)
                return ("Net", (norm_ip(sip), int(sport), norm_ip(dip), int(dport)))
            except Exception:
                return ("Net", ("", 0, "", 0))
        return ("Proc", rec[f"{side}_exe"] or "")

    edges = {"file": Counter(), "net": Counter(), "proc": Counter()}
    for rel, bucket in (("f2p", "file"), ("p2f", "file"),
                        ("n2p", "net"), ("p2n", "net"), ("p2p", "proc")):
        q = (f"MATCH (a)-[r:{rel}]->(b) RETURN "
             "a.file_id AS a_file, a.network_id AS a_net, a.exepath AS a_exe, "
             "b.file_id AS b_file, b.network_id AS b_net, b.exepath AS b_exe, "
             "r.syscall AS syscall, r.starttime AS st, r.endtime AS et, r.bytes AS bytes")
        for rec in fetch(q):
            t = (key(rec, "a"), key(rec, "b"), rec["syscall"],
                 rec["st"], rec["et"], rec["bytes"] or 0)
            edges[bucket][t] += 1
    w.close()
    return {"files": files, "procs": procs, "nets": nets, "edges": edges}


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else "1_Multi_Stage_Data_Exfiltration_norev"
    pg, neo = load_pg(db), load_neo()
    print(f"PG({db})  files={len(pg['files'])} procs(exepath)={len(pg['procs'])} "
          f"nets={len(pg['nets'])} fEdges={sum(pg['edges']['file'].values())} "
          f"nEdges={sum(pg['edges']['net'].values())} pEdges={sum(pg['edges']['proc'].values())}")
    print(f"Neo4j     files={len(neo['files'])} procs(exepath)={len(neo['procs'])} "
          f"nets={len(neo['nets'])} fEdges={sum(neo['edges']['file'].values())} "
          f"nEdges={sum(neo['edges']['net'].values())} pEdges={sum(neo['edges']['proc'].values())}")

    problems = []
    for name, a, b in (("files", pg["files"], neo["files"]),
                       ("process-exepaths", pg["procs"], neo["procs"]),
                       ("networks", pg["nets"], neo["nets"])):
        oa, ob = Counter(a), Counter(b)
        only_pg, only_neo = oa - ob, ob - oa
        status = "OK" if not only_pg and not only_neo else "DIFF"
        print(f"[{status}] {name}: onlyPG={sum(only_pg.values())} onlyNeo={sum(only_neo.values())}"
              + (f"  onlyPG sample={list(only_pg.elements())[:3]}" if only_pg else "")
              + (f"  onlyNeo sample={list(only_neo.elements())[:3]}" if only_neo else ""))
        if only_pg or only_neo:
            problems.append(name)
    for name in ("file", "net", "proc"):
        ca, cb = pg["edges"][name], neo["edges"][name]
        only_pg, only_neo = ca - cb, cb - ca
        status = "OK" if not only_pg and not only_neo else "DIFF"
        line = f"[{status}] {name}-edges: PG={sum(ca.values())} Neo={sum(cb.values())} " \
               f"onlyPG={sum(only_pg.values())} onlyNeo={sum(only_neo.values())}"
        if only_pg:
            line += f"\n    onlyPG sample={list(only_pg.elements())[:2]}"
        if only_neo:
            line += f"\n    onlyNeo sample={list(only_neo.elements())[:2]}"
        print(line)
        if only_pg or only_neo:
            problems.append(name + "-edges")

    print("\nRESULT: " + ("PASS - " + db + " 与 Neo4j 在 exepath 粒度下完全一致"
                        if not problems else f"FAIL - {problems}"))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
