#!/usr/bin/env python3
"""Rebuild the benign prior graph in the pipeline's own vocabulary.

Corrections against the first attempt
  * vertex label = role string from provenance/rules/roles.py
    (P.in.multi.few.-, F.wr.single.-.usr, N.listen.single ...), the same
    vocabulary the rule KG and the online matcher use;
  * edge label = syscall name (fallback: action), the same field the rule KG
    hops store -- never a composite of several syscalls, never a result bit;
  * Network vertices are kept and merged per (host, container, role), so a
    long-running client does not manufacture hundreds of "independent" entities;
  * Process / File vertices keep real instance identity, so support counts
    disjoint role instances instead of disjoint connection pairs.

Output: <out>/<scenario>.vf3.bin + <scenario>.graph_stats.json (vertex/edge
label maps, folding statistics).
"""
from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "provenance"))

from provenance.rules.roles import (  # noqa: E402
    RoleContext, RoleCuts, profile_role, WRITE_SYSCALLS,
)

PARSER = ROOT / "output" / "parser-v2"
FOLDS = ROOT / "output" / "rule-kg" / "v1" / "folds"
OUT = ROOT / "output" / "rule-kg" / "flexis-roles-v1" / "graphs"

SCENARIOS: Tuple[Tuple[str, str], ...] = (
    ("1_Web_Exploit_Ransomware", "1_Web_Exploit_Ransomware-r3"),
    ("2_SSH_Spray_Lateral_Exfiltration", "2_SSH_Spray_Lateral_Exfiltration-r3"),
    ("3_Phishing_Beacon_Cryptomining", "3_Phishing_Beacon_Cryptomining-r3"),
    ("4_Repo_Poisoning_Backdoor", "4_Repo_Poisoning_Backdoor-r3"),
    ("5_Exposed_Service_Pivot", "5_Exposed_Service_Pivot-r3"),
    ("6_Web_SQLi_Data_Exfiltration", "6_Web_SQLi_Data_Exfiltration-r3"),
    ("7_DB_Bruteforce_Datawipe", "7_DB_BruteForce_DataWipe-r3"),
    ("8_FTP_WeakCreds_WebShell_Exfiltration", "8_FTP_WeakCreds_WebShell_Exfiltration-r3"),
    ("9_Exposed_Container_Escape", "9_Exposed_Container_Escape-r9"),
    ("10_Tomcat_Weakcreds_DNS_Exfiltration", "10_Tomcat_Weakcreds_DNS_Exfiltration-r3"),
)
OOD: Tuple[Tuple[str, str], ...] = (
    ("TC_E3_THEIA_20180410", "TC_E3_THEIA_20180410-cdm"),
    ("TC_E3_THEIA_20180412", "TC_E3_THEIA_20180412-cdm"),
    ("TC_E3_THEIA_20180413", "TC_E3_THEIA_20180413-cdm"),
    ("TC_E3_TRACE_20180413", "TC_E3_TRACE_20180413-cdm"),
    ("TC_E3_TRACE_20180413_AM", "TC_E3_TRACE_20180413_AM-cdm"),
    ("TC_E3_TRACE_20180413_PM", "TC_E3_TRACE_20180413_PM-cdm"),
)


PRIVATE = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
           "192.168.", "127.", "::1", "fe80")


def peer_ip(endpoints: str) -> str:
    """网络端点 -> 对端 IP：优先取公网一侧，否则取右侧，再否则取整串。"""
    parts = [p for p in str(endpoints or "").split("->") if p]
    ips = [p.rsplit(":", 1)[0] or p for p in parts]
    public = [ip for ip in ips if not ip.startswith(PRIVATE)]
    if public:
        return public[0]
    if ips:
        return ips[-1]
    return str(endpoints or "")


def syscall_of(row: Dict[str, str]) -> str:
    return (row.get("syscall") or "").strip() or (row.get("action") or "").strip() or "unknown"


def endpoint(row: Dict[str, str], side: str, exe_of: Dict[Tuple[str, str, str, str], str]) -> str:
    label = row[f"{side}_label"]
    host = row[f"{side}_host"]
    if label == "Network":
        return f"n:{host}:{row[f'{side}_path']}"
    container = row[f"{side}_container"] or "host"
    if label == "Process":
        exe = exe_of.get((host, container, row[f"{side}_pid"], row[f"{side}_start_ns"]), "")
        return f"p:{host}/{container}:{exe or '<NA>'}"
    return f"f:{host}/{container}:{row[f'{side}_path']}"


def load_cuts(scenario: str) -> RoleCuts:
    path = FOLDS / f"{scenario}.json"
    if not path.is_file():
        return RoleCuts()
    return RoleCuts.from_dict(json.loads(path.read_text(encoding="utf-8")).get("role_cuts"))


NET_GRAIN = "peer"


def build(scenario: str, dirname: str, out_dir: Path) -> dict:
    t0 = time.time()
    base = PARSER / dirname
    nodes_csv, edges_csv = base / "nodes.csv", base / "edges.csv"

    exe_of: Dict[Tuple[str, str, str, str], str] = {}
    with nodes_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("label") == "Process":
                exe_of[(row["host_id"], row.get("container_id") or "host",
                        row["pid"], row["start_ns"])] = row.get("exe_path", "")

    # pass 1: role context (aggregated, no edge storage)
    ctx = RoleContext()
    out_sys: Dict[str, Set[str]] = {}
    in_sys: Dict[str, Set[str]] = {}
    proc_ids: Dict[str, Set[str]] = {}
    writers: Dict[str, Set[str]] = {}
    peers: Dict[str, Set[str]] = {}
    with edges_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            s, d = endpoint(row, "src", exe_of), endpoint(row, "dst", exe_of)
            sc = syscall_of(row)
            ctx.labels.setdefault(s, row["src_label"])
            ctx.labels.setdefault(d, row["dst_label"])
            out_sys.setdefault(s, set()).add(sc)
            in_sys.setdefault(d, set()).add(sc)
            if row["src_label"] == "Process":
                pid = "|".join([row["src_host"], row["src_container"] or "host",
                                row["src_pid"], row["src_start_ns"]])
                proc_ids.setdefault(s, set()).add(pid)
            if sc in WRITE_SYSCALLS and row["dst_label"] == "File":
                writers.setdefault(d, set()).add(
                    "|".join([row["src_host"], row["src_container"] or "host", row["src_pid"]]))
            if "->" in s:
                peers.setdefault(s, set()).add(row["src_path"])
            if "->" in d:
                peers.setdefault(d, set()).add(row["dst_path"])

    ctx.out_edges = {k: [{"syscall": x} for x in v] for k, v in out_sys.items()}
    ctx.in_edges = {k: [{"syscall": x} for x in v] for k, v in in_sys.items()}
    ctx.proc_instances = {k: len(v) for k, v in proc_ids.items()}
    ctx.file_writers = {k: len(v) for k, v in writers.items()}
    ctx.net_peers = {k: len(v) for k, v in peers.items()}
    cuts = load_cuts(scenario)
    roles = {ep: profile_role(ep, ctx, cuts, ctx.labels.get(ep, "")) for ep in ctx.labels}

    # pass 2: vertex identity + arcs
    vertex_of: Dict[Tuple[str, ...], int] = {}
    vlabels: List[str] = []
    arcs: Dict[int, Dict[int, Dict[str, int]]] = {}
    orig: Dict[Tuple[int, int], int] = {}
    with edges_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            s, d = endpoint(row, "src", exe_of), endpoint(row, "dst", exe_of)
            sc = syscall_of(row)
            def vkey(ep: str, side_label: str) -> Tuple[str, ...]:
                role = roles.get(ep, "")
                if side_label == "Network":
                    parts = ep.split(":", 2)
                    host = parts[1] if len(parts) == 3 else ep
                    content = parts[2] if len(parts) == 3 else ep
                    if NET_GRAIN == "connection":
                        return (role, "net", host, content)
                    return (role, "net", host, peer_ip(content))
                parts = ep.split(":", 2)
                host_part, _, content = parts if len(parts) == 3 else ("", "", ep)
                return (role, side_label, host_part, content)
            ks, kd = vkey(s, row["src_label"]), vkey(d, row["dst_label"])
            for k, role in ((ks, roles.get(s, "")), (kd, roles.get(d, ""))):
                if k not in vertex_of:
                    vertex_of[k] = len(vlabels)
                    vlabels.append(role)
            si, di = vertex_of[ks], vertex_of[kd]
            if si == di:
                continue
            arcs.setdefault(si, {}).setdefault(di, {})
            arcs[si][di][sc] = arcs[si][di].get(sc, 0) + 1
            orig[(si, di)] = orig.get((si, di), 0) + 1

    elabels: Dict[str, int] = {}
    csr_row: List[int] = []
    csr_dst: List[int] = []
    csr_lab: List[int] = []
    multi = 0
    orig_counts: List[int] = []
    for src in range(len(vlabels)):
        csr_row.append(len(csr_dst))
        for dst in sorted(arcs.get(src, {})):
            orig_counts.append(orig.get((src, dst), 0))
            counts = arcs[src][dst]
            if len(counts) > 1:
                multi += 1
            top = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
            if top not in elabels:
                elabels[top] = len(elabels)
            csr_dst.append(dst)
            csr_lab.append(elabels[top])
    csr_row.append(len(csr_dst))

    vlabel_ids: Dict[str, int] = {}
    for role in vlabels:
        if role not in vlabel_ids:
            vlabel_ids[role] = len(vlabel_ids)
    vid = [vlabel_ids[r] for r in vlabels]

    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / f"{scenario}.vf3.bin"
    n, nz = len(vlabels), len(csr_dst)
    with bin_path.open("wb") as fh:
        fh.write(struct.pack("<III", n, nz, len(vlabel_ids)))
        for vec in (csr_row, csr_dst, csr_lab, vid):
            fh.write(struct.pack("<Q", len(vec)))
            fh.write(struct.pack(f"<{len(vec)}I", *vec))
        keys = list(range(len(elabels)))
        for _ in range(2):
            fh.write(struct.pack("<Q", len(keys)))
            fh.write(struct.pack(f"<{len(keys)}I", *keys))
            fh.write(struct.pack("<Q", len(keys)))
            fh.write(struct.pack(f"<{len(keys)}I", *keys))

    payload = {
        "scenario": scenario,
        "parser_dir": str(base),
        "label_vocabulary": {"vertex": "role string", "edge": "syscall"},
        "counts": {
            "vertices": n, "arcs": nz,
            "distinct_vertex_labels": len(vlabel_ids),
            "distinct_edge_labels": len(elabels),
        },
        "parallel_arcs_with_multiple_syscalls": multi,
        "orig_counts": orig_counts,
        "vertex_labels": dict(sorted(vlabel_ids.items(), key=lambda kv: kv[1])),
        "edge_labels": dict(sorted(elabels.items(), key=lambda kv: kv[1])),
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (out_dir / f"{scenario}.graph_stats.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[{scenario}] vertices={n} arcs={nz} vlabels={len(vlabel_ids)} "
          f"elabels={len(elabels)} multi_syscall_pairs={multi} {payload['elapsed_seconds']}s", flush=True)
    return payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--ood", action="store_true", help="export the TC_E3 windows instead")
    ap.add_argument("--net-grain", default="peer", choices=("peer", "connection"))
    args = ap.parse_args()
    global NET_GRAIN
    NET_GRAIN = args.net_grain
    out_dir = Path(args.out)
    targets = OOD if args.ood else SCENARIOS
    rows = [build(scenario, dirname, out_dir) for scenario, dirname in targets]
    (out_dir / "export_manifest.json").write_text(
        json.dumps({"graphs": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_dir}", flush=True)


if __name__ == "__main__":
    main()
