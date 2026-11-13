#!/usr/bin/env python3
"""Export TraceSage parser graphs to the FLEXIS upstream binary format (.vf3.bin).

Upstream constraints that this exporter honours (see third_party/flexis/src):
  * graph.hpp : Vf3Graph layout is (n, nz, nl, CSR row, CSR dst, CSR edgeLabel,
                vertex labels, edge-label map, reversed edge-label map).
  * dataHelpers.hpp : every node's neighbour list must be sorted ascending, and a
                node pair carries exactly ONE edge label
                (Type::LabelledEdges = unordered_map<src, map<dst, label>>).
  * graph.hpp : therefore parallel edges between the same ordered pair are folded
                into a single composite label; the folded multiplicity is kept in
                graph_stats.json so frequency intensity is not lost.

Label scheme (default):
  Process  P:<exe basename>
  File     F:<path family>
  Network  N:<proto>:<peer scope>
  Edge     <action[+action...]>|<ok|err|na|mixed>
"""
from __future__ import annotations

import argparse
import csv
import json
import struct
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
PARSER_ROOT = ROOT / "output" / "parser-v2"
OUT_DEFAULT = ROOT / "output" / "rule-kg" / "flexis-exact-v1" / "graphs"

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
DIR_OF = {name: d for name, d in SCENARIOS}

# path families for File vertices
PATH_FAMILIES: Tuple[Tuple[str, str], ...] = (
    ("/proc/", "/proc"), ("/proc", "/proc"),
    ("/sys/", "/sys"), ("/sys", "/sys"),
    ("/dev/", "/dev"), ("/dev", "/dev"),
    ("/etc/", "/etc"), ("/etc", "/etc"),
    ("/usr/lib", "/lib"), ("/usr/lib64", "/lib"), ("/lib", "/lib"),
    ("/usr/bin", "/bin"), ("/usr/sbin", "/bin"), ("/bin", "/bin"), ("/sbin", "/bin"),
    ("/var/log", "/var/log"), ("/var/lib", "/var/lib"), ("/var/tmp", "/tmp"),
    ("/var/", "/var"), ("/tmp", "/tmp"), ("/run", "/tmp"),
    ("/root", "/root"), ("/home", "/home"),
    ("/opt", "/opt"), ("/srv", "/srv"), ("/mnt", "/mnt"), ("/media", "/media"),
    ("/boot", "/boot"), ("/usr/share", "/usr/share"), ("/usr", "/usr"),
    ("socket:", "socket"), ("pipe:", "pipe"), ("anon_inode:", "anon"),
)

PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                    "192.168.", "127.", "0.0.0.0", "::1", "fe80")


def path_family(path: str) -> str:
    text = path or ""
    for prefix, family in PATH_FAMILIES:
        if text.startswith(prefix):
            return family
    return "/other"


def basename(path: str) -> str:
    text = (path or "").replace("\\", "/").strip()
    if not text:
        return "unknown"
    return text.rsplit("/", 1)[-1] or "unknown"


def parse_endpoints(endpoints: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for part in (endpoints or "").split("->"):
        part = part.strip()
        if not part:
            continue
        ip, _, port = part.rpartition(":")
        if not ip:
            ip, port = part, "0"
        try:
            out.append((ip, int(port)))
        except ValueError:
            out.append((ip, 0))
    return out


def peer_scope(endpoints: str) -> str:
    peers = parse_endpoints(endpoints)
    if not peers:
        return "unknown"
    scopes = set()
    for ip, _port in peers:
        scopes.add("self" if ip.startswith(PRIVATE_PREFIXES) else "public")
    return "public" if "public" in scopes else "self"


def result_bit(result: str) -> str:
    text = (result or "").strip()
    if not text:
        return "na"
    try:
        value = int(text)
    except ValueError:
        return "na"
    return "ok" if value >= 0 else "err"


def vertex_label(label: str, path: str, endpoints: str, exe_path: str, proto: str, scheme: str) -> str:
    if label == "Process":
        if scheme == "L_A":
            return f"P:{basename(exe_path)}"
        return "P"
    if label == "File":
        return f"F:{path_family(path)}"
    if label == "Network":
        if scheme == "L_C":
            return "N"
        proto_s = (proto or "net").strip().lower() or "net"
        return f"N:{proto_s}:{peer_scope(endpoints)}"
    return f"X:{(label or 'unknown').strip()}"


def edge_label(actions: Sequence[str], results: Sequence[str]) -> str:
    acts = sorted({a for a in actions if a})
    if not acts:
        acts = ["unknown"]
    body = "+".join(acts[:3]) + ("+..." if len(acts) > 3 else "")
    if len(acts) > 1:
        return f"{body}|mixed"
    bits = {r for r in results}
    if bits == {"ok"}:
        bit = "ok"
    elif bits == {"err"}:
        bit = "err"
    elif bits == {"ok", "err"}:
        bit = "mixed"
    else:
        bit = "na"
    return f"{body}|{bit}"


def build_scenario(scenario: str, dirname: str, scheme: str) -> Tuple[dict, str]:
    base = PARSER_ROOT / dirname
    nodes_path = base / "nodes.csv"
    edges_path = base / "edges.csv"
    if not nodes_path.is_file() or not edges_path.is_file():
        raise FileNotFoundError(f"missing parser output: {nodes_path} / {edges_path}")

    t0 = time.time()
    keys: Dict[Tuple[str, ...], int] = {}
    node_labels: List[str] = []
    label_ids: Dict[str, int] = {}
    node_types: Dict[str, int] = {}
    with nodes_path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            key = (
                row.get("label", ""),
                row.get("host_id", ""),
                (row.get("container_id", "") or "host") if row.get("label", "") != "Network" else "",
                row.get("pid", ""),
                (row.get("start_ns", "") or "0") if row.get("label", "") == "Process" else row.get("start_ns", ""),
                row.get("path", "") if row.get("label", "") != "Network" else "",
                row.get("endpoints", "") if row.get("label", "") == "Network" else "",
            )
            if key in keys:
                continue
            keys[key] = len(node_labels)
            text = vertex_label(row.get("label", ""), row.get("path", ""), row.get("endpoints", ""),
                                row.get("exe_path", ""), row.get("proto", ""), scheme)
            node_labels.append(text)
            node_types[row.get("label", "")] = node_types.get(row.get("label", ""), 0) + 1
            if text not in label_ids:
                label_ids[text] = len(label_ids)
    print(f"[{scenario}] nodes={len(node_labels)} distinct_vertex_labels={len(label_ids)}", flush=True)

    # src,dst -> {action: [count, ok, err]}
    pairs: Dict[int, Dict[int, Dict[str, List[int]]]] = {}
    rows = 0
    bad = 0
    action_counts: Dict[str, int] = {}
    with edges_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows += 1
            src_key = (
                row["src_label"],
                row["src_host"],
                (row["src_container"] or "host") if row["src_label"] != "Network" else "",
                row["src_pid"],
                (row["src_start_ns"] or "0") if row["src_label"] == "Process" else row["src_start_ns"],
                row["src_path"] if row["src_label"] != "Network" else "",
                row["src_path"] if row["src_label"] == "Network" else "",
            )
            dst_key = (
                row["dst_label"],
                row["dst_host"],
                (row["dst_container"] or "host") if row["dst_label"] != "Network" else "",
                row["dst_pid"],
                (row["dst_start_ns"] or "0") if row["dst_label"] == "Process" else row["dst_start_ns"],
                row["dst_path"] if row["dst_label"] != "Network" else "",
                row["dst_path"] if row["dst_label"] == "Network" else "",
            )
            try:
                src = keys[src_key]
                dst = keys[dst_key]
            except KeyError:
                bad += 1
                continue
            action = row.get("action", "") or ""
            action_counts[action] = action_counts.get(action, 0) + 1
            bit = result_bit(row.get("result", ""))
            slot = pairs.setdefault(src, {}).setdefault(dst, {}).setdefault(action, [0, 0, 0])
            slot[0] += 1
            slot[1 if bit == "ok" else 2] += 1
            if rows % 1_000_000 == 0:
                print(f"[{scenario}] streamed edges={rows}", flush=True)

    # fold to one arc per (src,dst)
    edge_label_ids: Dict[str, int] = {}
    csr_row: List[int] = []
    csr_dst: List[int] = []
    csr_lab: List[int] = []
    arc_stats = {"arcs": 0, "multi_action_pairs": 0, "folded_edges": rows - bad, "max_actions_per_pair": 0}
    for src in range(len(node_labels)):
        neighbours = pairs.get(src)
        csr_row.append(len(csr_dst))
        if not neighbours:
            continue
        for dst in sorted(neighbours):
            acts = neighbours[dst]
            n_actions = len(acts)
            if n_actions > 1:
                arc_stats["multi_action_pairs"] += 1
            if n_actions > arc_stats["max_actions_per_pair"]:
                arc_stats["max_actions_per_pair"] = n_actions
            results = []
            for _act, (count, ok, err) in acts.items():
                results.extend(["ok"] * ok)
                results.extend(["err"] * err)
            text = edge_label(list(acts.keys()), results)
            if text not in edge_label_ids:
                edge_label_ids[text] = len(edge_label_ids)
            csr_dst.append(dst)
            csr_lab.append(edge_label_ids[text])
            arc_stats["arcs"] += 1
    csr_row.append(len(csr_dst))

    payload = {
        "scenario": scenario,
        "label_scheme": scheme,
        "parser_dir": str(base),
        "nodes_csv": str(nodes_path),
        "edges_csv": str(edges_path),
        "counts": {
            "vertices": len(node_labels),
            "arcs": arc_stats["arcs"],
            "parser_edges": rows,
            "dropped_edges": bad,
            "distinct_vertex_labels": len(label_ids),
            "distinct_edge_labels": len(edge_label_ids),
            "vertex_labels_by_node_type": node_types,
        },
        "folding": arc_stats,
        "actions": dict(sorted(action_counts.items(), key=lambda kv: -kv[1])),
        "vertex_labels": {k: v for k, v in sorted(label_ids.items(), key=lambda kv: kv[1])},
        "edge_labels": {k: v for k, v in sorted(edge_label_ids.items(), key=lambda kv: kv[1])},
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    # keep arrays for the caller
    return {
        "payload": payload,
        "vertex_label_ids": [label_ids[t] for t in node_labels],
        "csr_row": csr_row,
        "csr_dst": csr_dst,
        "csr_lab": csr_lab,
        "n_edge_labels": len(edge_label_ids),
    }, ""


def write_bin(path: Path, n: int, csr_row: List[int], csr_dst: List[int], csr_lab: List[int],
              vertex_label_ids: List[int], n_vertex_labels: int, n_edge_labels: int) -> None:
    nz = len(csr_dst)
    with path.open("wb") as fh:
        fh.write(struct.pack("<III", n, nz, n_vertex_labels))
        for vec in (csr_row, csr_dst, csr_lab, vertex_label_ids):
            fh.write(struct.pack("<Q", len(vec)))
            fh.write(struct.pack(f"<{len(vec)}I", *vec))
        # edge-label maps only need consistent sizes: upstream uses them for size()
        keys = list(range(n_edge_labels))
        vals = list(range(n_edge_labels))
        for _ in range(2):
            fh.write(struct.pack("<Q", len(keys)))
            fh.write(struct.pack(f"<{len(keys)}I", *keys))
            fh.write(struct.pack("<Q", len(vals)))
            fh.write(struct.pack(f"<{len(vals)}I", *vals))


def read_bin(path: Path) -> dict:
    data = path.read_bytes()
    off = 0
    n, nz, nl = struct.unpack_from("<III", data, off)
    off += 12
    vecs = []
    for _ in range(8):
        (length,) = struct.unpack_from("<Q", data, off)
        off += 8
        vec = list(struct.unpack_from(f"<{length}I", data, off))
        off += 4 * length
        vecs.append(vec)
    return {"n": n, "nz": nz, "nl": nl, "vectors": vecs, "consumed": off, "size": len(data)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Export parser graphs to FLEXIS .vf3.bin")
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    ap.add_argument("--scheme", default="L_A", choices=("L_A", "L_B", "L_C"),
                    help="vertex label scheme: L_A=process basename, L_B=process type only, "
                         "L_C=process+network type only")
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--extra", action="append", default=None,
                    help="name=parser-subdir, added on top of SCENARIOS")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = set(args.scenario) if args.scenario else None
    summary = []
    targets = list(SCENARIOS)
    for item in args.extra or []:
        name, _, sub = item.partition("=")
        if not name or not sub:
            raise SystemExit(f"--extra expects name=subdir, got {item!r}")
        targets.append((name, sub))
    for scenario, dirname in targets:
        if wanted and scenario not in wanted:
            continue
        built, _ = build_scenario(scenario, dirname, args.scheme)
        payload = built["payload"]
        n = payload["counts"]["vertices"]
        bin_path = out_dir / f"{scenario}.vf3.bin"
        write_bin(bin_path, n, built["csr_row"], built["csr_dst"], built["csr_lab"],
                  built["vertex_label_ids"], payload["counts"]["distinct_vertex_labels"],
                  payload["counts"]["distinct_edge_labels"])
        payload["bin"] = str(bin_path)
        payload["bin_bytes"] = bin_path.stat().st_size
        round_trip = read_bin(bin_path)
        ok = (
            round_trip["n"] == n
            and round_trip["nz"] == len(built["csr_dst"])
            and round_trip["vectors"][0] == built["csr_row"]
            and round_trip["vectors"][1] == built["csr_dst"]
            and round_trip["vectors"][2] == built["csr_lab"]
            and round_trip["vectors"][3] == built["vertex_label_ids"]
            and round_trip["consumed"] == round_trip["size"]
        )
        payload["round_trip_ok"] = ok
        (out_dir / f"{scenario}.graph_stats.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[{scenario}] vertices={n} arcs={len(built['csr_dst'])} "
              f"edge_labels={payload['counts']['distinct_edge_labels']} "
              f"multi_action_pairs={payload['folding']['multi_action_pairs']} "
              f"bin={payload['bin_bytes']/1e6:.1f}MB round_trip={'OK' if ok else 'FAIL'} "
              f"{payload['elapsed_seconds']}s", flush=True)
        summary.append({"scenario": scenario, "counts": payload["counts"],
                        "bin": str(bin_path), "round_trip_ok": ok,
                        "elapsed_seconds": payload["elapsed_seconds"]})

    (out_dir / "export_manifest.json").write_text(
        json.dumps({"graphs": summary, "scenarios": len(summary)}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"wrote {out_dir}", flush=True)


if __name__ == "__main__":
    main()
