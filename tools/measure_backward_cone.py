"""Measure the backward investigation cone on a TraceSage Neo4j provenance graph.

Purpose (design validation, not an import tool)
-----------------------------------------------
The LLM-investigation design in docs/agent-design-llm-provenance.md claims a
"provenance responsibility partition" can enumerate a **complete** candidate
set (the backward cone) whose recall ceiling is independent of heuristic
top-k sampling.  This script measures that claim against a ground-truth
attack path:

  1. assign every event edge to its unique owner Process (PRP rules),
  2. expand a cone from the POI owner under a configurable rule set,
  3. report cone size, owned-edge volume, and GT edge coverage.

Rule sets (comma separated):
  parent : reverse p2p (process ancestry / image lineage)
  child  : forward p2p (processes spawned by a process already in the cone)
  exe    : the executable file of a process -> the processes that wrote it
  read   : every file/network a process reads -> the processes that wrote it
  write  : every file a process writes -> the processes that read it (forward; NOTE:
           this one is measured to explode on session-heavy logs, see AGENTS.md)

Usage:
  .venv/Scripts/python.exe tools/measure_backward_cone.py \
      --db tracesage-1-multi-stage-data-exfiltration \
      --gt groundtruth/1_Multi_Stage_Data_Exfiltration.groundtruth.json \
      --poi-phase P4 --rules parent,child,exe,read

Notes:
  - GT entities are schema-level (processes by exepath/name, files by path,
    networks by 4-tuple), while the graph uses (pid,name).  A GT edge counts
    as covered if ANY graph edge matching it is owned by a process in the cone.
  - Read-only: opens a driver, issues MATCH queries only.
"""

import argparse
import json
import os
import posixpath
import sys
from collections import defaultdict, deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sysdig-parser"))

from parsers.config import load_dotenv  # noqa: E402

LABELS = {
    "p2f": ("Process", "File"),
    "f2p": ("File", "Process"),
    "p2n": ("Process", "Network"),
    "n2p": ("Network", "Process"),
    "p2p": ("Process", "Process"),
}


def node_key(node, label):
    if label == "Process":
        return node.get("process_id")
    if label == "File":
        return node.get("path")
    return node.get("network_id")


def edge_owner(rel_type, src_id, dst_id):
    """PRP ownership: p2f/p2n -> source process, f2p/n2p/p2p -> target process."""
    return src_id if rel_type in ("p2f", "p2n") else dst_id


def load_graph(session):
    procs, files, nets = {}, set(), set()
    for row in session.run(
        "MATCH (n:Process) RETURN n.process_id AS id, n.name AS name, n.exepath AS exe"
    ):
        procs[row["id"]] = {"name": row["name"], "exe": row["exe"]}
    for row in session.run("MATCH (n:File) RETURN n.path AS path"):
        files.add(row["path"])
    for row in session.run("MATCH (n:Network) RETURN n.network_id AS id"):
        nets.add(row["id"])
    edges = []
    for rel_type, (src_label, dst_label) in LABELS.items():
        for row in session.run(
            f"MATCH (a)-[x:{rel_type}]->(b) "
            "RETURN a, b, x.syscall AS syscall"
        ):
            src_id = node_key(row["a"], src_label)
            dst_id = node_key(row["b"], dst_label)
            edges.append((rel_type, src_id, dst_id, row["syscall"]))
    return procs, files, nets, edges


def build_indexes(edges):
    idx = {
        "rev_p2p": defaultdict(set),
        "fwd_p2p": defaultdict(set),
        "writers_of": defaultdict(set),
        "readers_of": defaultdict(set),
        "senders_to": defaultdict(set),
        "reads_by": defaultdict(set),
        "writes_by": defaultdict(set),
        "exe_of": defaultdict(set),
        "images_of": defaultdict(set),
        "edge_index": defaultdict(list),
    }
    for rel_type, src_id, dst_id, syscall in edges:
        owner = edge_owner(rel_type, src_id, dst_id)
        idx["edge_index"][(src_id, syscall, dst_id)].append((rel_type, owner))
        if rel_type == "p2p":
            idx["rev_p2p"][dst_id].add(src_id)
            idx["fwd_p2p"][src_id].add(dst_id)
        elif rel_type == "f2p":
            idx["reads_by"][dst_id].add(("File", src_id))
            idx["readers_of"][src_id].add(dst_id)
            if syscall == "execve":
                idx["exe_of"][dst_id].add(src_id)
                idx["images_of"][src_id].add(dst_id)
        elif rel_type == "n2p":
            idx["reads_by"][dst_id].add(("Network", src_id))
        elif rel_type == "p2f":
            idx["writes_by"][src_id].add(dst_id)
            idx["writers_of"][dst_id].add(src_id)
        elif rel_type == "p2n":
            idx["senders_to"][dst_id].add(src_id)
    return idx


def expand_cone(idx, poi_owner, rules):
    seen = {poi_owner}
    queue = deque([poi_owner])
    while queue:
        proc = queue.popleft()
        nxt = set()
        if "parent" in rules:
            nxt |= idx["rev_p2p"].get(proc, set())
        if "child" in rules:
            nxt |= idx["fwd_p2p"].get(proc, set())
        if "exe" in rules:
            for path in idx["exe_of"].get(proc, ()):
                nxt |= idx["writers_of"].get(path, set())
        if "read" in rules:
            for kind, obj in idx["reads_by"].get(proc, ()):
                if kind == "File":
                    nxt |= idx["writers_of"].get(obj, set())
                else:
                    nxt |= idx["senders_to"].get(obj, set())
        if "write" in rules:
            for path in idx["writes_by"].get(proc, ()):
                nxt |= idx["readers_of"].get(path, set())
        for cand in nxt:
            if cand not in seen:
                seen.add(cand)
                queue.append(cand)
    return seen


def gt_edges(gt_path, poi_phase):
    spec = json.load(open(gt_path, encoding="utf-8"))
    poi = None
    for phase in spec["attack_path"]:
        if phase["phase"].startswith(poi_phase):
            poi = phase["edges"]
    if poi is None:
        raise SystemExit(f"no GT phase starting with {poi_phase!r}")
    all_edges = [
        (e["src"], e["syscall"], e["dst"])
        for phase in spec["attack_path"]
        for e in phase["edges"]
    ]
    return all_edges, [(e["src"], e["syscall"], e["dst"]) for e in poi]


def build_resolver(procs, files, nets, images_of):
    by_name, by_exe, by_base = defaultdict(set), defaultdict(set), defaultdict(set)
    for pid_name, info in procs.items():
        by_name[info["name"]].add(pid_name)
        if info["exe"]:
            by_exe[info["exe"]].add(pid_name)
            by_base[posixpath.basename(info["exe"])].add(pid_name)

    def resolve(text):
        out = set()
        out |= {("Process", x) for x in by_exe.get(text, set())}
        base = posixpath.basename(text)
        out |= {("Process", x) for x in by_base.get(base, set())}
        out |= {("Process", x) for x in by_name.get(base, set())}
        out |= {("Process", x) for x in by_name.get(text.lstrip("/"), set())}
        if text in files:
            out.add(("File", text))
            # GT writes the *exec source* as a file path (e.g. the payload script);
            # the graph stores it as the image process, so map the file back.
            out |= {("Process", x) for x in images_of.get(text, set())}
        else:
            for path in files:
                if path.endswith(text) or text.endswith(path):
                    out.add(("File", path))
                    out |= {("Process", x) for x in images_of.get(path, set())}
                    break
        if text in nets:
            out.add(("Network", text))
        return out

    return resolve


def measure(idx, resolve, edges, gt_all, gt_poi, rules, show_misses=False):
    poi_owner = None
    for src, syscall, dst in gt_poi:
        for _, s_id in resolve(src):
            for _, d_id in resolve(dst):
                for rel_type, owner in idx["edge_index"].get((s_id, syscall, d_id), []):
                    poi_owner = owner
    if poi_owner is None:
        raise SystemExit("could not resolve the POI owner from the GT")
    cone = expand_cone(idx, poi_owner, rules)
    owned = sum(
        1
        for rel_type, s_id, d_id, _ in edges
        if edge_owner(rel_type, s_id, d_id) in cone
    )
    covered, misses = 0, []
    for src, syscall, dst in gt_all:
        hit = False
        for _, s_id in resolve(src):
            for _, d_id in resolve(dst):
                for rel_type, owner in idx["edge_index"].get((s_id, syscall, d_id), []):
                    if owner in cone:
                        hit = True
        covered += int(hit)
        if not hit:
            misses.append((src, syscall, dst))
    return poi_owner, cone, owned, covered, misses


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--gt", required=True)
    ap.add_argument("--poi-phase", required=True)
    ap.add_argument("--rules", default="parent,exe,read,write")
    ap.add_argument("--all-rule-sets", action="store_true")
    ap.add_argument("--max-misses", type=int, default=8)
    args = ap.parse_args()

    load_dotenv()
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]),
    )
    with driver.session(database=args.db) as session:
        procs, files, nets, edges = load_graph(session)
        idx = build_indexes(edges)
    resolve = build_resolver(procs, files, nets, idx["images_of"])
    gt_all, gt_poi = gt_edges(args.gt, args.poi_phase)

    if args.all_rule_sets:
        rule_sets = [
            ("parent", {"parent"}),
            ("parent,exe", {"parent", "exe"}),
            ("parent,child", {"parent", "child"}),
            ("parent,child,exe", {"parent", "child", "exe"}),
            ("parent,child,exe,read", {"parent", "child", "exe", "read"}),
            ("parent,exe,read,write", {"parent", "exe", "read", "write"}),
            ("parent,child,exe,read,write", {"parent", "child", "exe", "read", "write"}),
        ]
    else:
        rule_sets = [(args.rules, set(args.rules.split(",")))]

    print(f"db={args.db}  base_edges={len(edges)}  gt_edges={len(gt_all)}")
    for name, rules in rule_sets:
        poi_owner, cone, owned, covered, misses = measure(
            idx, resolve, edges, gt_all, gt_poi, rules
        )
        print(
            f"  rules={name:22s} |cone|={len(cone):5d} ownedEdges={owned:7d} "
            f"({owned / len(edges) * 100:5.1f}%) GT={covered}/{len(gt_all)}"
        )
        for m in misses[: args.max_misses]:
            print(f"      MISS {m[0]} --{m[1]}--> {m[2]}")
        if len(misses) > args.max_misses:
            print(f"      ... {len(misses) - args.max_misses} more misses")


if __name__ == "__main__":
    main()
