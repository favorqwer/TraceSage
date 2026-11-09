#!/usr/bin/env python3
"""Mine unlabeled recurrent activity priors from TraceSage parser edges.

This is an adapter inspired by FLEXIS, not a direct invocation of the upstream
binary. It keeps candidate generation bounded and stream-oriented for the
large parser CSV files:

* 1-hop candidates are typed directed edges.
* 2-hop candidates are typed directed paths sharing their middle node.
* cross-scenario recurrence is used as the unlabeled benign-prior filter.
* support is reported as a deterministic greedy node-disjoint matching count,
  i.e. a maximal independent occurrence set, not an exact maximum independent
  set.

No groundtruth file is read by this program. The output is an independent
prior library and is not an attack detector or a proof of benignness.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
VERSION = "flexis-benign-v1"
FLEXIS_COMMIT = "9f260efa658bec39ffd514eec6765a94417ae9c9"

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

WRITE_ACTIONS = {"create", "write", "rename", "link", "unlink", "truncate", "chmod", "mount", "umount"}
DELETE_ACTIONS = {"unlink", "rename"}
NET_OUT_ACTIONS = {"connect", "send", "bind", "listen"}
NET_IN_ACTIONS = {"accept", "recv"}
SPAWN_ACTIONS = {"clone", "exec"}
PRIV_ACTIONS = {"chmod", "chown"}
READ_ACTIONS = {"read", "stat", "mmap_read"}
AUTH_MARKERS = (
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers",
    "authorized_keys", "/.ssh/", "/etc/ssh/ssh_host",
)
SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/boot/", "/opt/", "/etc/", "/var/lib/")

NodeKey = Tuple[str, str, str, str, str, str, str]


@dataclass
class NodeInfo:
    label: str
    host: str
    container: str
    pid: str = ""
    start_ns: str = ""
    path: str = ""
    endpoints: str = ""
    exe_path: str = ""


@dataclass
class ScenarioModel:
    scenario: str
    edge_path: Path
    node_path: Path
    nodes: List[NodeInfo]
    node_ids: Dict[NodeKey, int]
    in_action_masks: List[int]
    out_action_masks: List[int]
    writer_ids: Dict[int, set[int]] = field(default_factory=dict)
    roles: List[str] = field(default_factory=list)
    one_counts: Dict[int, int] = field(default_factory=dict)
    pair_counts: Dict[Tuple[int, int], int] = field(default_factory=dict)
    in_sig_masks: List[int] = field(default_factory=list)
    out_sig_masks: List[int] = field(default_factory=list)
    first_in: List[Dict[int, int]] = field(default_factory=list)
    first_out: List[Dict[int, int]] = field(default_factory=list)
    bad_edges: int = 0


class ActionBits:
    def __init__(self) -> None:
        self.ids: Dict[str, int] = {}

    def bit(self, action: str) -> int:
        if action not in self.ids:
            self.ids[action] = len(self.ids)
        return 1 << self.ids[action]

    def has(self, mask: int, action: str) -> bool:
        bit = self.ids.get(action)
        return bit is not None and bool(mask & (1 << bit))


ACTION_BITS = ActionBits()


def norm(value: object, default: str = "") -> str:
    text = "" if value is None else str(value)
    return text if text else default


def node_key(info: NodeInfo) -> NodeKey:
    return (info.label, info.host, info.container, info.pid, info.start_ns,
            info.path, info.endpoints)


def edge_endpoint(row: Sequence[str], idx: Dict[str, int], side: str) -> NodeKey:
    label = row[idx[f"{side}_label"]]
    host = row[idx[f"{side}_host"]]
    container = row[idx[f"{side}_container"]]
    pid = row[idx[f"{side}_pid"]]
    start_ns = row[idx[f"{side}_start_ns"]]
    path = row[idx[f"{side}_path"]]
    if label == "Process":
        container = container or "host"
        start_ns = start_ns or "0"
        path = ""
        endpoints = ""
    elif label == "File":
        container = container or "host"
        pid = ""
        start_ns = ""
        endpoints = ""
    elif label == "Network":
        container = ""
        pid = ""
        start_ns = ""
        endpoints = path
        path = ""
    else:
        endpoints = ""
    return (label, host, container, pid, start_ns, path, endpoints)


def load_nodes(node_path: Path) -> Tuple[List[NodeInfo], Dict[NodeKey, int]]:
    nodes: List[NodeInfo] = []
    ids: Dict[NodeKey, int] = {}
    with node_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            info = NodeInfo(
                label=norm(row.get("label")),
                host=norm(row.get("host_id")),
                container=norm(row.get("container_id"), "host") if norm(row.get("label")) != "Network" else "",
                pid=norm(row.get("pid")),
                start_ns=norm(row.get("start_ns")),
                path=norm(row.get("path")),
                endpoints=norm(row.get("endpoints")),
                exe_path=norm(row.get("exe_path")),
            )
            key = node_key(info)
            if key not in ids:
                ids[key] = len(nodes)
                nodes.append(info)
    return nodes, ids


def edge_indexes(header: Sequence[str]) -> Dict[str, int]:
    required = (
        "src_label", "src_host", "src_container", "src_pid", "src_start_ns", "src_path",
        "dst_label", "dst_host", "dst_container", "dst_pid", "dst_start_ns", "dst_path",
        "action", "syscall",
    )
    idx = {name: header.index(name) for name in required if name in header}
    missing = [name for name in required if name not in idx]
    if missing:
        raise RuntimeError(f"{missing} missing from parser edge file")
    return idx


def edge_rows(path: Path) -> Iterator[Tuple[Sequence[str], Dict[str, int]]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        idx = edge_indexes(header)
        for row in reader:
            yield row, idx


def process_role(info: NodeInfo, in_mask: int, out_mask: int, process_count: int) -> str:
    in_net = any(ACTION_BITS.has(in_mask, a) for a in ("accept", "recv"))
    out_net = any(ACTION_BITS.has(out_mask, a) for a in NET_OUT_ACTIONS)
    direction = "both" if in_net and out_net else "in" if in_net else "out" if out_net else "none"
    has_clone = ACTION_BITS.has(out_mask, "clone")
    has_exec = ACTION_BITS.has(in_mask, "exec") or ACTION_BITS.has(out_mask, "exec")
    spawn = "multi" if has_clone and has_exec else "exec" if has_exec else "clone" if has_clone else "leaf"
    inst = "single" if process_count < 3 else "few" if process_count < 56 else "many"
    priv = "chg" if any(ACTION_BITS.has(out_mask, a) for a in PRIV_ACTIONS) else "-"
    return f"P.{direction}.{spawn}.{inst}.{priv}"


def file_role(info: NodeInfo, in_mask: int, out_mask: int, writers: int) -> str:
    bits: List[str] = []
    if any(ACTION_BITS.has(in_mask, a) for a in WRITE_ACTIONS):
        bits.append("w")
    if any(ACTION_BITS.has(out_mask, a) for a in ("exec", "mmap_exec")):
        bits.append("x")
    if any(ACTION_BITS.has(out_mask, a) for a in READ_ACTIONS):
        bits.append("r")
    if any(ACTION_BITS.has(in_mask | out_mask, a) for a in DELETE_ACTIONS):
        bits.append("d")
    bit_s = "".join(bits) or "-"
    writer_band = "none" if writers == 0 else "single" if writers == 1 else "multi"
    sensitivity = "auth" if any(marker in info.path for marker in AUTH_MARKERS) else "cfg" if info.path.startswith("/etc/") else "-"
    place = "sys" if info.path.startswith(SYSTEM_PREFIXES) else "usr"
    return f"F.{bit_s}.{writer_band}.{sensitivity}.{place}"


def network_role(in_mask: int, out_mask: int) -> str:
    listened = ACTION_BITS.has(out_mask, "accept")
    dialed = any(ACTION_BITS.has(in_mask, a) for a in NET_OUT_ACTIONS)
    direction = "both" if listened and dialed else "listen" if listened else "dial"
    return f"N.{direction}.single"


def assign_roles(model: ScenarioModel) -> None:
    exe_counts: Dict[str, int] = {}
    for info in model.nodes:
        if info.label == "Process":
            exe_counts[info.exe_path or "<unknown>"] = exe_counts.get(info.exe_path or "<unknown>", 0) + 1
    roles: List[str] = []
    for node_id, info in enumerate(model.nodes):
        in_mask = model.in_action_masks[node_id]
        out_mask = model.out_action_masks[node_id]
        if info.label == "Process":
            roles.append(process_role(info, in_mask, out_mask, exe_counts.get(info.exe_path or "<unknown>", 1)))
        elif info.label == "File":
            roles.append(file_role(info, in_mask, out_mask, len(model.writer_ids.get(node_id, ()))))
        elif info.label == "Network":
            roles.append(network_role(in_mask, out_mask))
        else:
            roles.append(info.label or "Unknown")
    model.roles = roles


def first_scan(model: ScenarioModel, log_every: int) -> int:
    rows_seen = 0
    for row, idx in edge_rows(model.edge_path):
        rows_seen += 1
        try:
            src = model.node_ids[edge_endpoint(row, idx, "src")]
            dst = model.node_ids[edge_endpoint(row, idx, "dst")]
        except KeyError:
            model.bad_edges += 1
            continue
        action = norm(row[idx["action"]])
        bit = ACTION_BITS.bit(action)
        model.out_action_masks[src] |= bit
        model.in_action_masks[dst] |= bit
        if model.nodes[dst].label == "File" and model.nodes[src].label == "Process" and action in WRITE_ACTIONS:
            writers = model.writer_ids.setdefault(dst, set())
            if len(writers) < 3:
                writers.add(src)
        if log_every and rows_seen % log_every == 0:
            print(f"[{model.scenario}] stats edges={rows_seen}", flush=True)
    return rows_seen


def syscall_of(row: Sequence[str], idx: Dict[str, int]) -> str:
    return norm(row[idx["syscall"]]) or norm(row[idx["action"]])


def second_scan(model: ScenarioModel, signatures: Dict[Tuple[str, str, str], int],
                min_edge_count: int, max_pairs_per_node: int, log_every: int) -> int:
    n = len(model.nodes)
    model.in_sig_masks = [0] * n
    model.out_sig_masks = [0] * n
    model.first_in = [{} for _ in range(n)]
    model.first_out = [{} for _ in range(n)]
    rows_seen = 0
    for row, idx in edge_rows(model.edge_path):
        rows_seen += 1
        try:
            src = model.node_ids[edge_endpoint(row, idx, "src")]
            dst = model.node_ids[edge_endpoint(row, idx, "dst")]
        except KeyError:
            continue
        sig = (model.roles[src], syscall_of(row, idx), model.roles[dst])
        sid = signatures.setdefault(sig, len(signatures))
        model.one_counts[sid] = model.one_counts.get(sid, 0) + 1
        model.out_sig_masks[src] |= 1 << sid
        model.in_sig_masks[dst] |= 1 << sid
        model.first_out[src].setdefault(sid, dst)
        model.first_in[dst].setdefault(sid, src)
        if log_every and rows_seen % log_every == 0:
            print(f"[{model.scenario}] typed edges={rows_seen}", flush=True)

    active = {sid for sid, count in model.one_counts.items() if count >= min_edge_count}
    for node_id in range(n):
        incoming = [sid for sid in iter_bits(model.in_sig_masks[node_id]) if sid in active]
        outgoing = [sid for sid in iter_bits(model.out_sig_masks[node_id]) if sid in active]
        pairs = [(a, b) for a in incoming for b in outgoing]
        if len(pairs) > max_pairs_per_node:
            pairs = sorted(pairs)[:max_pairs_per_node]
        for pair in pairs:
            model.pair_counts[pair] = model.pair_counts.get(pair, 0) + 1
    return rows_seen


def iter_bits(mask: int) -> Iterator[int]:
    while mask:
        low = mask & -mask
        yield low.bit_length() - 1
        mask ^= low


def greedy_one_support(model: ScenarioModel, selected: set[int], log_every: int) -> Tuple[Dict[int, int], Dict[int, int]]:
    used: Dict[int, set[int]] = {sid: set() for sid in selected}
    selected_by_signature = {SIGNATURES_BY_ID[sid]: sid for sid in selected}
    support = {sid: 0 for sid in selected}
    raw = {sid: 0 for sid in selected}
    rows_seen = 0
    for row, idx in edge_rows(model.edge_path):
        rows_seen += 1
        try:
            src = model.node_ids[edge_endpoint(row, idx, "src")]
            dst = model.node_ids[edge_endpoint(row, idx, "dst")]
        except KeyError:
            continue
        signature = (model.roles[src], syscall_of(row, idx), model.roles[dst])
        sid = selected_by_signature.get(signature)
        if sid is None:
            continue
        raw[sid] += 1
        occupied = used[sid]
        if src not in occupied and dst not in occupied and src != dst:
            occupied.add(src)
            occupied.add(dst)
            support[sid] += 1
        if log_every and rows_seen % log_every == 0:
            print(f"[{model.scenario}] support edges={rows_seen}", flush=True)
    return raw, support


def greedy_two_support(model: ScenarioModel, selected: set[Tuple[int, int]]) -> Tuple[Dict[Tuple[int, int], int], Dict[Tuple[int, int], int]]:
    raw = {pair: 0 for pair in selected}
    support = {pair: 0 for pair in selected}
    used: Dict[Tuple[int, int], set[int]] = {pair: set() for pair in selected}
    for middle in range(len(model.nodes)):
        incoming = model.first_in[middle]
        outgoing = model.first_out[middle]
        for pair in selected:
            src = incoming.get(pair[0])
            dst = outgoing.get(pair[1])
            if src is None or dst is None:
                continue
            raw[pair] += 1
            if src == middle or dst == middle or src == dst:
                continue
            occupied = used[pair]
            if src not in occupied and middle not in occupied and dst not in occupied:
                occupied.update((src, middle, dst))
                support[pair] += 1
    return raw, support


def resolve_paths(edge_root: Path, node_root: Path) -> List[Tuple[str, Path, Path]]:
    resolved = []
    for scenario, dirname in SCENARIOS:
        edge = edge_root / dirname / "edges.csv"
        node = node_root / dirname / "nodes.csv"
        if not edge.is_file() or not node.is_file():
            raise FileNotFoundError(f"missing parser output for {scenario}: {edge} / {node}")
        resolved.append((scenario, edge, node))
    return resolved


def make_motif(mid: str, sig: Tuple[str, str, str], scenarios: List[str], raw: Dict[str, int], mis: Dict[str, int], total: int, kind: str) -> Dict[str, object]:
    src, syscall, dst = sig
    return {
        "id": mid,
        "name": f"Unlabeled recurrent {kind}: {src} --{syscall}--> {dst}",
        "hops": 1,
        "src_role": src,
        "syscalls": [syscall],
        "dst_role": dst,
        "support_scenarios": list(scenarios),
        "support_scenarios_list": list(scenarios),
        "mined_support_scenarios": len(scenarios),
        "admitted": True,
        "source": "flexis-unlabeled-cross-scenario",
        "version": VERSION,
        "stats": {
            "scenario_support": len(scenarios),
            "raw_occurrences_total": total,
            "raw_occurrences_by_scenario": raw,
            "greedy_mis_support_total": sum(mis.values()),
            "greedy_mis_support_by_scenario": mis,
            "support_metric": "greedy maximal node-disjoint occurrence set",
            "benign_prior_status": "unlabeled recurrent prior; not groundtruth-verified",
        },
    }


def make_two_motif(mid: str, sig1: Tuple[str, str, str], sig2: Tuple[str, str, str], scenarios: List[str], raw: Dict[str, int], mis: Dict[str, int], total: int) -> Dict[str, object]:
    chain = [
        {"src_role": sig1[0], "syscall": sig1[1], "dst_role": sig1[2]},
        {"src_role": sig2[0], "syscall": sig2[1], "dst_role": sig2[2]},
    ]
    return {
        "id": mid,
        "name": f"Unlabeled recurrent 2-hop: {sig1[0]} --{sig1[1]}--> {sig1[2]} --{sig2[1]}--> {sig2[2]}",
        "hops": 2,
        "chain": chain,
        "syscalls": [sig1[1], sig2[1]],
        "support_scenarios": list(scenarios),
        "support_scenarios_list": list(scenarios),
        "mined_support_scenarios": len(scenarios),
        "admitted": True,
        "source": "flexis-unlabeled-cross-scenario",
        "version": VERSION,
        "stats": {
            "scenario_support": len(scenarios),
            "raw_occurrences_total": total,
            "raw_occurrences_by_scenario": raw,
            "greedy_mis_support_total": sum(mis.values()),
            "greedy_mis_support_by_scenario": mis,
            "support_metric": "greedy maximal node-disjoint occurrence set",
            "benign_prior_status": "unlabeled recurrent prior; not groundtruth-verified",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Mine unlabeled recurrent FLEXIS-inspired prior motifs")
    parser.add_argument("--edge-root", default=str(ROOT / "output/parser-v2"))
    parser.add_argument("--node-root", default=str(ROOT / "output/parser-v2"))
    parser.add_argument("--out", default=str(ROOT / "output/rule-kg/flexis-benign-v1"))
    parser.add_argument("--min-scenario-support", type=int, default=7)
    parser.add_argument("--min-edge-count", type=int, default=100)
    parser.add_argument("--min-mis-support", type=int, default=3)
    parser.add_argument("--max-pairs-per-node", type=int, default=1000)
    parser.add_argument("--max-two-candidates", type=int, default=500)
    parser.add_argument("--log-every", type=int, default=250000)
    args = parser.parse_args()

    if args.min_scenario_support < 1 or args.min_scenario_support > len(SCENARIOS):
        raise SystemExit("--min-scenario-support must be in [1, 10]")
    resolved = resolve_paths(Path(args.edge_root), Path(args.node_root))
    print(f"input scenarios={len(resolved)} groundtruth_used=false", flush=True)
    print(f"thresholds scenario_support>={args.min_scenario_support} edge_count>={args.min_edge_count} mis_support>={args.min_mis_support}", flush=True)

    models: List[ScenarioModel] = []
    signatures: Dict[Tuple[str, str, str], int] = {}
    started = time.time()
    for scenario, edge_path, node_path in resolved:
        nodes, node_ids = load_nodes(node_path)
        model = ScenarioModel(
            scenario=scenario,
            edge_path=edge_path,
            node_path=node_path,
            nodes=nodes,
            node_ids=node_ids,
            in_action_masks=[0] * len(nodes),
            out_action_masks=[0] * len(nodes),
        )
        print(f"[{scenario}] nodes={len(nodes)} first pass", flush=True)
        first_scan(model, args.log_every)
        assign_roles(model)
        print(f"[{scenario}] second pass and typed adjacency", flush=True)
        second_scan(model, signatures, args.min_edge_count, args.max_pairs_per_node, args.log_every)
        models.append(model)
        print(f"[{scenario}] typed_signatures={len(model.one_counts)} two_hop_candidates={len(model.pair_counts)} bad_edges={model.bad_edges}", flush=True)

    global_signatures = {sid: sig for sig, sid in signatures.items()}
    SIGNATURES_BY_ID.clear()
    SIGNATURES_BY_ID.update(global_signatures)
    scenario_count = len(models)

    one_by_sid: Dict[int, Dict[str, int]] = {}
    for model in models:
        for sid, count in model.one_counts.items():
            one_by_sid.setdefault(sid, {})[model.scenario] = count
    one_candidates = {
        sid for sid, by_sc in one_by_sid.items()
        if len(by_sc) >= args.min_scenario_support
        and min(by_sc.values()) >= args.min_edge_count
    }

    pair_by_pair: Dict[Tuple[int, int], Dict[str, int]] = {}
    for model in models:
        for pair, count in model.pair_counts.items():
            if count >= args.min_mis_support:
                pair_by_pair.setdefault(pair, {})[model.scenario] = count
    pair_candidates = {
        pair for pair, by_sc in pair_by_pair.items()
        if len(by_sc) >= args.min_scenario_support
    }
    pair_candidates = sorted(
        pair_candidates,
        key=lambda pair: (-len(pair_by_pair[pair]), -min(pair_by_pair[pair].values()), pair),
    )[:args.max_two_candidates]
    pair_candidates = set(pair_candidates)
    print(f"selected candidates one_hop={len(one_candidates)} two_hop={len(pair_candidates)}", flush=True)

    one_raw_by_sid: Dict[int, Dict[str, int]] = {sid: {} for sid in one_candidates}
    one_mis_by_sid: Dict[int, Dict[str, int]] = {sid: {} for sid in one_candidates}
    for model in models:
        if not one_candidates:
            break
        print(f"[{model.scenario}] greedy MIS for {len(one_candidates)} one-hop candidates", flush=True)
        raw, mis = greedy_one_support(model, one_candidates, args.log_every)
        for sid in one_candidates:
            one_raw_by_sid[sid][model.scenario] = raw[sid]
            one_mis_by_sid[sid][model.scenario] = mis[sid]

    one_diagnostics: List[Dict[str, object]] = []
    for sid in sorted(one_candidates, key=lambda x: global_signatures[x]):
        supported_scenarios = set(one_by_sid[sid])
        raw_by_sc = {sc: one_raw_by_sid[sid].get(sc, 0) for sc in supported_scenarios}
        mis_by_sc = {sc: one_mis_by_sid[sid].get(sc, 0) for sc in supported_scenarios}
        diagnostic = {
            "signature": list(global_signatures[sid]),
            "scenario_support": len(supported_scenarios),
            "raw_min": min(raw_by_sc.values()) if raw_by_sc else 0,
            "raw_total": sum(raw_by_sc.values()),
            "mis_min": min(mis_by_sc.values()) if mis_by_sc else 0,
            "mis_total": sum(mis_by_sc.values()),
            "raw_by_scenario": raw_by_sc,
            "mis_by_scenario": mis_by_sc,
        }
        one_diagnostics.append(diagnostic)
        print(
            f"candidate {global_signatures[sid]} scenarios={diagnostic['scenario_support']} "
            f"raw_min={diagnostic['raw_min']} mis_min={diagnostic['mis_min']}",
            flush=True,
        )

    motifs: List[Dict[str, object]] = []
    motif_counter = 1
    for sid in sorted(one_candidates, key=lambda x: global_signatures[x]):
        sig = global_signatures[sid]
        scenarios = sorted(one_by_sid[sid])
        raw = {sc: one_raw_by_sid[sid][sc] for sc in scenarios}
        mis = {sc: one_mis_by_sid[sid][sc] for sc in scenarios}
        if min(mis.values()) < args.min_mis_support:
            continue
        motifs.append(make_motif(
            f"FLEXIS_PRIOR_{motif_counter:05d}_1HOP", sig, scenarios,
            raw, mis, sum(raw.values()), "1-hop"))
        motif_counter += 1

    for pair in sorted(pair_candidates, key=lambda p: (global_signatures[p[0]], global_signatures[p[1]])):
        sig1, sig2 = global_signatures[pair[0]], global_signatures[pair[1]]
        raw_by_sc: Dict[str, int] = {}
        mis_by_sc: Dict[str, int] = {}
        for model in models:
            raw, mis = greedy_two_support(model, {pair})
            raw_by_sc[model.scenario] = raw[pair]
            mis_by_sc[model.scenario] = mis[pair]
        scenarios = sorted(sc for sc, count in mis_by_sc.items() if count >= args.min_mis_support)
        if len(scenarios) < args.min_scenario_support:
            continue
        motifs.append(make_two_motif(
            f"FLEXIS_PRIOR_{motif_counter:05d}_2HOP", sig1, sig2, scenarios,
            {sc: raw_by_sc[sc] for sc in scenarios}, {sc: mis_by_sc[sc] for sc in scenarios},
            sum(raw_by_sc[sc] for sc in scenarios)))
        motif_counter += 1

    hops: List[Dict[str, object]] = []
    for motif in motifs:
        if int(motif["hops"]) == 1:
            hops.append({
                "motif_id": motif["id"], "index": 1,
                "src_role": motif["src_role"], "syscall": motif["syscalls"][0],
                "dst_role": motif["dst_role"],
            })
        else:
            for index, hop in enumerate(motif["chain"], 1):
                hops.append({"motif_id": motif["id"], "index": index, **hop})

    out_dir = Path(args.out)
    (out_dir / "folds").mkdir(parents=True, exist_ok=True)
    kg = {
        "version": VERSION,
        "fold_of": "global",
        "train_scenarios": [scenario for scenario, _ in SCENARIOS],
        "groundtruth_used": False,
        "source": {
            "paper": "arXiv:2404.01585v1",
            "upstream_repository": "https://github.com/akshit-sharma/flexis",
            "upstream_commit": FLEXIS_COMMIT,
            "adapter": "TraceSage stream adapter; upstream vf3.bin executable was not used",
        },
        "selection": {
            "min_scenario_support": args.min_scenario_support,
            "min_edge_count": args.min_edge_count,
            "min_mis_support": args.min_mis_support,
            "max_two_candidates": args.max_two_candidates,
            "support_metric": "greedy maximal node-disjoint occurrence set",
            "candidate_generation": "typed 1-hop edges and 2-hop paths sharing a middle node",
            "node_identity": "parser node primary-key fields from nodes.csv",
        },
        "input_files": [
            {"scenario": scenario, "edges": str(edge), "nodes": str(node)}
            for scenario, edge, node in resolved
        ],
        "candidate_diagnostics": {
            "one_hop": one_diagnostics,
            "two_hop_candidate_count": len(pair_candidates),
        },
        "motifs": motifs,
        "hops": hops,
        "counts": {
            "motifs": len(motifs),
            "admitted": len(motifs),
            "hops": len(hops),
            "one_hop": sum(1 for m in motifs if int(m["hops"]) == 1),
            "two_hop": sum(1 for m in motifs if int(m["hops"]) == 2),
        },
        "elapsed_seconds": round(time.time() - started, 3),
    }
    fold_path = out_dir / "folds" / "global.json"
    fold_path.write_text(json.dumps(kg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = dict(kg)
    manifest["folds"] = {"global": {"path": str(fold_path), "counts": kg["counts"]}}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out_dir), "counts": kg["counts"], "elapsed_seconds": kg["elapsed_seconds"]}, ensure_ascii=False), flush=True)


SIGNATURES_BY_ID: Dict[int, Tuple[str, str, str]] = {}


if __name__ == "__main__":
    main()
