#!/usr/bin/env python3
"""Offline verification for output/rule-kg/flexis-benign-v1.

Three independent stages, none of which calls an LLM, opens Neo4j or touches
the network:

* ``structure``   : artifact self-consistency, input provenance, threshold
                    conformance, and source/log scanning.
* ``recount``     : re-derives role signatures, per-scenario raw counts and
                    greedy node-disjoint support directly from nodes.csv /
                    edges.csv with a separate implementation, re-checks
                    candidate completeness under the declared thresholds, and
                    runs the post-hoc groundtruth contamination audit.
* ``determinism`` : reruns the miner twice into scratch directories and diffs
                    everything except runtime fields.

The reimplementation below is written against the documented role definitions;
it is an independent code path, not an independent semantics. A wrong role
definition cannot be detected here, only a miscounted number.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "output" / "rule-kg" / "flexis-benign-v1"
OUT_DIR = ROOT / "tmp" / "flexis-verify"
LOG_PATH = ROOT / "tmp" / "flexis-benign-v1.log"
PARSER_ROOT = ROOT / "output" / "parser-v2"
GT_ROOT = ROOT / "groundtruth"
FLEXIS_REPO = ROOT / "third_party" / "flexis"

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
DIR_OF = {name: dirname for name, dirname in SCENARIOS}

WRITE_ACTIONS = {"create", "write", "rename", "link", "unlink", "truncate", "chmod", "mount", "umount"}
DELETE_ACTIONS = {"unlink", "rename"}
NET_OUT_ACTIONS = {"connect", "send", "bind", "listen"}
PRIV_ACTIONS = {"chmod", "chown"}
READ_ACTIONS = {"read", "stat", "mmap_read"}
EXEC_FILE_ACTIONS = {"exec", "mmap_exec"}
AUTH_MARKERS = (
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers",
    "authorized_keys", "/.ssh/", "/etc/ssh/ssh_host",
)
SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/boot/", "/opt/", "/etc/", "/var/lib/")

NodeKey = Tuple[str, str, str, str, str, str, str]

EDGE_COLS = (
    "src_label", "src_host", "src_container", "src_pid", "src_start_ns", "src_path",
    "dst_label", "dst_host", "dst_container", "dst_pid", "dst_start_ns", "dst_path",
    "action", "syscall", "event_id", "edge_class", "result",
)
REQUIRED_EDGE_COLS = EDGE_COLS[:14]


def norm(value: object) -> str:
    return "" if value is None else str(value)


# --------------------------------------------------------------------------
# stage: structure
# --------------------------------------------------------------------------

def check(id_: str, ok: bool, detail: str) -> Dict[str, object]:
    print(f"[{'PASS' if ok else 'FAIL'}] {id_}: {detail}", flush=True)
    return {"id": id_, "ok": bool(ok), "detail": detail}


def stage_structure(kg: Dict[str, object]) -> Dict[str, object]:
    checks: List[Dict[str, object]] = []

    checks.append(check("no_groundtruth_flag", kg.get("groundtruth_used") is False,
                        f"groundtruth_used={kg.get('groundtruth_used')!r}"))

    source = kg.get("source") or {}
    expected_commit = "9f260efa658bec39ffd514eec6765a94417ae9c9"
    actual_commit: Optional[str] = None
    if FLEXIS_REPO.is_dir():
        proc = subprocess.run(["git", "-C", str(FLEXIS_REPO), "rev-parse", "HEAD"],
                              capture_output=True, text=True)
        actual_commit = proc.stdout.strip() or None
    checks.append(check("upstream_commit",
                        actual_commit == source.get("upstream_commit") == expected_commit,
                        f"artifact={source.get('upstream_commit')} repo={actual_commit} expected={expected_commit}"))

    inputs = kg.get("input_files") or []
    missing: List[str] = []
    misplaced: List[str] = []
    seen_scenarios: List[str] = []
    for item in inputs:
        name = str(item.get("scenario"))
        seen_scenarios.append(name)
        for key in ("edges", "nodes"):
            p = Path(str(item.get(key)))
            if not p.is_file():
                missing.append(str(p))
                continue
            want_dir = DIR_OF.get(name)
            if p.parent.name != want_dir or p.parent.parent.resolve() != PARSER_ROOT.resolve():
                misplaced.append(str(p))
    checks.append(check("input_files_exist", not missing,
                        f"{len(inputs)} pairs checked, missing={len(missing)} {missing[:3]}"))
    checks.append(check("input_files_in_parser_root", not misplaced,
                        f"outside expected parser-v2 scenario dir: {misplaced[:3]}"))
    checks.append(check("input_scenario_set", sorted(seen_scenarios) == sorted(DIR_OF),
                        f"artifact={len(seen_scenarios)} expected={len(DIR_OF)}"))

    motifs = kg.get("motifs") or []
    hops = kg.get("hops") or []
    counts = kg.get("counts") or {}
    recomputed = {
        "motifs": len(motifs),
        "admitted": sum(1 for m in motifs if m.get("admitted")),
        "hops": len(hops),
        "one_hop": sum(1 for m in motifs if int(m.get("hops", 0)) == 1),
        "two_hop": sum(1 for m in motifs if int(m.get("hops", 0)) == 2),
    }
    checks.append(check("counts_consistent", recomputed == counts,
                        f"artifact={counts} recomputed={recomputed}"))

    hop_problems: List[str] = []
    by_motif: Dict[str, List[Dict[str, object]]] = {}
    for h in hops:
        by_motif.setdefault(str(h.get("motif_id")), []).append(h)
    for m in motifs:
        mid = str(m.get("id"))
        chain = by_motif.get(mid, [])
        want = int(m.get("hops", 0))
        if len(chain) != want:
            hop_problems.append(f"{mid}: hops={want} hop_records={len(chain)}")
            continue
        if want == 1:
            h = chain[0]
            if (h.get("src_role"), h.get("syscall"), h.get("dst_role")) != (
                    m.get("src_role"), (m.get("syscalls") or [""])[0], m.get("dst_role")):
                hop_problems.append(f"{mid}: hop does not rebuild 1-hop edge")
        else:
            got = [(h.get("src_role"), h.get("syscall"), h.get("dst_role")) for h in sorted(chain, key=lambda x: x["index"])]
            want_chain = [(c["src_role"], c["syscall"], c["dst_role"]) for c in (m.get("chain") or [])]
            if got != want_chain:
                hop_problems.append(f"{mid}: hop chain mismatch")
    checks.append(check("hop_rebuild", not hop_problems, f"problems={hop_problems[:3]}"))

    key_problems: List[str] = []
    threshold_problems: List[str] = []
    sel = kg.get("selection") or {}
    min_sc = int(sel.get("min_scenario_support", 0))
    min_edges = int(sel.get("min_edge_count", 0))
    min_mis = int(sel.get("min_mis_support", 0))
    for m in motifs:
        stats = m.get("stats") or {}
        sc = list(m.get("support_scenarios") or [])
        raw = stats.get("raw_occurrences_by_scenario") or {}
        mis = stats.get("greedy_mis_support_by_scenario") or {}
        if not (sorted(sc) == sorted(raw) == sorted(mis)):
            key_problems.append(f"{m.get('id')}: scenario/raw/mis key mismatch {sorted(sc)} {sorted(raw)} {sorted(mis)}")
            continue
        if len(sc) < min_sc or int(stats.get("scenario_support", 0)) != len(sc):
            threshold_problems.append(f"{m.get('id')}: scenario_support={len(sc)} < {min_sc}")
        low_raw = {k: v for k, v in raw.items() if v < min_edges}
        low_mis = {k: v for k, v in mis.items() if v < min_mis}
        if low_raw:
            threshold_problems.append(f"{m.get('id')}: raw below {min_edges} in {low_raw}")
        if low_mis:
            threshold_problems.append(f"{m.get('id')}: mis below {min_mis} in {low_mis}")
    checks.append(check("stat_key_alignment", not key_problems, f"problems={key_problems[:3]}"))
    checks.append(check("declared_thresholds_hold", not threshold_problems,
                        f"sc>={min_sc} raw>={min_edges} mis>={min_mis}; problems={threshold_problems[:3]}"))

    bad_edges: List[str] = []
    if LOG_PATH.is_file():
        for line in LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            m2 = re.search(r"bad_edges=(\d+)", line)
            if m2 and int(m2.group(1)) != 0:
                bad_edges.append(line.strip())
    checks.append(check("log_bad_edges_zero", not bad_edges, f"nonzero lines={bad_edges[:3]}"))

    tool = ROOT / "tools" / "mine_flexis_benign_prior.py"
    src = tool.read_text(encoding="utf-8")
    code_lines = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
    gt_reads = [ln for ln in code_lines
                if "groundtruth" in ln and ("open(" in ln or "read_text" in ln or "Path(" in ln)]
    network = [ln for ln in code_lines if re.search(r"\brequests\b|urllib|http[s]?://[^\"]*\"?\s*\)|neo4j|GraphDatabase", ln)]
    checks.append(check("tool_reads_no_groundtruth", not gt_reads, f"lines={gt_reads[:2]}"))
    checks.append(check("tool_no_network_or_db", not network, f"lines={network[:2]}"))

    log_hits: List[str] = []
    if LOG_PATH.is_file():
        text = LOG_PATH.read_text(encoding="utf-8", errors="replace").lower()
        log_hits = [w for w in ("llm", "gpt", "openai", "neo4j", "http") if w in text]
    checks.append(check("log_no_llm_or_db", not log_hits, f"markers={log_hits}"))

    ok = all(c["ok"] for c in checks)
    print(f"\nstructure: {'OK' if ok else 'BLOCKED'} ({sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed)", flush=True)
    return {"ok": ok, "checks": checks}


# --------------------------------------------------------------------------
# stage: recount
# --------------------------------------------------------------------------

def node_key_from_nodes(row: Dict[str, str]) -> NodeKey:
    label = norm(row.get("label"))
    host = norm(row.get("host_id"))
    container = norm(row.get("container_id"))
    if label != "Network":
        container = container or "host"
    return (label, host, container, norm(row.get("pid")), norm(row.get("start_ns")),
            norm(row.get("path")), norm(row.get("endpoints")))


def norm_container(label: str, container: str) -> str:
    if label == "Network":
        return ""
    return container or "host"


class Scenario:
    def __init__(self, name: str, dirname: str) -> None:
        self.name = name
        self.dir = PARSER_ROOT / dirname
        self.edges = self.dir / "edges.csv"
        self.nodes = self.dir / "nodes.csv"
        self.keys: List[NodeKey] = []
        self.exe_of: List[str] = []
        self.id_of: Dict[NodeKey, int] = {}
        self.exe_counts: Dict[str, int] = {}
        self.in_actions: List[Set[str]] = []
        self.out_actions: List[Set[str]] = []
        self.writer_ids: Dict[int, Set[int]] = {}
        self.roles: List[str] = []
        self.bad_edges = 0
        self.rows = 0

    def load_nodes(self) -> None:
        with self.nodes.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                key = node_key_from_nodes(row)
                if key in self.id_of:
                    continue
                self.id_of[key] = len(self.keys)
                self.keys.append(key)
                exe = norm(row.get("exe_path")) or "<unknown>"
                self.exe_of.append(exe)
                if key[0] == "Process":
                    self.exe_counts[exe] = self.exe_counts.get(exe, 0) + 1

    def iter_edges(self, with_tail: bool = False) -> Iterator[Tuple[int, int, str, str, Tuple[str, str, str]]]:
        with self.edges.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader)
            idx = {name: header.index(name) for name in header}
            missing = [c for c in REQUIRED_EDGE_COLS if c not in idx]
            if missing:
                raise RuntimeError(f"{self.edges}: missing columns {missing}")
            for row in reader:
                self.rows += 1
                src_key = (row[idx["src_label"]], row[idx["src_host"]],
                           norm_container(row[idx["src_label"]], row[idx["src_container"]]),
                           row[idx["src_pid"]], row[idx["src_start_ns"]], row[idx["src_path"]], "")
                dst_key = (row[idx["dst_label"]], row[idx["dst_host"]],
                           norm_container(row[idx["dst_label"]], row[idx["dst_container"]]),
                           row[idx["dst_pid"]], row[idx["dst_start_ns"]], row[idx["dst_path"]], "")
                if src_key[0] == "Process":
                    src_key = (src_key[0], src_key[1], src_key[2], src_key[3], src_key[4] or "0", "", "")
                elif src_key[0] == "File":
                    src_key = (src_key[0], src_key[1], src_key[2], "", "", src_key[5], "")
                elif src_key[0] == "Network":
                    src_key = (src_key[0], src_key[1], "", "", "", "", src_key[5])
                if dst_key[0] == "Process":
                    dst_key = (dst_key[0], dst_key[1], dst_key[2], dst_key[3], dst_key[4] or "0", "", "")
                elif dst_key[0] == "File":
                    dst_key = (dst_key[0], dst_key[1], dst_key[2], "", "", dst_key[5], "")
                elif dst_key[0] == "Network":
                    dst_key = (dst_key[0], dst_key[1], "", "", "", "", dst_key[5])
                try:
                    src = self.id_of[src_key]
                    dst = self.id_of[dst_key]
                except KeyError:
                    self.bad_edges += 1
                    continue
                tail = (row[idx["event_id"]], row[idx["edge_class"]], row[idx["result"]])
                if with_tail:
                    yield src, dst, row[idx["action"]], row[idx["syscall"]], tail
                else:
                    yield src, dst, row[idx["action"]], row[idx["syscall"]], ("", "", "")

    def prepare_roles(self) -> None:
        n = len(self.keys)
        self.in_actions = [set() for _ in range(n)]
        self.out_actions = [set() for _ in range(n)]
        for src, dst, action, _syscall, _ in self.iter_edges():
            self.out_actions[src].add(action)
            self.in_actions[dst].add(action)
            if self.keys[dst][0] == "File" and self.keys[src][0] == "Process" and action in WRITE_ACTIONS:
                writers = self.writer_ids.setdefault(dst, set())
                if len(writers) < 3:
                    writers.add(src)
        self.roles = [self._role(i) for i in range(n)]

    def _role(self, i: int) -> str:
        label, _host, _container, _pid, _start, path, _endpoints = self.keys[i]
        ins = self.in_actions[i]
        outs = self.out_actions[i]
        if label == "Process":
            count = self.exe_counts.get(self.exe_of[i], 1)
            in_net = bool(ins & {"accept", "recv"})
            out_net = bool(outs & NET_OUT_ACTIONS)
            direction = "both" if (in_net and out_net) else "in" if in_net else "out" if out_net else "none"
            has_clone = "clone" in outs
            has_exec = "exec" in ins or "exec" in outs
            spawn = "multi" if (has_clone and has_exec) else "exec" if has_exec else "clone" if has_clone else "leaf"
            inst = "single" if count < 3 else "few" if count < 56 else "many"
            priv = "chg" if (outs & PRIV_ACTIONS) else "-"
            return f"P.{direction}.{spawn}.{inst}.{priv}"
        if label == "File":
            bits = []
            if ins & WRITE_ACTIONS:
                bits.append("w")
            if outs & EXEC_FILE_ACTIONS:
                bits.append("x")
            if outs & READ_ACTIONS:
                bits.append("r")
            if (ins | outs) & DELETE_ACTIONS:
                bits.append("d")
            bit_s = "".join(bits) or "-"
            writers = len(self.writer_ids.get(i, ()))
            band = "none" if writers == 0 else "single" if writers == 1 else "multi"
            sens = "auth" if any(mk in path for mk in AUTH_MARKERS) else "cfg" if path.startswith("/etc/") else "-"
            place = "sys" if path.startswith(SYSTEM_PREFIXES) else "usr"
            return f"F.{bit_s}.{band}.{sens}.{place}"
        if label == "Network":
            listened = "accept" in outs
            dialed = bool(ins & NET_OUT_ACTIONS)
            direction = "both" if (listened and dialed) else "listen" if listened else "dial"
            return f"N.{direction}.single"
        return label or "Unknown"


def load_gt(scenario: str) -> Tuple[Dict[Tuple[str, str, str], str], int]:
    path = GT_ROOT / f"{scenario}.groundtruth.json"
    if not path.is_file():
        return {}, 0
    gt = json.loads(path.read_text(encoding="utf-8"))
    out: Dict[Tuple[str, str, str], str] = {}
    total = 0
    for step in gt.get("attack_path") or []:
        for e in step.get("edges") or []:
            total += 1
            parts = str(e.get("edge_key", "")).split(":")
            if len(parts) < 3:
                continue
            out[(parts[1], parts[0], str(e.get("action")))] = str(e.get("edge_id"))
    return out, total


def stage_recount(kg: Dict[str, object], only: Optional[Set[str]], max_edges: int) -> Dict[str, object]:
    rules: Dict[str, Tuple[str, str, str]] = {}
    for m in kg.get("motifs") or []:
        rules[str(m["id"])] = (str(m["src_role"]), str((m.get("syscalls") or [""])[0]), str(m["dst_role"]))
    sig_to_rule = {v: k for k, v in rules.items()}
    print(f"declared rules={len(rules)}", flush=True)

    declared_diag = {}
    for d in (kg.get("candidate_diagnostics") or {}).get("one_hop") or []:
        declared_diag[tuple(d["signature"])] = d
    print(f"declared one-hop candidates in diagnostics={len(declared_diag)}", flush=True)

    min_sc = int((kg.get("selection") or {}).get("min_scenario_support", 0))
    min_edges = int((kg.get("selection") or {}).get("min_edge_count", 0))
    min_mis = int((kg.get("selection") or {}).get("min_mis_support", 0))

    per_scenario: Dict[str, object] = {}
    rule_report: Dict[str, Dict[str, object]] = {
        rid: {"id": rid, "signature": list(sig), "by_scenario": {}, "raw_total": 0,
              "attack_matches": 0, "all_matches": 0, "gt_steps_hit": set(), "src_nodes": {}, "dst_nodes": {},
              "edge_class": Counter(), "result": Counter()}
        for rid, sig in rules.items()
    }
    sig_counts: Dict[Tuple[str, str, str], Dict[str, int]] = {}
    started = time.time()

    for name, dirname in SCENARIOS:
        if only and name not in only:
            continue
        t0 = time.time()
        sc = Scenario(name, dirname)
        sc.load_nodes()
        sc.prepare_roles()
        gt_edges, gt_total = load_gt(name)

        local_counts: Dict[Tuple[str, str, str], int] = {}
        used: Dict[str, Set[int]] = {rid: set() for rid in rules}
        raw: Dict[str, int] = {rid: 0 for rid in rules}
        support: Dict[str, int] = {rid: 0 for rid in rules}
        atk: Dict[str, int] = {rid: 0 for rid in rules}
        gt_hit: Dict[str, Set[str]] = {rid: set() for rid in rules}
        gt_any: Set[str] = set()
        src_ctr: Dict[str, Counter] = {rid: Counter() for rid in rules}
        dst_ctr: Dict[str, Counter] = {rid: Counter() for rid in rules}
        edge_ctr: Dict[str, Counter] = {rid: Counter() for rid in rules}
        res_ctr: Dict[str, Counter] = {rid: Counter() for rid in rules}

        rows = 0
        for src, dst, action, syscall, (event_id, edge_class, result) in sc.iter_edges(with_tail=True):
            rows += 1
            if max_edges and rows > max_edges:
                break
            sig = (sc.roles[src], syscall or action, sc.roles[dst])
            local_counts[sig] = local_counts.get(sig, 0) + 1
            rid = sig_to_rule.get(sig)
            if rid is None:
                continue
            raw[rid] += 1
            src_ctr[rid][src] += 1
            dst_ctr[rid][dst] += 1
            edge_ctr[rid][edge_class] += 1
            res_ctr[rid][result] += 1
            key = (event_id, edge_class, action)
            if key in gt_edges:
                atk[rid] += 1
                gt_hit[rid].add(gt_edges[key])
                gt_any.add(gt_edges[key])
            occ = used[rid]
            if src != dst and src not in occ and dst not in occ:
                occ.add(src)
                occ.add(dst)
                support[rid] += 1

        for sig, count in local_counts.items():
            sig_counts.setdefault(sig, {})[name] = count

        per_scenario[name] = {
            "nodes": len(sc.keys),
            "edges": rows,
            "truncated": bool(max_edges and rows >= max_edges),
            "bad_edges": sc.bad_edges,
            "distinct_signatures": len(local_counts),
            "gt_edges_loaded": gt_total,
            "gt_steps_touched": len(gt_any),
            "elapsed": round(time.time() - t0, 1),
        }
        for rid in rules:
            rr = rule_report[rid]
            rr["by_scenario"][name] = {
                "raw": raw[rid],
                "greedy_mis": support[rid],
                "attack_matches": atk[rid],
                "attack_ratio": (atk[rid] / raw[rid]) if raw[rid] else None,
                "gt_steps_hit": len(gt_hit[rid]),
                "distinct_src": len(src_ctr[rid]),
                "distinct_dst": len(dst_ctr[rid]),
            }
            rr["raw_total"] += raw[rid]
            rr["attack_matches"] += atk[rid]
            rr["all_matches"] += raw[rid]
            rr["gt_steps_hit"] |= gt_hit[rid]
            for ctr, store in ((src_ctr[rid], rr["src_nodes"]), (dst_ctr[rid], rr["dst_nodes"])):
                top = ctr.most_common(10)
                store[name] = [{"key": list(sc.keys[i]), "count": c} for i, c in top]
            rr["edge_class"].update(edge_ctr[rid])
            rr["result"].update(res_ctr[rid])
        print(f"[{name}] nodes={len(sc.keys)} edges={rows} bad={sc.bad_edges} sigs={len(local_counts)} "
              f"gt={gt_total} gt_touched={len(gt_any)} {round(time.time()-t0,1)}s", flush=True)

    # candidate completeness under declared thresholds
    candidate_sigs = {sig for sig, by_sc in sig_counts.items()
                      if len(by_sc) >= min_sc and min(by_sc.values()) >= min_edges}
    diag_sigs = set(declared_diag)
    partial = only is not None
    missed = sorted(candidate_sigs - diag_sigs)
    extra = sorted(diag_sigs - candidate_sigs)
    print(f"candidate set: recomputed={len(candidate_sigs)} declared={len(diag_sigs)} "
          f"missed={len(missed)} extra={len(extra)}" + (" (PARTIAL: single-scenario mode, not comparable)" if partial else ""), flush=True)
    for sig in missed[:5]:
        print(f"  MISSED {sig} scenarios={len(sig_counts[sig])}", flush=True)

    # verify declared diagnostics numbers against recount
    diag_mismatch = []
    for rid, sig in rules.items():
        d = declared_diag.get(sig)
        if not d:
            diag_mismatch.append(f"{rid}: not in diagnostics")
            continue
        rr = rule_report[rid]
        for sc_name, stat in rr["by_scenario"].items():
            raw_map = d.get("raw_by_scenario") or {}
            mis_map = d.get("mis_by_scenario") or {}
            dec_raw = raw_map.get(sc_name, 0)
            dec_mis = mis_map.get(sc_name, 0)
            if dec_raw != stat["raw"] or dec_mis != stat["greedy_mis"]:
                diag_mismatch.append(f"{rid}@{sc_name}: raw {stat['raw']} vs {dec_raw}, mis {stat['greedy_mis']} vs {dec_mis}")
            if (sc_name in raw_map) != (stat["raw"] > 0) or (sc_name in mis_map) != (stat["raw"] > 0):
                diag_mismatch.append(f"{rid}@{sc_name}: scenario presence differs (recount raw={stat['raw']})")
    print(f"recount vs declared diagnostics mismatches={len(diag_mismatch)}", flush=True)
    for line in diag_mismatch[:10]:
        print(f"  {line}", flush=True)

    gt_audit = {}
    for rid, rr in rule_report.items():
        gt_audit[rid] = {
            "signature": rr["signature"],
            "all_matches": rr["all_matches"],
            "attack_matches": rr["attack_matches"],
            "contamination_rate": (rr["attack_matches"] / rr["all_matches"]) if rr["all_matches"] else None,
            "matched_gt_steps": len(rr["gt_steps_hit"]),
            "by_scenario": {k: {"raw": v["raw"], "attack_matches": v["attack_matches"],
                                "attack_ratio": v["attack_ratio"], "gt_steps_hit": v["gt_steps_hit"]}
                            for k, v in rr["by_scenario"].items()},
        }

    print("\n--- per-rule summary ---", flush=True)
    for rid, g in gt_audit.items():
        print(f"{rid} {g['signature']}", flush=True)
        print(f"  matches={g['all_matches']} gt_attack_matches={g['attack_matches']} "
              f"contamination={g['contamination_rate']} gt_steps_hit={g['matched_gt_steps']}", flush=True)

    total_gt = 0
    for name, _ in SCENARIOS:
        if only and name not in only:
            continue
        total_gt += per_scenario[name]["gt_edges_loaded"]
    covered = set()
    for rr in rule_report.values():
        covered |= rr["gt_steps_hit"]
    print(f"\nGT steps covered by at least one rule: {len(covered)} / {total_gt}", flush=True)

    result = {
        "elapsed_seconds": round(time.time() - started, 1),
        "selection": {"min_scenario_support": min_sc, "min_edge_count": min_edges, "min_mis_support": min_mis},
        "per_scenario": per_scenario,
        "candidate_completeness": {
            "recomputed": len(candidate_sigs), "declared": len(diag_sigs),
            "missed": [list(s) for s in missed], "extra": [list(s) for s in extra],
            "partial_run": partial,
        },
        "declared_vs_recount_mismatches": diag_mismatch,
        "gt_audit": gt_audit,
        "gt_steps_covered": len(covered), "gt_steps_total": total_gt,
        "rule_detail": {
            rid: {
                "signature": rr["signature"],
                "edge_class": dict(rr["edge_class"]),
                "result_values": dict(rr["result"]),
                "src_nodes_top": rr["src_nodes"],
                "dst_nodes_top": rr["dst_nodes"],
            } for rid, rr in rule_report.items()
        },
    }
    return result


# --------------------------------------------------------------------------
# stage: determinism
# --------------------------------------------------------------------------

def strip_runtime(obj: object) -> object:
    if isinstance(obj, dict):
        return {k: strip_runtime(v) for k, v in obj.items() if k != "elapsed_seconds"}
    if isinstance(obj, list):
        return [strip_runtime(v) for v in obj]
    return obj


def stage_determinism() -> Dict[str, object]:
    runs = []
    for tag in ("run1", "run2"):
        out = OUT_DIR / tag
        cmd = [sys.executable, str(ROOT / "tools" / "mine_flexis_benign_prior.py"),
               "--edge-root", str(PARSER_ROOT), "--node-root", str(PARSER_ROOT), "--out", str(out)]
        print(f"running {tag}: {' '.join(cmd)}", flush=True)
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        print(f"  exit={proc.returncode} elapsed={round(time.time()-t0,1)}s", flush=True)
        if proc.returncode != 0:
            print(proc.stdout[-4000:], flush=True)
            print(proc.stderr[-4000:], flush=True)
            raise SystemExit(f"determinism run {tag} failed")
        runs.append(json.loads((out / "folds" / "global.json").read_text(encoding="utf-8")))

    a, b = strip_runtime(runs[0]), strip_runtime(runs[1])
    same = json.dumps(a, sort_keys=True, ensure_ascii=False) == json.dumps(b, sort_keys=True, ensure_ascii=False)
    diffs: List[str] = []
    if not same:
        for key in sorted(set(a) | set(b)):
            if json.dumps(a.get(key), sort_keys=True) != json.dumps(b.get(key), sort_keys=True):
                diffs.append(key)
    print(f"\ndeterminism: {'IDENTICAL' if same else 'DIFFERS'} differing_top_level_keys={diffs}", flush=True)

    original = strip_runtime(json.loads((RULE_DIR / "folds" / "global.json").read_text(encoding="utf-8")))
    vs_artifact = json.dumps(original, sort_keys=True) == json.dumps(a, sort_keys=True)
    print(f"rerun vs stored artifact (elapsed excluded): {'IDENTICAL' if vs_artifact else 'DIFFERS'}", flush=True)
    if not vs_artifact:
        for key in sorted(set(original) | set(a)):
            if json.dumps(original.get(key), sort_keys=True) != json.dumps(a.get(key), sort_keys=True):
                print(f"  differs: {key}", flush=True)
    return {"identical": same, "differing_keys": diffs, "matches_stored_artifact": vs_artifact,
            "elapsed_run1": runs[0].get("elapsed_seconds"), "elapsed_run2": runs[1].get("elapsed_seconds")}


def main() -> None:
    ap = argparse.ArgumentParser(description="Offline verification of the FLEXIS benign-prior artifacts")
    ap.add_argument("--stage", choices=("structure", "recount", "determinism", "all"), default="all")
    ap.add_argument("--scenario", action="append", default=None, help="limit recount to these scenario names")
    ap.add_argument("--max-edges", type=int, default=0, help="stop each scenario after N edges (smoke test)")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    kg = json.loads((RULE_DIR / "folds" / "global.json").read_text(encoding="utf-8"))
    summary: Dict[str, object] = {}

    if args.stage in ("structure", "all"):
        summary["structure"] = stage_structure(kg)
        (OUT_DIR / "structure.json").write_text(json.dumps(summary["structure"], ensure_ascii=False, indent=2), encoding="utf-8")

    if args.stage in ("recount", "all"):
        only = set(args.scenario) if args.scenario else None
        summary["recount"] = stage_recount(kg, only, args.max_edges)
        (OUT_DIR / "recount.json").write_text(json.dumps(summary["recount"], ensure_ascii=False, indent=2), encoding="utf-8")

    if args.stage in ("determinism", "all"):
        summary["determinism"] = stage_determinism()
        (OUT_DIR / "determinism.json").write_text(json.dumps(summary["determinism"], ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nwrote {OUT_DIR}", flush=True)


if __name__ == "__main__":
    main()
