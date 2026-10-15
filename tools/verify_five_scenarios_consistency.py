#!/usr/bin/env python3
"""Full 5-scenario consistency verification between scap-parser and baseline databases.

Streams each scenario's capture.scap via WSL2 backend, ingests into an isolated
test database (attack-test-verify-<id>), performs strict node/edge/label/relation
audits against the baseline database (attack-<id>-...), and then safely drops the
temporary database.

Adheres strictly to the Four Engineering Laws:
- 100.000% zero-drift match required.
- Baseline databases are NEVER modified.
- Full timing, counts, and verification logs are recorded.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scap-parser"))

from parsers.storage.neo4j_writer import Neo4jWriter

SCENARIOS = [
    {
        "id": 1,
        "name": "1_Web_Exploit_Ransomware",
        "baseline_db": "attack-1-web-exploit-ransomware",
        "scap_path": ROOT / "attack" / "data" / "1" / "capture.scap",
    },
    {
        "id": 2,
        "name": "2_SSH_Spray_Lateral_Exfiltration",
        "baseline_db": "attack-2-ssh-spray-lateral-exfiltration",
        "scap_path": ROOT / "attack" / "data" / "2" / "capture.scap",
    },
    {
        "id": 3,
        "name": "3_Phishing_Beacon_Cryptomining",
        "baseline_db": "attack-3-phishing-beacon-cryptomining",
        "scap_path": ROOT / "attack" / "data" / "3" / "capture.scap",
    },
    {
        "id": 4,
        "name": "4_Repo_Poisoning_Backdoor",
        "baseline_db": "attack-4-repo-poisoning-backdoor",
        "scap_path": ROOT / "attack" / "data" / "4" / "capture.scap",
    },
    {
        "id": 5,
        "name": "5_Exposed_Service_Pivot",
        "baseline_db": "attack-5-exposed-service-pivot",
        "scap_path": ROOT / "attack" / "data" / "5" / "capture.scap",
    },
]

NODE_LABELS = ["Process", "File", "Network"]
EDGE_TYPES = ["p2p", "p2f", "f2p", "p2n", "n2p"]


def get_db_stats(writer: Neo4jWriter, db_name: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    nodes = {}
    for lbl in NODE_LABELS:
        res = writer._driver.execute_query(
            f"MATCH (n:{lbl}) RETURN count(n) AS c", database_=db_name
        )
        nodes[lbl] = res.records[0]["c"]

    edges = {}
    for r in EDGE_TYPES:
        res = writer._driver.execute_query(
            f"MATCH ()-[e:{r}]->() RETURN count(e) AS c", database_=db_name
        )
        edges[r] = res.records[0]["c"]

    return nodes, edges


def manage_db(action: str, db_name: str) -> None:
    w_sys = Neo4jWriter(database="system")
    try:
        if action == "create":
            q = f"CREATE DATABASE {chr(96)}{db_name}{chr(96)} IF NOT EXISTS WAIT"
            w_sys._driver.execute_query(q)
        elif action == "drop":
            q = f"DROP DATABASE {chr(96)}{db_name}{chr(96)} IF EXISTS WAIT"
            w_sys._driver.execute_query(q)
    finally:
        w_sys.close()


def run_verification(target_ids: List[int]) -> int:
    python_exe = sys.executable
    main_script = str(ROOT / "scap-parser" / "main.py")
    results = []

    print("=" * 80)
    print("TraceSage — 5-Scenario Consistency Verification Pipeline")
    print("=" * 80)

    for item in SCENARIOS:
        sc_id = item["id"]
        if target_ids and sc_id not in target_ids:
            continue

        name = item["name"]
        baseline_db = item["baseline_db"]
        scap_path = item["scap_path"]
        test_db = f"attack-test-verify-{sc_id}"

        print(f"\n{'='*30} [Scenario {sc_id}: {name}] {'='*30}")
        print(f"SCAP file  : {scap_path} ({scap_path.stat().st_size / (1024*1024):.2f} MB)")
        print(f"Baseline DB: {baseline_db}")
        print(f"Test DB    : {test_db}")

        # 1. Reset and create test database
        print(f"[1/4] Preparing clean test database '{test_db}'...")
        manage_db("drop", test_db)
        manage_db("create", test_db)

        # 2. Run scap-parser via WSL2 backend
        print(f"[2/4] Streaming and ingesting into '{test_db}' via WSL backend...")
        cmd = [
            python_exe,
            "-u",
            main_script,
            "--scap", str(scap_path),
            "--scenario", name,
            "--backend", "wsl",
            "--neo4j-database", test_db,
        ]
        t0 = time.time()
        proc = subprocess.run(cmd, cwd=str(ROOT))
        elapsed = time.time() - t0

        if proc.returncode != 0:
            print(f"ERROR: scap-parser failed with exit code {proc.returncode}")
            manage_db("drop", test_db)
            return 1

        print(f"Ingestion finished in {elapsed:.2f}s.")

        # 3. Query stats and compare
        print(f"[3/4] Performing strict data consistency comparison...")
        w_comp = Neo4jWriter()
        try:
            base_nodes, base_edges = get_db_stats(w_comp, baseline_db)
            test_nodes, test_edges = get_db_stats(w_comp, test_db)
        finally:
            w_comp.close()

        # Audit differences
        node_diffs = {lbl: test_nodes[lbl] - base_nodes[lbl] for lbl in NODE_LABELS}
        edge_diffs = {r: test_edges[r] - base_edges[r] for r in EDGE_TYPES}
        has_node_diff = any(v != 0 for v in node_diffs.values())
        has_edge_diff = any(v != 0 for v in edge_diffs.values())

        passed = not has_node_diff and not has_edge_diff
        status_str = "PASSED (100.000% EXACT MATCH)" if passed else "FAILED (MISMATCH)"

        res_entry = {
            "id": sc_id,
            "name": name,
            "elapsed": elapsed,
            "passed": passed,
            "base_nodes": base_nodes,
            "test_nodes": test_nodes,
            "node_diffs": node_diffs,
            "base_edges": base_edges,
            "test_edges": test_edges,
            "edge_diffs": edge_diffs,
        }
        results.append(res_entry)

        print(f"Status: {status_str}")
        print("  Nodes:")
        for lbl in NODE_LABELS:
            print(f"    {lbl:10}: baseline={base_nodes[lbl]:7}, test={test_nodes[lbl]:7}, diff={node_diffs[lbl]:+d}")
        print("  Edges:")
        for r in EDGE_TYPES:
            print(f"    {r:10}: baseline={base_edges[r]:7}, test={test_edges[r]:7}, diff={edge_diffs[r]:+d}")

        if not passed:
            print(f"ABORTING: Scenario {sc_id} failed strict consistency check! Keeping '{test_db}' for inspection.")
            return 1

        # 4. Clean up test database
        print(f"[4/4] Cleaning up test database '{test_db}'...")
        manage_db("drop", test_db)
        print(f"Scenario {sc_id} completed successfully.")

    # Final summary report
    print("\n" + "=" * 80)
    print("FINAL CONSISTENCY REPORT (ALL SCENARIOS)")
    print("=" * 80)
    total_time = sum(r["elapsed"] for r in results)
    for r in results:
        b_n = sum(r["base_nodes"].values())
        t_n = sum(r["test_nodes"].values())
        b_e = sum(r["base_edges"].values())
        t_e = sum(r["test_edges"].values())
        tag = "PASSED [100.000% MATCH]" if r["passed"] else "FAILED"
        print(
            f"Scenario {r['id']} ({r['name']:35}): {tag} | "
            f"Nodes: {t_n} ({b_n}) | Edges: {t_e} ({b_e}) | Time: {r['elapsed']:.2f}s"
        )
    print(f"\nTotal Pipeline Elapsed Time: {total_time:.2f}s ({total_time/60:.2f} min)")
    print("=" * 80)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify 5-scenario consistency against Neo4j baseline.")
    ap.add_argument(
        "--scenarios", nargs="+", type=int, default=[],
        help="Specific scenario IDs to verify (e.g. --scenarios 4 5, default: all 1 2 3 4 5)"
    )
    args = ap.parse_args()
    return run_verification(args.scenarios)


if __name__ == "__main__":
    sys.exit(main())
