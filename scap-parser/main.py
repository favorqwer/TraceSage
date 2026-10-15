"""SCAP Streaming Provenance Importer.

Directly parses .scap binary capture files into Neo4j provenance graphs
via streaming execution pipelines (SSH, Local Linux, Docker, WSL2)
without creating intermediate .jsonl physical files.

Usage:
    # 探测当前可用后端状态
    python scap-parser/main.py --detect-backends

    # 单场景流式导入（自动探测最佳后端，默认 SSH 直连受害者机）
    python scap-parser/main.py --scap attack/data/5/capture.scap --scenario 5_Exposed_Service_Pivot

    # 显式指定后端为 ssh
    python scap-parser/main.py --scap attack/data/5/capture.scap --backend ssh --neo4j-database attack-5-exposed-service-pivot

    # 试跑模式（只解析不写库）
    python scap-parser/main.py --scap attack/data/5/capture.scap --dry-run --max-events 10000

    # 批量导入全部场景
    python scap-parser/main.py --scap-dir attack/data --all
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from parsers import SysdigLogParser, load_dotenv
from sources import create_scap_source, detect_available_backends

DEFAULT_DB_PREFIX = "attack-"
DEFAULT_SSH_HOST = "100.86.108.4"
DEFAULT_SSH_USER = "ubuntu"


def scenario_database_name(prefix: str, scenario: str) -> str:
    """Normalize scenario name to Neo4j database name (lowercase, _ -> -)."""
    return (prefix + scenario).lower().replace("_", "-")


def resolve_neo4j_database(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    load_dotenv()
    return os.environ.get("NEO4J_DATABASE", "neo4j")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python scap-parser/main.py",
        description="Direct SCAP -> Neo4j provenance graph streaming importer.",
    )
    ap.add_argument(
        "--scap", metavar="FILE", default=None,
        help="Path to a single .scap binary capture file",
    )
    ap.add_argument(
        "--scap-dir", metavar="DIR", default=None,
        help="Directory containing scenario folders with capture.scap (for batch import)",
    )
    ap.add_argument(
        "--all", action="store_true",
        help="Batch import switch, must be used with --scap-dir",
    )
    ap.add_argument(
        "--scenario", metavar="NAME", default=None,
        help="Scenario identifier name (e.g. 5_Exposed_Service_Pivot); auto-derives DB name",
    )
    ap.add_argument(
        "--backend", choices=["auto", "ssh", "local", "docker", "wsl"], default="auto",
        help="Streaming execution backend (default: auto)",
    )
    ap.add_argument(
        "--ssh-host", default=DEFAULT_SSH_HOST,
        help=f"Target SSH host for remote backend (default: {DEFAULT_SSH_HOST})",
    )
    ap.add_argument(
        "--ssh-user", default=DEFAULT_SSH_USER,
        help=f"Target SSH user for remote backend (default: {DEFAULT_SSH_USER})",
    )
    ap.add_argument(
        "--docker-image", default="sysdig/sysdig:latest",
        help="Docker image to use for docker backend (default: sysdig/sysdig:latest)",
    )
    ap.add_argument(
        "--wsl-distro", default=None,
        help="WSL2 distribution name to use (default: default WSL distribution)",
    )
    ap.add_argument(
        "--neo4j-database", metavar="NAME", default=None,
        help="Target Neo4j database name",
    )
    ap.add_argument(
        "--neo4j-database-prefix", metavar="PREFIX", default=DEFAULT_DB_PREFIX,
        help=f"Prefix for auto-derived database name (default: {DEFAULT_DB_PREFIX})",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Parse and validate without committing transactions to Neo4j",
    )
    ap.add_argument(
        "--max-events", type=int, default=None,
        help="Limit number of events parsed from SCAP stream (for debugging)",
    )
    ap.add_argument(
        "--detect-backends", action="store_true",
        help="Probe and print available backends on current system, then exit",
    )
    return ap


def run_single(
    scap_file: Path,
    scenario_name: str,
    neo4j_database: str,
    backend: str,
    args: argparse.Namespace,
) -> int:
    """Stream-import a single .scap file into specified Neo4j database."""
    print(f"\n{'='*20} Scenario: {scenario_name} -> DB: {neo4j_database} {'='*20}")
    print(f"Target SCAP: {scap_file}")

    source = create_scap_source(
        scap_path=str(scap_file),
        backend=backend,
        max_events=args.max_events,
        ssh_host=args.ssh_host,
        ssh_user=args.ssh_user,
        wsl_distribution=args.wsl_distro,
        docker_image=args.docker_image,
    )

    parser = SysdigLogParser(
        log_file=source,
        db_str="neo4j",
        start_event_id=1,
        dry_run=args.dry_run,
        neo4j_database=neo4j_database,
        scenario_name=scenario_name,
    )

    t0 = time.time()
    try:
        parser.parse_entry()
    except Exception as e:
        print(f"Error: SCAP streaming import failed: {e}", file=sys.stderr)
        return 1
    finally:
        source.close()

    elapsed = time.time() - t0
    print(f"Finished scenario {scenario_name} in {elapsed:.2f}s\n")
    return 0


def run_batch(scap_dir: Path, prefix: str, backend: str, args: argparse.Namespace) -> int:
    """Find and batch import all capture.scap files in directory tree."""
    scap_files = sorted(scap_dir.glob("**/capture.scap"), key=lambda p: str(p))
    if not scap_files:
        scap_files = sorted(scap_dir.glob("*.scap"), key=lambda p: str(p))

    if not scap_files:
        print(f"Error: no .scap files found under {scap_dir}", file=sys.stderr)
        return 1

    print(f"Batch import: found {len(scap_files)} SCAP file(s) under {scap_dir}")
    for idx, f in enumerate(scap_files, 1):
        # Scenario name: parent folder name if file is capture.scap, else stem
        scenario = f.parent.name if f.name == "capture.scap" else f.stem
        db_name = scenario_database_name(prefix, scenario)
        print(f"  [{idx}] {f} -> {db_name}")

    failures = []
    for idx, f in enumerate(scap_files, 1):
        scenario = f.parent.name if f.name == "capture.scap" else f.stem
        db_name = scenario_database_name(prefix, scenario)
        ret = run_single(f, scenario, db_name, backend, args)
        if ret != 0:
            failures.append(scenario)
            print(f"Batch fail-fast: aborted at {scenario}", file=sys.stderr)
            break

    if failures:
        print(f"\nBatch import encountered failures: {failures}", file=sys.stderr)
        return 1

    print("\nBatch SCAP import completed successfully.")
    return 0


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.detect_backends:
        print("[SCAP Parser] Probing system execution backends...")
        res = detect_available_backends(ssh_host=args.ssh_host, ssh_user=args.ssh_user)
        for b, avail in res.items():
            status = "AVAILABLE" if avail else "NOT AVAILABLE"
            print(f"  - {b:8}: {status}")
        return 0

    if args.all and args.scap_dir:
        scap_dir = Path(args.scap_dir).resolve()
        if not scap_dir.is_dir():
            print(f"Error: --scap-dir '{args.scap_dir}' is not a directory", file=sys.stderr)
            return 2
        return run_batch(scap_dir, args.neo4j_database_prefix, args.backend, args)

    if args.scap:
        scap_file = Path(args.scap).resolve()
        scenario = args.scenario
        if not scenario:
            scenario = scap_file.parent.name if scap_file.name == "capture.scap" else scap_file.stem
        db_name = args.neo4j_database or scenario_database_name(args.neo4j_database_prefix, scenario)
        return run_single(scap_file, scenario, db_name, args.backend, args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
