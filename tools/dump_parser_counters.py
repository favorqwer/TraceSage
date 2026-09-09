#!/usr/bin/env python3
"""Dev tool: dump every observable parser counter for a dry-run parse, so that
performance refactors can prove behavioral equivalence (counts must be
byte-identical before vs after; only elapsed time may differ).

Usage:
    python tools/dump_parser_counters.py <file.jsonl> -o out.json
    python tools/dump_parser_counters.py <file.jsonl> -o out.json --baseline pre.json

Compares: returned stats dict (minus elapsed), per-reason skip counts, all
pairing counters, fd-table audit stats, and registry audit counters.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sysdig-parser"))

os.environ.setdefault("PROGQL_SYSDIG_PROGRESS_INTERVAL_SECONDS", "3600")

from parsers import SysdigLogParser  # noqa: E402


def collect(log_file: str) -> dict:
    started = time.perf_counter()
    parser = SysdigLogParser(log_file, "neo4j", 1, dry_run=True)
    stats = parser.parse_entry()
    elapsed = time.perf_counter() - started

    pairing = parser._pairing
    skip = parser._skip_logger
    registry = parser._registry

    return {
        "file": str(log_file),
        "file_size": os.path.getsize(log_file),
        "wall_seconds": round(elapsed, 3),
        "mb_per_sec": round(os.path.getsize(log_file) / 1048576 / max(elapsed, 1e-9), 2),
        "stats": stats,
        "skip_reason_counts": dict(skip._reason_counts),
        "pairing": {
            "start_records": pairing._pairing_start_records,
            "end_records": pairing._pairing_end_records,
            "exact_matches": pairing._pairing_exact_matches,
            "fallback_matched": pairing._pairing_fallback_matched,
            "fallback_rejected": pairing._pairing_fallback_rejected,
            "fallback_no_partner": pairing._pairing_fallback_no_partner,
            "dummy_starts": pairing._pairing_dummy_starts,
            "start_key_collisions": pairing._pairing_start_key_collisions,
            "ambiguous_fallbacks": pairing._pairing_ambiguous_fallbacks,
            "dummy_by_event": dict(pairing._pairing_dummy_by_event),
        },
        "fd_table": registry.fd_table_stats(),
        "registry_audit": {
            "incomplete_network": registry.incomplete_network_count,
            "no_object": registry.no_object_count,
            "protocol_conflicts": registry.network_protocol_conflicts,
        },
    }


def diff(a: dict, b: dict, path: str = "") -> list[str]:
    """Deep diff ignoring wall_seconds/mb_per_sec (timing is allowed to drift)."""
    out: list[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key in ("wall_seconds", "mb_per_sec", "file", "file_size", "elapsed_seconds"):
                continue
            out.extend(diff(a.get(key), b.get(key), f"{path}.{key}"))
    elif a != b:
        out.append(f"{path}: baseline={a!r} current={b!r}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file", help="JSONL input (parsed in dry-run mode)")
    ap.add_argument("-o", "--out", required=True, help="output JSON path")
    ap.add_argument("--baseline", help="previous dump to compare against")
    args = ap.parse_args()

    result = collect(args.file)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"dumped -> {out_path}")
    print(
        f"throughput: {result['mb_per_sec']} MB/s  "
        f"events={result['stats']['processed_event_lines']}  "
        f"skipped={result['stats']['skipped_lines']}"
    )

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        differences = diff(baseline, result)
        if differences:
            print(f"\nDIFF vs {args.baseline}: {len(differences)} difference(s)")
            for line in differences[:50]:
                print("  " + line)
            return 1
        print(f"\nEQUIVALENT: all counters identical to {args.baseline}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
