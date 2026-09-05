#!/usr/bin/env python3
r"""Dev tool: sanity-check a sysdig JSONL export before importing it.

Background pitfall
-----------------
sysdig `-p` prints a line ONLY IF all fields in the format string are present,
unless the format string is prefixed with a bare `*`.  A `\*` inside bash single
quotes is TWO characters, so the prefix never activates and every event missing
e.g. `%fd.l4proto` (all non-fd events: futex/switch/poll/execve/rename/...) gets
dropped.  Result: hundreds of thousands of events silently missing.

Most exports of the multi-stage attack (capture window
1768985381.9..1768985550.8) contain 9.3M+ records covering 126 event types
including futex/switch/poll/execve/rename.  A "filtered" export instead has
~3.06M records and only the ~28 event types that carry an fd (no futex, no
execve, no rename).

This tool reads the whole file once, counts records and event types, and fails
the check when the fingerprint of a filtered export is detected.

Usage:
    python check_sysdig_export.py <file.jsonl>
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

try:
    import orjson  # type: ignore
except ImportError:  # pragma: no cover
    orjson = None

# Event types that ONLY exist on events without an fd.  Their total absence from
# an export is the signature of a missing `*` prefix (or of an fd-filter).
#
# 注意：只保留核实过从不携带 `fd=` 的事件类型。connect/bind/listen/shutdown/
# getsockopt/setsockopt/mmap/getdents/getdents64 在真实导出中带 `fd=`
# （2026-09 用 attack.jsonl 逐类型核实），会出现在 fd 过滤型导出里，
# 不能作为签名，否则会削弱本检查的判别力（重名/目录 fd 系 dirfd=<d>）。
_FD_LESS_TYPES = {
    "futex",
    "switch",
    "poll",
    "sched_yield",
    "epoll_wait",
    "epoll_ctl",
    "setitimer",
    "execve",
    "execveat",
    "rename",
    "renameat",
    "renameat2",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "mprotect",
    "getpid",
    "gettid",
    "madvise",
    "socketpair",
    "stat",
    "lstat",
    "fstatat",
    "statx",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "newfstatat",
    "prctl",
    "getuid",
    "getgid",
    "times",
    "unlink",
    "unlinkat",
}


def _loads(line: str):
    if orjson is not None:
        return orjson.loads(line)
    return json.loads(line)


def check(path: str) -> int:
    total = 0
    invalid = 0
    types: Counter = Counter()
    fd_proto_missing = 0
    first_ts = None
    last_ts = None

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = _loads(line)
            except Exception:
                invalid += 1
                continue
            if not isinstance(obj, dict):
                invalid += 1
                continue
            total += 1
            evt_type = obj.get("evt.type")
            if evt_type is not None:
                types[evt_type] += 1
            if "fd.l4proto" not in obj:
                fd_proto_missing += 1
            ts = obj.get("evt.rawtime")
            if ts is not None:
                ts = int(ts)
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)

    print(f"file            : {path}")
    print(f"records         : {total:,}")
    print(f"invalid lines   : {invalid:,}")
    print(f"event types     : {len(types)}")
    print(f"fd.l4proto miss : {fd_proto_missing:,} ({100.0*fd_proto_missing/max(total,1):.1f}%)")
    if first_ts is not None and last_ts is not None:
        print(
            f"time window     : {first_ts} .. {last_ts} "
            f"({(last_ts-first_ts)/1e9:.1f}s)"
        )
    else:
        print("time window     : n/a (no parsable evt.rawtime)")

    problems = []

    # 1. Signature of a filtered (no-`*`) export: zero fd-less events.
    present_fd_less = sorted(t for t in _FD_LESS_TYPES if t in types)
    if not present_fd_less:
        problems.append(
            "NO fd-less event types found (futex/switch/poll/execve/rename/...). "
            "This is the signature of a missing `*` prefix in -p: the export "
            "kept only events that carry an fd. Re-export with -p '*%...' "
            "(bare *, no backslash)."
        )
    else:
        print(f"fd-less types   : {len(present_fd_less)} present (e.g. {', '.join(present_fd_less[:8])})")

    # 2. Extremely small total relative to the known capture (~9.3M records).
    if total < 5_000_000 and not present_fd_less:
        problems.append(
            f"Suspiciously small export ({total:,} records) and no fd-less types: "
            "likely filtered."
        )

    # 3. Event types that appear suspiciously missing.
    absent_common = [t for t in ("futex", "recvmsg", "writev", "read", "write", "ioctl")
                     if t not in types]
    if absent_common:
        problems.append(
            "Very common event types missing from export: "
            + ", ".join(absent_common)
        )

    if problems:
        print("\nFAIL:")
        for p in problems:
            print("  - " + p)
        return 1

    print("\nRESULT: OK - export looks complete (fd-less events present, "
          "reasonable record count)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file", help="sysdig JSONL export to check")
    args = ap.parse_args()

    if not Path(args.file).is_file():
        print(f"file not found: {args.file}", file=sys.stderr)
        return 2
    return check(args.file)


if __name__ == "__main__":
    sys.exit(main())
