"""
Python port of the Java sysdig-parser.

Usage:
    python main.py <logFile> neo4j [startEventId] [--dry-run]
"""

import sys
import os
from typing import List, Tuple

from parsers import SysdigLogParser


def print_usage() -> None:
    print(
        "Usage: python main.py <logFile> neo4j [startEventId] [--dry-run]",
        file=sys.stderr,
    )


def is_supported_db_target(db_str: str) -> bool:
    # 精确匹配：startswith 会放过 neo4jxyz 之类的拼写错误，
    # 让错误漏到 parser 内部抛出裸 traceback。
    return db_str == "neo4j"


def _parse_optional_flags(argv: List[str]) -> Tuple[List[str], bool]:
    """Extract --dry-run flag; reject unknown options (typo protection).

    未知选项若被静默当作位置参数，会顺位挤占 <startEventId> 并在 int()
    处抛出裸 traceback，这里直接报错并提示用法。"""
    dry_run = False
    positional = []
    for arg in argv:
        if arg == "--dry-run":
            dry_run = True
        elif arg.startswith("-"):
            raise ValueError(f"Unknown option: {arg} (supported: --dry-run)")
        else:
            positional.append(arg)
    return positional, dry_run


def main() -> None:
    print("#################ParsersMain start....")

    try:
        args, dry_run = _parse_optional_flags(sys.argv[1:])
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print_usage()
        sys.exit(1)

    if len(args) < 2:
        print_usage()
        sys.exit(1)

    log_file = args[0]
    db_str = args[1]
    try:
        start_event_id = int(args[2]) if len(args) >= 3 else 1
    except ValueError:
        print(
            f"Invalid startEventId: {args[2]!r} (must be an integer)",
            file=sys.stderr,
        )
        print_usage()
        sys.exit(1)

    if not os.path.isfile(log_file):
        print(f"Log file not found: {log_file}", file=sys.stderr)
        sys.exit(1)

    if not is_supported_db_target(db_str):
        print(
            f"Unsupported database backend '{db_str}'. "
            "sysdig-parser supports: neo4j.",
            file=sys.stderr,
        )
        print_usage()
        sys.exit(1)

    parser = SysdigLogParser(
        log_file, db_str, start_event_id,
        dry_run=dry_run,
    )
    parser.parse_entry()


if __name__ == "__main__":
    main()
