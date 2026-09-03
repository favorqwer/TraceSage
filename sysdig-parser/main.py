"""
Python port of the Java sysdig-parser.

Usage:
    python main.py <logFile> postgres/<dbName> [hostId] [startUid] [startEventId]
"""

import sys
import os

from parsers.my_sysdig_log_parser import MySysdigLogParser


def print_usage() -> None:
    print(
        "Usage: python main.py <logFile> <postgres/<dbName>> "
        "[hostId] [startUid] [startEventId]",
        file=sys.stderr,
    )


def is_supported_db_target(db_str: str) -> bool:
    return db_str is not None and db_str.startswith("postgres/") and len(db_str) > len("postgres/")


def main() -> None:
    print("#################ParsersMain start....")

    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    log_file = sys.argv[1]
    db_str = sys.argv[2]
    host_id = int(sys.argv[3]) if len(sys.argv) >= 4 else -1
    start_uid = int(sys.argv[4]) if len(sys.argv) >= 5 else 1
    start_event_id = int(sys.argv[5]) if len(sys.argv) >= 6 else 1

    if not os.path.isfile(log_file):
        print(f"Log file not found: {log_file}", file=sys.stderr)
        sys.exit(1)

    if not is_supported_db_target(db_str):
        print(
            f"Unsupported database backend '{db_str}'. "
            "sysdig-parser only supports postgres/<dbName>.",
            file=sys.stderr,
        )
        print_usage()
        sys.exit(1)

    parser = MySysdigLogParser(log_file, db_str, host_id, start_uid, start_event_id)
    parser.parse_entry()


if __name__ == "__main__":
    main()
