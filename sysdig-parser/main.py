"""Python port of the Java sysdig-parser.

Usage:
    # 单场景导入（旧位置参数用法，保持兼容；起始 event id 默认 1）
    python main.py <logFile> neo4j [startEventId] [--dry-run] [--neo4j-database NAME]

    # 单场景导入（显式输入文件）
    python main.py --input <logFile> [--dry-run] [--neo4j-database NAME]

    # 批量导入：--input-dir 下全部 *.jsonl 按文件名排序逐个导入；
    # 场景名取文件名 stem，每个场景写入独立数据库
    # <prefix><stem 小写，_ 归一化为 ->（如 tracesage-1-multi-stage-data-exfiltration）
    python main.py --input-dir <dir> --all [--dry-run] [--neo4j-database-prefix PREFIX]

Neo4j 数据库选择优先级：--neo4j-database > 环境/.env 的 NEO4J_DATABASE > 默认 neo4j。
Neo4j 库名只允许字母/数字/点/横线（不允许下划线，统一小写，见 Neo4j Operations
Manual "Naming rules for databases"），批量模式自动做 _ -> - 归一化。
每个场景使用独立数据库，event_id 从 1 开始且仅在该场景库内保证唯一。
本工具不创建数据库：目标数据库必须已存在（批量导入前先逐个 CREATE DATABASE；
多数据库需要 Neo4j Enterprise，Community 版只有默认 neo4j 库）。
批量导入默认 fail-fast：任一场景失败立即停止，不继续导入后续场景。
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from parsers import SysdigLogParser, load_dotenv

DEFAULT_DB_PREFIX = "tracesage-"


def scenario_database_name(prefix: str, scenario: str) -> str:
    """批量导入的场景库名：前缀 + 场景名，小写并把 `_` 归一化为 `-`。

    Neo4j 库名只允许字母/数字/点/横线且统一小写（Operations Manual
    "Naming rules for databases"），因此
    tracesage- + 1_Multi_Stage_Data_Exfiltration
      -> tracesage-1-multi-stage-data-exfiltration。
    """
    return (prefix + scenario).lower().replace("_", "-")


def is_supported_db_target(db_str: str) -> bool:
    # 精确匹配：startswith 会放过 neo4jxyz 之类的拼写错误，
    # 让错误漏到 parser 内部抛出裸 traceback。
    return db_str == "neo4j"


def resolve_neo4j_database(explicit: Optional[str]) -> str:
    """解析目标 Neo4j 数据库名。

    优先级：命令行显式指定 > 环境变量 / 根目录 .env 的 NEO4J_DATABASE >
    默认 neo4j（load_dotenv 用 setdefault，不会覆盖已有环境变量）。
    """
    if explicit:
        return explicit
    load_dotenv()
    return os.environ.get("NEO4J_DATABASE", "neo4j")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python sysdig-parser/main.py",
        description="Sysdig JSONL -> Neo4j provenance graph importer.",
    )
    # 旧位置参数用法（保持兼容）：<logFile> neo4j [startEventId]
    ap.add_argument(
        "log_file_pos", nargs="?", default=None,
        help="JSONL 日志文件（旧位置参数用法；与 --input / --input-dir 互斥）",
    )
    ap.add_argument(
        "db_pos", nargs="?", default=None,
        help="数据库后端，仅支持 neo4j（旧位置参数用法）",
    )
    ap.add_argument(
        "start_pos", nargs="?", type=int, default=None,
        help="起始 event id（默认 1）",
    )
    ap.add_argument(
        "--input", metavar="FILE", default=None,
        help="单场景导入的 JSONL 日志文件",
    )
    ap.add_argument(
        "--input-dir", metavar="DIR", default=None,
        help="批量导入：该目录下全部 *.jsonl（按文件名排序）",
    )
    ap.add_argument(
        "--all", action="store_true",
        help="批量导入开关，必须与 --input-dir 同时使用",
    )
    ap.add_argument(
        "--neo4j-database", metavar="NAME", default=None,
        help="单场景导入的目标 Neo4j 数据库（默认取 NEO4J_DATABASE，再默认 neo4j）",
    )
    ap.add_argument(
        "--neo4j-database-prefix", metavar="PREFIX", default=None,
        help=f"批量导入的数据库名前缀（默认 {DEFAULT_DB_PREFIX}），"
             "最终库名 = 前缀 + 文件名 stem（小写，_ 归一化为 -）",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="只解析不写库",
    )
    return ap


def run_single(
    log_file: Path,
    start_event_id: int,
    neo4j_database: str,
    dry_run: bool,
) -> int:
    """导入单个 JSONL 文件到指定 Neo4j 数据库。"""
    parser = SysdigLogParser(
        str(log_file), "neo4j", start_event_id,
        dry_run=dry_run,
        neo4j_database=neo4j_database,
    )
    try:
        parser.parse_entry()
    except Exception as e:
        print(f"Error: import failed: {e}", file=sys.stderr)
        return 1
    return 0


def run_batch(input_dir: Path, prefix: str, dry_run: bool) -> int:
    """批量导入目录下全部 *.jsonl：按文件名排序、每场景独立数据库、fail-fast。"""
    jsonl_files = sorted(input_dir.glob("*.jsonl"), key=lambda p: p.name)
    if not jsonl_files:
        print(f"Error: no *.jsonl files found in {input_dir}", file=sys.stderr)
        return 1

    print(f"Batch import: {len(jsonl_files)} scenario(s) from {input_dir}")
    for i, f in enumerate(jsonl_files, 1):
        print(f"  {i}. {f.name} -> {scenario_database_name(prefix, f.stem)}")
    if dry_run:
        print("Batch mode: DRY-RUN (no DB writes)")

    results: List[Dict] = []
    stopped_at: Optional[str] = None
    for scenario_file in jsonl_files:
        scenario = scenario_file.stem
        db_name = scenario_database_name(prefix, scenario)
        print(f"\n############### [{len(results) + 1}/{len(jsonl_files)}] "
              f"{scenario} -> {db_name} ###############")
        started = time.monotonic()
        try:
            parser = SysdigLogParser(
                str(scenario_file), "neo4j", 1,
                dry_run=dry_run,
                neo4j_database=db_name,
            )
            stats = parser.parse_entry()
        except Exception as e:
            elapsed = time.monotonic() - started
            results.append({
                "scenario": scenario, "db": db_name, "status": "FAILED",
                "error": str(e), "elapsed": elapsed,
            })
            print(f"\nError importing {scenario_file.name}: {e}", file=sys.stderr)
            stopped_at = scenario
            break  # fail-fast：不继续导入后续场景
        results.append({
            "scenario": scenario, "db": db_name, "status": "OK",
            "stats": stats, "elapsed": time.monotonic() - started,
        })

    _print_batch_summary(results, len(jsonl_files), stopped_at)
    all_ok = (
        all(r["status"] == "OK" for r in results)
        and len(results) == len(jsonl_files)
    )
    return 0 if all_ok else 1


def _print_batch_summary(
    results: List[Dict], total: int, stopped_at: Optional[str]
) -> None:
    print("\n################# Batch import summary #################")
    if stopped_at is not None:
        remaining = total - len(results)
        print(f"Stopped at '{stopped_at}' (fail-fast); {remaining} scenario(s) not attempted.")
    header = (
        f"{'scenario':<38} {'status':<7} {'events':>10} {'skipped':>8} "
        f"{'p/f/n':>15} {'p2p/p2f/f2p/p2n/n2p':>24} {'elapsed':>10}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        if r["status"] != "OK":
            print(f"{r['scenario']:<38} FAILED  ({r['error']})")
            continue
        s = r["stats"]
        v = s["vertices"]
        e = s["edges"]
        vtx = f"{v['process']}/{v['file']}/{v['network']}"
        edg = f"{e['p2p']}/{e['p2f']}/{e['f2p']}/{e['p2n']}/{e['n2p']}"
        print(
            f"{r['scenario']:<38} {'OK':<7} {s['processed_event_lines']:>10} "
            f"{s['skipped_lines']:>8} "
            f"{vtx:>15} "
            f"{edg:>24} "
            f"{r['elapsed']:>9.1f}s"
        )
    ok = sum(1 for r in results if r["status"] == "OK")
    print(f"\n{ok}/{total} scenario(s) imported successfully.")


def main() -> None:
    ap = _build_arg_parser()
    args = ap.parse_args()

    try:
        positional_used = any(
            v is not None for v in (args.log_file_pos, args.db_pos, args.start_pos)
        )
        batch_used = args.input_dir is not None or args.all

        if batch_used:
            _validate_batch_args(args, positional_used)
            input_dir = Path(args.input_dir)
            if not input_dir.is_dir():
                raise ValueError(f"Input directory not found: {input_dir}")
            prefix = args.neo4j_database_prefix or DEFAULT_DB_PREFIX
            sys.exit(run_batch(input_dir, prefix, args.dry_run))

        # --- 单场景模式 ---
        if args.input is not None:
            if positional_used:
                raise ValueError(
                    "--input cannot be combined with positional arguments; "
                    "startEventId is fixed to 1 in this mode"
                )
            log_file = Path(args.input)
            start_event_id = 1
        else:
            if args.log_file_pos is None:
                ap.print_usage(sys.stderr)
                sys.exit(1)
            if args.db_pos is None:
                raise ValueError(
                    "Missing database backend argument. "
                    "sysdig-parser supports: neo4j."
                )
            if not is_supported_db_target(args.db_pos):
                raise ValueError(
                    f"Unsupported database backend '{args.db_pos}'. "
                    "sysdig-parser supports: neo4j."
                )
            log_file = Path(args.log_file_pos)
            start_event_id = (
                args.start_pos if args.start_pos is not None else 1
            )

        if not log_file.is_file():
            raise ValueError(f"Log file not found: {log_file}")
        if args.neo4j_database is not None and not args.neo4j_database.strip():
            raise ValueError("--neo4j-database must not be empty")

        neo4j_database = resolve_neo4j_database(args.neo4j_database)
        sys.exit(run_single(log_file, start_event_id, neo4j_database, args.dry_run))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _validate_batch_args(args: argparse.Namespace, positional_used: bool) -> None:
    if args.input_dir is None:
        raise ValueError("--all must be combined with --input-dir <dir>")
    if not args.all:
        raise ValueError("--input-dir must be combined with --all")
    if positional_used or args.input is not None:
        raise ValueError(
            "--input-dir/--all cannot be combined with positional arguments or --input"
        )
    if args.neo4j_database is not None:
        raise ValueError(
            "Batch import does not support --neo4j-database; "
            "each scenario gets its own database via --neo4j-database-prefix"
        )


if __name__ == "__main__":
    main()
