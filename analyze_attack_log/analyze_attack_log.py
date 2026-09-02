#!/usr/bin/env python3
"""流式统计 sysdig JSONL 日志中的 26 个字段（14 个原始字段 + 12 个派生字段）。

用法:
    python analyze_attack_log.py [输入文件] [-n 记录数] [-w 进程数]

参数:
    input              输入 JSONL 文件路径，默认 attack.jsonl
    -n N               最多统计 N 条有效 JSON 记录；不指定则统计整个文件
                       指定后自动使用单进程
    -w, --workers N    并行进程数，0=自动（默认，最多 8 个）
                       指定 -n 时自动单进程；xxhash 不可用时也退回单进程

示例:
    python analyze_attack_log/analyze_attack_log.py analyze_attack_log/attack.jsonl               # 统计整个文件，自动并行
    python analyze_attack_log/analyze_attack_log.py analyze_attack_log/attack.jsonl -n 10000      # 只统计前 10000 条
    python analyze_attack_log/analyze_attack_log.py analyze_attack_log/attack.jsonl -w 4          # 用 4 个进程并行

统计字段:
    原始字段 (14): evt.num, evt.rawtime, proc.pid, thread.tid, proc.ppid,
                  proc.exepath, proc.name, proc.args, proc.cwd, fd.l4proto,
                  evt.dir, evt.type, evt.args, evt.latency
    派生字段 (12): proc.cmdline, proc.exeline, fd.num, fd.type, fd.name,
                  fd.lip, fd.lport, fd.rip, fd.rport, evt.res, evt.failed, evt.arg.filename

输出:
    - 终端打印统计摘要（各字段的 present/missing/unique/avg/Top 值）
    - 同时写入 {输入文件名}.stats.txt（如 attack.stats.txt）
    - 全局汇总：失败事件数、事件类型分布、进程名分布、fd 类型分布
"""


from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

try:
    import orjson  # type: ignore
except ImportError:  # 标准库回退，脚本仍可直接运行
    orjson = None

try:
    import xxhash  # type: ignore
except ImportError:  # 多进程时会自动退回单进程，避免 hash seed 不一致
    xxhash = None


RAW_FIELDS = [
    "evt.num", "evt.rawtime", "proc.pid", "thread.tid", "proc.ppid",
    "proc.exepath", "proc.name", "proc.args", "proc.cwd", "fd.l4proto",
    "evt.dir", "evt.type", "evt.args", "evt.latency",
]
DERIVED_FIELDS = [
    "proc.cmdline", "proc.exeline", "fd.num", "fd.type", "fd.name",
    "fd.lip", "fd.lport", "fd.rip", "fd.rport", "evt.res", "evt.failed", "evt.arg.filename",
]
ALL_FIELDS = RAW_FIELDS + DERIVED_FIELDS
DEFAULT_TOP_N = 10
FD_FIELDS = ("fd.num", "fd.type", "fd.name", "fd.lip", "fd.lport", "fd.rip", "fd.rport")
NUMERIC_FIELDS = {
    "evt.num", "evt.rawtime", "proc.pid", "thread.tid", "proc.ppid",
    "evt.latency", "fd.num", "fd.lport", "fd.rport", "evt.res",
}

FD_RE = re.compile(r"\bfd=(\d+)")
RES_RE = re.compile(r"\bres=([^\s]+)")
FILENAME_RE = re.compile(r"(?:^|\s)filename=")
TYPE_RE = re.compile(r"^<([^>]+)>")
INT_PREFIX_RE = re.compile(r"^[+-]?\d+")
ERRNO_RE = re.compile(r"^E[A-Z0-9_]+(?:\b|\))")


def _balanced_parenthesized(text: str, start: int) -> Tuple[str, int]:
    """返回从 start='(' 开始的内容和结束位置，处理名称中的嵌套括号。"""
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:index], index + 1
    return text[start + 1:], len(text)


def parse_fd_values(args: str) -> Tuple[Any, ...]:
    empty = (None, None, None, None, None, None, None)
    if not args or "fd=" not in args:
        return empty
    match = FD_RE.search(args or "")
    if not match:
        return empty

    fd_num = int(match.group(1))
    pos = match.end()
    if pos >= len(args) or args[pos] != "(":
        return (fd_num, None, None, None, None, None, None)

    name, _ = _balanced_parenthesized(args, pos)
    type_match = TYPE_RE.match(name)
    if type_match:
        # 保留 sysdig 原始标记（例如 <f>、<4t>），便于和原日志直接对照。
        fd_type = type_match.group(0)
        fd_name = name[type_match.end():].strip()
    else:
        fd_type = None
        fd_name = name.strip()

    fd_lip = fd_lport = fd_rip = fd_rport = None
    fd_name_for_parse = fd_name or ""
    if "->" in fd_name_for_parse:
        local, remote = (part.strip() for part in fd_name_for_parse.split("->", 1))
        fd_lip, fd_lport = parse_endpoint(local)
        fd_rip, fd_rport = parse_endpoint(remote)
    return fd_num, fd_type, fd_name, fd_lip, fd_lport, fd_rip, fd_rport


def parse_fd_args(args: str) -> Dict[str, Any]:
    return dict(zip(FD_FIELDS, parse_fd_values(args)))


def parse_endpoint(endpoint: str) -> Tuple[Optional[str], Optional[int]]:
    """解析 IPv4/IPv6/主机名端点；没有端口时保留完整地址。"""
    endpoint = endpoint.strip()
    if not endpoint:
        return None, None
    if endpoint.startswith("[") and "]" in endpoint:
        close = endpoint.find("]")
        address = endpoint[1:close]
        suffix = endpoint[close + 1:]
        if suffix.startswith(":") and suffix[1:].isdigit():
            return address, int(suffix[1:])
        return address, None
    if ":" in endpoint:
        address, port = endpoint.rsplit(":", 1)
        if port.isdigit():
            return address, int(port)
    return endpoint, None


def parse_res(args: str) -> Tuple[Any, bool]:
    if not args or "res=" not in args:
        return None, False
    match = RES_RE.search(args or "")
    if not match:
        return None, False
    token = match.group(1)
    number = INT_PREFIX_RE.match(token)
    if number:
        value: Any = int(number.group(0))
        return value, value < 0
    # sysdig may render errno names such as EAGAIN; keep the original token.
    return token, bool(ERRNO_RE.match(token))


def parse_filename(args: str) -> Optional[str]:
    """从 evt.args 提取 filename= 的值；支持引号和括号包裹的值。"""
    if not args or "filename=" not in args:
        return None
    match = FILENAME_RE.search(args)
    if not match:
        return None
    start = match.end()
    if start >= len(args):
        return None
    first = args[start]
    if first in ("'", '"'):
        end = args.find(first, start + 1)
        value = args[start + 1:] if end < 0 else args[start + 1:end]
    elif first == "(":
        value, _ = _balanced_parenthesized(args, start)
    else:
        end = start
        while end < len(args) and not args[end].isspace():
            end += 1
        value = args[start:end]
    value = value.strip()
    return value or None


def restore_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    values = {field: event.get(field) for field in RAW_FIELDS}
    name = event.get("proc.name") or ""
    args = event.get("proc.args") or ""
    exepath = event.get("proc.exepath") or ""
    values["proc.cmdline"] = f"{name}{args}"
    values["proc.exeline"] = f"{exepath}{args}"
    evt_args = event.get("evt.args") or ""
    values.update(parse_fd_args(evt_args))
    values["evt.res"], values["evt.failed"] = parse_res(evt_args)
    values["evt.arg.filename"] = parse_filename(evt_args)
    return values


def restore_values(event: Dict[str, Any]) -> list[Any]:
    """统计专用的定长列表路径，避免每条记录创建派生字段字典。"""
    raw_values = [event.get(field) for field in RAW_FIELDS]
    name = event.get("proc.name") or ""
    args = event.get("proc.args") or ""
    exepath = event.get("proc.exepath") or ""
    evt_args = event.get("evt.args") or ""
    fd_values = parse_fd_values(evt_args)
    evt_res, evt_failed = parse_res(evt_args)
    filename = parse_filename(evt_args)
    return raw_values + [f"{name}{args}", f"{exepath}{args}", *fd_values, evt_res, evt_failed, filename]


class HyperLogLog:
    """小型近似基数计数器，固定使用 64 个寄存器。"""

    def __init__(self, registers: int = 64) -> None:
        self.registers = registers
        self.bits = int(math.log2(registers))
        self.data = [0] * registers

    def add(self, value: str) -> None:
        # xxhash 跨进程稳定，保证分块合并后的近似唯一值可比较。
        h = (
            xxhash.xxh64(value.encode("utf-8", "surrogatepass")).intdigest()
            if xxhash is not None
            else hash(value)
        ) & ((1 << 64) - 1)
        index = h & (self.registers - 1)
        remaining = h >> self.bits
        remaining_bits = 64 - self.bits
        rank = (remaining_bits - remaining.bit_length() + 1) if remaining else remaining_bits + 1
        self.data[index] = max(self.data[index], rank)

    def estimate(self) -> int:
        m = self.registers
        alpha = 0.709  # m=64 的经典修正系数
        harmonic = sum(2.0 ** (-register) for register in self.data)
        estimate = alpha * m * m / harmonic if harmonic else 0.0
        zeros = self.data.count(0)
        if estimate <= 2.5 * m and zeros:
            estimate = m * math.log(m / zeros)
        return max(0, int(round(estimate)))


class FieldStats:
    def __init__(self, top_n: int, numeric_enabled: bool) -> None:
        self.total = 0
        self.present = 0
        self.top_n = top_n
        self.numeric_enabled = numeric_enabled
        self.top = Counter()
        self.hll = HyperLogLog()
        self.numeric_count = 0
        self.numeric_sum = 0.0
        self.minimum: Optional[float] = None
        self.maximum: Optional[float] = None

    @staticmethod
    def missing(value: Any) -> bool:
        return value is None or value == ""

    def update(self, value: Any) -> None:
        self.total += 1
        if value is None or value == "":
            return
        self.present += 1
        key = str(value)
        top = self.top
        top[key] = top.get(key, 0) + 1
        # 高基数字段（如 evt.args）不必每条记录都排序裁剪，降低热点开销。
        if len(top) > 4096:
            self.top = Counter(dict(top.most_common(1024)))
        self.hll.add(key)
        if not self.numeric_enabled or isinstance(value, bool):
            return
        numeric = float(value) if isinstance(value, (int, float)) else None
        if numeric is not None and math.isfinite(numeric):
            self.numeric_count += 1
            self.numeric_sum += numeric
            self.minimum = numeric if self.minimum is None else min(self.minimum, numeric)
            self.maximum = numeric if self.maximum is None else max(self.maximum, numeric)

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "count": self.total,
            "present": self.present,
            "missing": self.total - self.present,
            "missing_rate": ((self.total - self.present) / self.total) if self.total else 0.0,
            "unique": self.hll.estimate(),
            "unique_mode": "approximate",
            "top": [{"value": value, "count": count} for value, count in self.top.most_common(self.top_n)],
            "min": self.minimum,
            "max": self.maximum,
            "avg": (self.numeric_sum / self.numeric_count) if self.numeric_count else None,
        }
        return result


def update_stats_batch(stats_list: list[FieldStats], values: list[Any]) -> None:
    """一次性更新一条记录的全部字段，避免逐字段方法调用。"""
    for stat, value in zip(stats_list, values):
        stat.total += 1
        if value is None or value == "":
            continue
        stat.present += 1
        key = str(value)
        top = stat.top
        top[key] = top.get(key, 0) + 1
        if len(top) > 4096:
            stat.top = Counter(dict(top.most_common(1024)))
        stat.hll.add(key)
        if not stat.numeric_enabled or isinstance(value, bool):
            continue
        numeric = float(value) if isinstance(value, (int, float)) else None
        if numeric is not None and math.isfinite(numeric):
            stat.numeric_count += 1
            stat.numeric_sum += numeric
            stat.minimum = numeric if stat.minimum is None else min(stat.minimum, numeric)
            stat.maximum = numeric if stat.maximum is None else max(stat.maximum, numeric)


def iter_events_range(
    path: Path,
    start: int = 0,
    end: Optional[int] = None,
) -> Iterable[Tuple[int, Optional[Dict[str, Any]], Optional[str]]]:
    """按字节区间逐行读取；非首块会丢弃开头残缺行，避免重复统计。"""
    with path.open("rb", buffering=4 * 1024 * 1024) as handle:
        if start:
            # 只有落在一行中间时才丢弃首行；若恰好位于换行后的行首，不能跳过整行。
            handle.seek(start - 1)
            previous = handle.read(1)
            handle.seek(start)
            if previous not in (b"\n", b"\r"):
                handle.readline()
        line_number = 0
        while True:
            if end is not None and handle.tell() >= end:
                break
            line = handle.readline()
            if not line:
                break
            line_number += 1
            try:
                if orjson is not None:
                    event = orjson.loads(line)
                else:
                    event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("JSON 根节点不是对象")
                yield line_number, event, None
            except (ValueError, TypeError, UnicodeDecodeError) as exc:
                yield line_number, None, str(exc)


def iter_events(path: Path) -> Iterable[Tuple[int, Optional[Dict[str, Any]], Optional[str]]]:
    yield from iter_events_range(path)


def _new_stats(top_n: int) -> Tuple[Dict[str, FieldStats], list[FieldStats]]:
    stats = {field: FieldStats(top_n, field in NUMERIC_FIELDS) for field in ALL_FIELDS}
    return stats, [stats[field] for field in ALL_FIELDS]


def _analyze_range(
    path: Path,
    start: int,
    end: Optional[int],
    top_n: int,
    max_records: Optional[int] = None,
) -> Dict[str, Any]:
    stats, stats_list = _new_stats(top_n)
    processed = invalid = restore_errors = failed_events = 0
    event_types = Counter()
    process_names = Counter()
    fd_types = Counter()

    stopped_early = False
    for _, event, error in iter_events_range(path, start, end):
        if error is not None:
            invalid += 1
            continue
        processed += 1
        try:
            values = restore_values(event or {})
            update_stats_batch(stats_list, values)
            if values[24] is True:
                failed_events += 1
            evt_type = values[11]
            if evt_type not in (None, ""):
                event_types[str(evt_type)] += 1
            proc_name = values[6]
            if proc_name not in (None, ""):
                process_names[str(proc_name)] += 1
            fd_type = values[17]
            if fd_type not in (None, ""):
                fd_types[str(fd_type)] += 1
        except Exception:
            restore_errors += 1
        if max_records is not None and processed >= max_records:
            stopped_early = True
            break
    return {
        "stats": stats,
        "processed": processed,
        "invalid": invalid,
        "restore_errors": restore_errors,
        "failed_events": failed_events,
        "event_types": event_types,
        "process_names": process_names,
        "fd_types": fd_types,
        "stopped_early": stopped_early,
    }


def _analyze_chunk_worker(arguments: Tuple[str, int, int, int]) -> Dict[str, Any]:
    path, start, end, top_n = arguments
    return _analyze_range(Path(path), start, end, top_n)


def _merge_chunks(destination: Dict[str, Any], source: Dict[str, Any]) -> None:
    destination["processed"] += source["processed"]
    destination["invalid"] += source["invalid"]
    destination["restore_errors"] += source["restore_errors"]
    destination["failed_events"] += source["failed_events"]
    destination["event_types"].update(source["event_types"])
    destination["process_names"].update(source["process_names"])
    destination["fd_types"].update(source["fd_types"])
    for field in ALL_FIELDS:
        dst = destination["stats"][field]
        src = source["stats"][field]
        dst.total += src.total
        dst.present += src.present
        dst.numeric_count += src.numeric_count
        dst.numeric_sum += src.numeric_sum
        dst.minimum = src.minimum if dst.minimum is None else dst.minimum if src.minimum is None else min(dst.minimum, src.minimum)
        dst.maximum = src.maximum if dst.maximum is None else dst.maximum if src.maximum is None else max(dst.maximum, src.maximum)
        dst.top.update(src.top)
        if len(dst.top) > 4096:
            dst.top = Counter(dict(dst.top.most_common(1024)))
        for index, value in enumerate(src.hll.data):
            if value > dst.hll.data[index]:
                dst.hll.data[index] = value


def _finalize_result(
    path: Path,
    chunk: Dict[str, Any],
    top_n: int,
    max_records: Optional[int],
    workers: int,
) -> Dict[str, Any]:
    def top(counter: Counter) -> list[Dict[str, Any]]:
        return [{"value": value, "count": count} for value, count in counter.most_common(top_n)]

    return {
        "meta": {
            "input": str(path),
            "processed_lines": chunk["processed"],
            "invalid_json_lines": chunk["invalid"],
            "restore_error_lines": chunk["restore_errors"],
            "top_n": top_n,
            "max_records": max_records,
            "stopped_early": chunk["stopped_early"],
            "workers": workers,
        },
        "global": {
            "failed_events": chunk["failed_events"],
            "event_types": top(chunk["event_types"]),
            "process_names": top(chunk["process_names"]),
            "fd_types": top(chunk["fd_types"]),
        },
        "fields": {field: chunk["stats"][field].as_dict() for field in ALL_FIELDS},
    }


def analyze(
    path: Path,
    top_n: int,
    max_records: Optional[int] = None,
    workers: int = 1,
) -> Dict[str, Any]:
    # 前 N 条必须保持文件顺序；没有稳定哈希时也不能安全合并 HLL。
    if max_records is not None or xxhash is None:
        workers = 1
    size = path.stat().st_size
    if workers <= 1 or size == 0:
        chunk = _analyze_range(path, 0, size, top_n, max_records)
        return _finalize_result(path, chunk, top_n, max_records, workers)

    ranges = []
    for index in range(workers):
        start = size * index // workers
        end = size * (index + 1) // workers
        if start < end:
            ranges.append((str(path), start, end, top_n))
    with concurrent.futures.ProcessPoolExecutor(max_workers=len(ranges)) as pool:
        chunks = list(pool.map(_analyze_chunk_worker, ranges))
    merged = chunks[0]
    for chunk in chunks[1:]:
        _merge_chunks(merged, chunk)
    return _finalize_result(path, merged, top_n, max_records, workers)


def format_summary(result: Dict[str, Any]) -> str:
    lines = []
    meta = result["meta"]
    global_stats = result["global"]
    lines.append(f"处理有效记录: {meta['processed_lines']:,}")
    lines.append(f"非法 JSON 行: {meta['invalid_json_lines']:,}，字段恢复异常: {meta['restore_error_lines']:,}")
    lines.append(f"失败事件: {global_stats['failed_events']:,}")
    lines.append(f"统计进程数: {meta['workers']}")
    if meta["max_records"] is not None:
        state = "已达到上限并停止" if meta["stopped_early"] else "未达到上限（文件已结束）"
        lines.append(f"记录上限: {meta['max_records']:,}，{state}")
    lines.append("")
    lines.append("字段统计（count=有效 JSON 记录数，present=非空值数）:")
    lines.append(f"{'字段':<16} {'present':>12} {'missing':>12} {'unique':>12} {'avg':>14}  Top 值")
    for field in ALL_FIELDS:
        item = result["fields"][field]
        top_text = ", ".join(f"{x['value']} ({x['count']})" for x in item["top"][:3])
        avg = "" if item["avg"] is None else f"{item['avg']:.3f}"
        lines.append(f"{field:<16} {item['present']:>12,} {item['missing']:>12,} {item['unique']:>12,} {avg:>14}  {top_text}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="流式统计 sysdig JSONL 日志中的 26 个字段")
    parser.add_argument("input", nargs="?", default="attack.jsonl", help="输入 JSONL 文件，默认 attack.jsonl")
    parser.add_argument(
        "-n", type=int,
        help="最多统计多少条有效 JSON 记录；不指定则统计整个文件",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=0,
        help="整文件统计使用的并行进程数，0=自动（默认最多 8 个）；指定 -n 时自动单进程",
    )
    args = parser.parse_args()
    if args.n is not None and args.n <= 0:
        parser.error("-n 必须大于 0")
    if args.workers < 0:
        parser.error("-w/--workers 不能小于 0")
    path = Path(args.input)
    if not path.is_file():
        print(f"输入文件不存在: {path}", file=sys.stderr)
        return 2
    workers = args.workers or min(8, max(1, os.cpu_count() or 1))
    result = analyze(path, DEFAULT_TOP_N, args.n, workers)
    summary = format_summary(result)
    print(summary)
    output = Path.cwd() / f"{path.stem}.stats.txt"
    output.write_text(summary + "\n", encoding="utf-8")
    print(f"\n统计结果已写入: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
