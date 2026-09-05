"""Sysdig JSONL record decoding, canonical-field validation, and timestamp
parsing — the entry layer between raw log lines and the pipeline."""

import json as _json_stdlib
from typing import Dict, Optional

from .fields import extract_file_and_socket, extract_size

try:
    import orjson as _orjson  # type: ignore
except ImportError:  # 标准库回退
    _orjson = None


# JSONL（sysdig -j 导出）中一条事件记录必须具备的原始字段。
# 即 analyze_attack_log.RAW_FIELDS 的 12 项去掉 proc.args 和 fd.l4proto 后的 10 项；
# 缺失任一字段视为无效行（跳过并计数）。
# proc.args 和 fd.l4proto 作为可选字段解析（见 parse_jsonl_entry 的 proc_args / l4proto），
# 不加入必填键：缺少这两个键的旧日志行仍可解析，不会被跳过。
_REQUIRED_JSONL_KEYS = (
    "evt.num",
    "evt.rawtime",
    "evt.dir",
    "evt.type",
    "evt.args",
    "evt.latency",
    "proc.pid",
    "proc.name",
    "proc.exepath",
    "proc.cwd",
)


def _loads_json_line(line: str):
    if _orjson is not None:
        return _orjson.loads(line)
    return _json_stdlib.loads(line)


def _json_str(value) -> str:
    """JSON 字段值 -> 字符串；null -> ""（绝不产生 'None' 字面量）。
    非字符串标量（如 int 型 proc.pid）按 str() 转换。"""
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def parse_jsonl_entry(entry: str) -> Optional[Dict[str, str]]:
    """Parse a single Sysdig JSONL record (sysdig -j) into a canonical field
    map consumed by the rest of the parsing pipeline.

    Field mapping (JSONL key -> canonical key):
        evt.num      -> eventno (str)
        evt.rawtime  -> timestamp ("sec.nsec", int ns converted losslessly)
        (absent)     -> cpu = "0" (JSONL 导出无此列，占位)
        proc.name    -> process
        proc.pid     -> pid
        evt.dir      -> direction ("<" / ">")
        evt.type     -> event
        proc.cwd     -> cwd
        evt.latency  -> latency
        proc.exepath -> exepath
        evt.args     -> args
        proc.args    -> proc_args (可选字段：进程命令行，缺失/空 -> "")
        fd.l4proto   -> l4proto   (可选字段：socket 四层协议，缺失/空 -> "")

    proc_args / l4proto 为可选映射（不加入 _REQUIRED_JSONL_KEYS），
    缺少这两个键的旧日志行仍可正常解析，不会被跳过。

    JSON null 一律映射为 ""（绝不产生 'None' 字面量）：proc.pid /
    proc.name 为 null（无进程上下文，如内核调度 switch 事件）的记录由
    validate_parsed_entry 以精确理由跳过；proc.cwd /
    proc.exepath / evt.args 为 null 时映射为 ""，经 _normalize_optional_text
    归一为 None（顶点不写该属性）。

    Returns None for malformed/incomplete records (caller counts as skipped).
    """
    try:
        obj = _loads_json_line(entry)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    for key in _REQUIRED_JSONL_KEYS:
        if key not in obj:
            return None
    try:
        rawtime = int(obj["evt.rawtime"])
        eventno = str(int(obj["evt.num"]))
        latency = str(int(obj["evt.latency"] or 0))
    except (TypeError, ValueError):
        return None
    direction = str(obj["evt.dir"])
    if direction not in (">", "<"):
        return None
    sec, nsec = divmod(rawtime, 1_000_000_000)
    return {
        "raw": entry,
        "eventno": eventno,
        "timestamp": f"{sec}.{nsec:09d}",
        "cpu": "0",
        "process": _json_str(obj["proc.name"]),
        "pid": _json_str(obj["proc.pid"]),
        "direction": direction,
        "event": _json_str(obj["evt.type"]),
        "cwd": _json_str(obj["proc.cwd"]),
        "latency": latency,
        "exepath": _json_str(obj["proc.exepath"]),
        "args": _json_str(obj["evt.args"]),
        "proc_args": _json_str(obj.get("proc.args")),
        "l4proto": _json_str(obj.get("fd.l4proto")),
    }


def parse_timestamp_ns(ts: str) -> int:
    """'sec.nanosec' timestamp string -> integer nanoseconds since epoch."""
    parts = ts.split(".")
    if len(parts) < 2:
        return int(parts[0]) * 1_000_000_000
    return int(parts[0]) * 1_000_000_000 + int(parts[1])


def validate_parsed_entry(record: Dict[str, str]) -> None:
    """Validate a canonical record; raise ValueError with the exact skip
    reason if it cannot produce graph elements.

    Also exercises the args extractors so malformed fd/socket fields fail
    here (and get counted as skipped) instead of deep in edge generation.
    """
    for field in ("eventno", "timestamp", "cpu", "process", "pid",
                  "direction", "event", "latency", "exepath", "args"):
        if field not in record:
            raise ValueError(f"Missing parsed field: {field}")

    int(record["eventno"])
    # Validate timestamp format
    ts = record["timestamp"]
    ts_parts = ts.split(".")
    if len(ts_parts) < 2:
        raise ValueError(f"Timestamp has no nanosecond part: {ts}")
    int(ts_parts[0])
    int(ts_parts[1])

    direction = record["direction"]
    if direction not in (">", "<"):
        raise ValueError(f"Unsupported syscall direction: {direction}")

    # 无进程上下文的记录（proc.pid/proc.name 为 JSON null，典型如内核调度
    # switch 事件）：无法归属到任何进程，永远不会产生边，只会堆积为永不
    # 配对的 pending。按精确理由跳过，保持跳过统计可审计。
    if not record["pid"] or not record["process"]:
        raise ValueError(
            "Record has no process context (proc.pid/proc.name is null)"
        )

    args = record["args"]
    extract_file_and_socket(args)
    extract_size(args)
