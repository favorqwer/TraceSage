"""Sysdig JSONL record decoding, canonical-field validation, and timestamp
parsing — the entry layer between raw log lines and the pipeline."""

import json as _json_stdlib
from typing import Dict, Optional, Union

from .fields import extract_file_and_socket, extract_res, extract_size

try:
    import orjson as _orjson  # type: ignore
except ImportError:  # 标准库回退
    _orjson = None


# JSONL（sysdig -j 导出）中一条事件记录必须具备的原始字段，共 10 项：
# 事件 6 项（evt.num/rawtime/dir/type/args/latency）+ 进程 4 项（proc.pid/name/exepath/cwd）。
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
_REQUIRED_JSONL_KEY_SET = frozenset(_REQUIRED_JSONL_KEYS)


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


def parse_jsonl_entry(entry: Union[str, bytes]) -> Optional[Dict[str, str]]:
    """Parse a single Sysdig JSONL record (sysdig -j) into a canonical field
    map consumed by the rest of the parsing pipeline.

    ``entry`` 可为 str 或 bytes（主循环二进制读入后直接传 bytes，orjson
    原生支持，省去每行 UTF-8 解码）；"raw" 键保留原始 bytes，仅在跳过
    样例日志时由 SkipLineLogger 懒解码。

    Field mapping (JSONL key -> canonical key):
        evt.num      -> eventno (str)
        evt.rawtime  -> _ns (int ns；旧版同时构造的 "sec.nsec" timestamp 字符串
                        已移除：唯一消费者管道哨兵改用 _ns//1e9，配对/建边
                        早在用 _ns 缓存)
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
        # 旧文本模式（strict UTF-8 readline）对不可解码字节行会中止导入。
        # orjson 对非法 UTF-8 抛的是 JSONDecodeError 而非 UnicodeDecodeError，
        # 因此解析失败时对 bytes 行补一次 strict 解码：不可解码 → 抛
        # UnicodeDecodeError 向上传播中止（与旧行为完全一致）；可解码 →
        # 是真正的坏 JSON 行，按原口径返回 None 跳过。仅解析失败行触发，
        # 真实日志中近乎为零。
        if isinstance(entry, bytes):
            entry.decode("utf-8")
        return None
    if not isinstance(obj, dict):
        return None
    if not _REQUIRED_JSONL_KEY_SET.issubset(obj):
        return None
    try:
        rawtime = int(obj["evt.rawtime"])
        # 解析门禁：非整数 evt.num/evt.latency 在此被跳过（理由不变，
        # 仍为 "Sysdig entry could not be parsed"）；str(int()) 往返已省去，
        # eventno 存原始字符串（唯一消费方 validate 的 int() 已由门禁保证）。
        int(obj["evt.num"])
        latency_ns = int(obj["evt.latency"] or 0)
    except (TypeError, ValueError):
        return None
    direction = str(obj["evt.dir"])
    if direction not in (">", "<"):
        return None
    # 字段值大多是字符串：仅对非字符串（JSON null / int 型 pid 等）才
    # 走 _json_str 的慢路径，避免每行 10+ 次函数调用开销。
    # _ns/_latency_ns 为派生值缓存（见 record_start_ns / record_latency_ns）：
    # parse 时已有整数，直接预存，下游 pairing/handlers 不再重复解析。
    name_v = obj["proc.name"]
    pid_v = obj["proc.pid"]
    cwd_v = obj["proc.cwd"]
    exepath_v = obj["proc.exepath"]
    args_v = obj["evt.args"]
    event_v = obj["evt.type"]
    proc_args_v = obj.get("proc.args")
    l4proto_v = obj.get("fd.l4proto")
    return {
        "raw": entry,
        "eventno": str(obj["evt.num"]),
        "cpu": "0",
        "_ns": rawtime,
        "_latency_ns": latency_ns,
        "process": name_v if isinstance(name_v, str) else _json_str(name_v),
        "pid": pid_v if isinstance(pid_v, str) else _json_str(pid_v),
        "direction": direction,
        "event": event_v if isinstance(event_v, str) else _json_str(event_v),
        "cwd": cwd_v if isinstance(cwd_v, str) else _json_str(cwd_v),
        "latency": str(latency_ns),
        "exepath": exepath_v if isinstance(exepath_v, str) else _json_str(exepath_v),
        "args": args_v if isinstance(args_v, str) else _json_str(args_v),
        "proc_args": proc_args_v if isinstance(proc_args_v, str) else _json_str(proc_args_v),
        "l4proto": l4proto_v if isinstance(l4proto_v, str) else _json_str(l4proto_v),
    }


def parse_timestamp_ns(ts: str) -> int:
    """'sec.nanosec' timestamp string -> integer nanoseconds since epoch."""
    parts = ts.split(".")
    if len(parts) < 2:
        return int(parts[0]) * 1_000_000_000
    return int(parts[0]) * 1_000_000_000 + int(parts[1])


# ----------------------------------------------------------------------
# Record-level derived-value caches
# ----------------------------------------------------------------------
# 记录 dict 由 parse_jsonl_entry 每事件新建、不跨事件复用，因此把纯函数
# 派生值（ns 时间戳、res 字节数、fd/socket 抽取）缓存在私有键上是安全的：
# 同一 args/timestamp 字符串此前被 validate / extract_entities / pairing /
# handlers 反复解析（profile 实测 extract_file_and_socket 每行 ~2.2 次、
# parse_timestamp_ns 每事件 2~4 次）。抽取函数抛 ValueError 时（畸形
# socket 端点）不写缓存，异常照旧向上传播——与改造前跳过口径一致。


def record_start_ns(record: Dict[str, str]) -> int:
    """Cached parse_timestamp_ns(record['timestamp'])。"""
    ns = record.get("_ns")
    if ns is None:
        ns = parse_timestamp_ns(record.get("timestamp", "0.0"))
        record["_ns"] = ns
    return ns


def record_latency_ns(record: Dict[str, str]) -> int:
    """Cached evt.latency -> int ns（非数字回落 0，与配对侧原语义一致）。"""
    value = record.get("_latency_ns")
    if value is None:
        latency_str = record.get("latency", "0")
        value = int(latency_str) if latency_str.lstrip("-").isdigit() else 0
        record["_latency_ns"] = value
    return value


def record_size(record: Dict[str, str]) -> int:
    """Cached extract_size(record['args'])。"""
    value = record.get("_size")
    if value is None:
        value = extract_size(record.get("args", ""))
        record["_size"] = value
    return value


# record_res 的可能值包含 None（= 字段缺失），所以不能用“get 到 None 就重算”
# 的缓存写法，需要一个独立哨兵。
_RES_UNSET = object()


def record_res(record: Dict[str, str]) -> Optional[int]:
    """Cached extract_res(record['args'])；None 表示退出记录里没有 `res=` 字段。"""
    value = record.get("_res", _RES_UNSET)
    if value is _RES_UNSET:
        value = extract_res(record.get("args", ""))
        record["_res"] = value
    return value


def record_failed(record: Dict[str, str]) -> bool:
    """“调用明确失败”（`res=` 存在且为负，或不可解析）。

    只用于“失败则不建边”的 handler（accept/fcntl/connect/bind/rename/
    文件生命周期族/chmod 族）。不能用 record_size(...) == -1 代替：后者把
    “导出格式没给 res”也算失败，会无差别丢弃整类退出记录（accept 就是这个
    问题丢光的）。数据流边（read/write）仍用 record_size，因为那里 res 就是
    bytes 属性，拿不到 res 就不能写边。
    """
    res = record_res(record)
    return res is not None and res < 0


# EINPROGRESS(115)：非阻塞 connect 的正常中间态 —— 连接已发起、四元组已由内核
# 分配，稍后由 poll/getsockopt 完成，语义上不是失败。实测六个场景该返回码只出现
# 在 connect 的退出记录里（45/306/95/248/732/305 条，无一落在其他事件类型），
# 所以例外只给 connect 家族，record_failed 本体与其余 6 处调用不受影响；
# -101 ENETUNREACH / -111 ECONNREFUSED / -2 ENOENT / -13 EACCES 仍是真失败。
_ERRNO_EINPROGRESS = -115


def record_in_progress(record: Dict[str, str]) -> bool:
    """connect 语义下的 EINPROGRESS（已发起、未完成）；复用 record_res 的缓存。"""
    return record_res(record) == _ERRNO_EINPROGRESS


def record_connect_failed(record: Dict[str, str]) -> bool:
    """connect 专用“明确失败”判据 = record_failed 且不是 EINPROGRESS。

    给 connect 单独开一条判据而不是给 record_failed 加例外参数：这样只有
    connect 一家被放宽，chmod/rename 生命周期/accept/bind 等家族保持原语义，
    也便于改前改后做“只有 p2n 计数变化”的等价性归因。
    """
    res = record_res(record)
    if res is None or res >= 0:
        return False
    return res != _ERRNO_EINPROGRESS


def record_file_socket(record: Dict[str, str]) -> Dict[str, str]:
    """Cached extract_file_and_socket(record['args'])（畸形端点时抛出且不缓存）。"""
    file_socket = record.get("_fs")
    if file_socket is None:
        file_socket = extract_file_and_socket(record.get("args", ""))
        record["_fs"] = file_socket
    return file_socket


def validate_parsed_entry(record: Dict[str, str]) -> None:
    """Validate a canonical record; raise ValueError with the exact skip
    reason if it cannot produce graph elements.

    parse_jsonl_entry 构造时已保证：14 个规范键齐全、eventno/latency 可 int、
    direction ∈ {>, <}——这些在旧版这里的重复检查是不可达死代码，已删除
    （计数等价已验证）。仍需在此检查的：
    无进程上下文（pid/name 是否为 null 只有 parse 的结果能回答），以及
    args 抽取触发（畸形 fd/socket 在此计入跳过统计，而非深层建边时失败）。
    """
    # 无进程上下文的记录（proc.pid/proc.name 为 JSON null，典型如内核调度
    # switch 事件）：无法归属到任何进程，永远不会产生边，只会堆积为永不
    # 配对的 pending。按精确理由跳过，保持跳过统计可审计。
    if not record["pid"] or not record["process"]:
        raise ValueError(
            "Record has no process context (proc.pid/proc.name is null)"
        )

    # 顺手触发 args 抽取器，让畸形 fd/socket 字段在这里（计入跳过统计）
    # 而不是在深层建边时失败；结果缓存复用（见上方缓存说明）。
    record_file_socket(record)
    record_size(record)
