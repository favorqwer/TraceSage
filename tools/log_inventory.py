#!/usr/bin/env python3
"""全量日志信息清单（raw JSONL -> inventory JSON）。

目的
----
把一份 Sysdig JSONL 里**所有可统计的信息**完整落成一份确定性 JSON，作为
"解析器到底从日志里提取了什么 / 丢掉了什么"的参照基线。后续想往 Neo4j 里
增加顶点/边/属性/系统调用时，先跑本工具，再和 `tools/db_inventory.py` 的
图侧清单做差，就能直接看到缺口。

三条不遗漏的保证
----------------
1. **维度从数据里长出来**：顶层 JSON 键、`evt.args` 参数名、fd 类型符、errno
   名、注解枚举名全部是扫描出来的 Counter，不依赖任何预置清单；采集格式串
   以后加字段，重扫即可自动出现。
2. **`evt.args` 分段自证**：每个空格分隔的 token 必须归入三类之一——
   `pair`（`k=v`）、`continuation`（无 `=`，是前一个键的多 token 取值）、
   `data_payload`（`data=` 之后的载荷，按整体统计长度而不解析内部字段）。
   `accounting.unclassified` 必须为 0，否则输出原始样本。
3. **高基数不静默丢弃**：值集合能全枚举就全枚举；超过 `--value-cap` 则标记
   `capped=true` 并保留 TopN，而不是假装统计过了。

已知边界（在输出里显式记录，不算遗漏）
------------------------------------
- `data=` 载荷是内核/应用二进制内容，按"不透明值"处理：统计条数、总字节、
  长度直方图、是否含空格/等号，但不枚举载荷内部的伪 `k=v`（已在实测中确认
  载荷里会出现 `lang=`/`TTY=`/`viewBox=` 这类假字段）。
- `evt.rawtime`/`evt.latency`/`evt.num` 是高基数整数，只做 min/max/连续性，
  不枚举值集合。

用法
----
    python tools/log_inventory.py input/sysdig/1_Multi_Stage_Data_Exfiltration.jsonl \
        -o output/inventory/1_Multi_Stage_Data_Exfiltration.log-inventory.json
    python tools/log_inventory.py <file> -o out.json --max-lines 2000000
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import orjson
except ImportError:  # pragma: no cover
    orjson = None

TOOL_VERSION = 2

# ---------------------------------------------------------------- 常量/正则
_EXPECTED_JSONL_KEYS = (
    "evt.num", "evt.rawtime", "evt.dir", "evt.type", "evt.args", "evt.latency",
    "proc.pid", "proc.name", "proc.exepath", "proc.cwd", "proc.args", "fd.l4proto",
)
# 顶层 JSON 键里不做值枚举的（高基数整数；evt.num 另做连续性分析）
_NO_ENUM_JSON_KEYS = frozenset({"evt.rawtime", "evt.latency", "evt.num", "evt.args"})

_PAIR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)=(.*)$")
_ANNOT_RE = re.compile(r"^(-?\d+)\(([^()]*)\)$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]{6,32}$")
_HEX_ANY_RE = re.compile(r"^(?:0[xX])?[0-9A-Fa-f]{6,32}$")
_FD_KEY_RE = re.compile(r"^(?:fd\d*|dirfd|oldfd|newfd|sockfd)$")
_FD_VALUE_RE = re.compile(r"^(-?\d+)(?:\((.*)\))?$", re.S)
_FD_MASK_RE = re.compile(r"^\d+:[a-z]+\d+$")
_QUAD_RE = re.compile(r"^[0-9.]{7,}:\d+->[0-9.]{7,}:\d+$")
_ERRNO_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
_LEN_HIST_BUCKETS = (0, 8, 32, 128, 512, 2048, 8192)
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


def _otrunc(s: str, n: int = 600) -> str:
    return s if len(s) <= n else s[:n] + f"...<+{len(s) - n} chars>"


def _sorted_counter(c: Counter, limit: Optional[int] = None) -> Dict[str, int]:
    items = sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0])))
    if limit is not None:
        items = items[:limit]
    return {str(k): v for k, v in items}


class ValueStats:
    """单个字符串键的取值统计：频次、形态、注解词汇、枚举/TopN。"""

    def __init__(self, cap: int, list_cap: int) -> None:
        self.count = 0
        self.null = 0
        self.empty = 0
        self.int_count = 0
        self.nonstr = 0
        self.len_min: Optional[int] = None
        self.len_max = 0
        self.len_sum = 0
        self.forms: Counter = Counter()
        self.annotations: Counter = Counter()
        self.values: Counter = Counter()
        self.capped = False
        self.distinct_seen = 0
        self._cap = cap
        self._list_cap = list_cap

    def add(self, v, track: bool = True, classify: bool = True) -> None:
        self.count += 1
        if type(v) is str:
            if v == "":
                self.empty += 1
                self.forms["empty"] += 1
                return
            n = len(v)
            if self.len_min is None or n < self.len_min:
                self.len_min = n
            if n > self.len_max:
                self.len_max = n
            self.len_sum += n
            if classify:
                self.forms[classify_string(v, self.annotations)] += 1
            if track:
                self._track(v)
        elif type(v) is int:
            self.int_count += 1
            self.forms["int"] += 1
            if self.len_min is None:
                self.len_min = 0
        elif v is None:
            self.null += 1
            self.forms["null"] += 1
        else:
            self.nonstr += 1
            self.forms[f"type:{type(v).__name__}"] += 1

    def _track(self, v: str) -> None:
        if self.capped:
            return
        if v not in self.values:
            if self.distinct_seen >= self._cap:
                self.capped = True
                return
            self.distinct_seen += 1
        self.values[v] += 1

    def to_json(self) -> dict:
        out = {
            "count": self.count,
            "null": self.null,
            "empty": self.empty,
            "int": self.int_count,
            "nonstr": self.nonstr,
            "len_min": self.len_min,
            "len_max": self.len_max,
            "len_sum": self.len_sum,
            "forms": _sorted_counter(self.forms),
            "annotations": _sorted_counter(self.annotations),
            "capped": self.capped,
            "distinct": None if self.capped else len(self.values),
        }
        if self.capped:
            out["values"] = None
            out["top"] = _sorted_counter(self.values, limit=200)
        else:
            out["values"] = _sorted_counter(self.values, limit=self._list_cap)
            out["values_truncated"] = len(self.values) > self._list_cap
        return out


def classify_string(v: str, annotations: Counter) -> str:
    """值形态分类；顺便把括号内注解名收进 annotations（flags/errno/enum）。"""
    c0 = v[0]
    if c0 == "<" and v[-1] == ">":
        return "angle_marker"                      # <NA> / <4t>
    if c0.isdigit() or c0 == "-":
        if v.lstrip("-").isdigit():
            return "int" if c0 != "-" else "neg_int"
        if v[-1] == ")":
            m = _ANNOT_RE.match(v)
            if m:
                inner = m.group(2)
                if inner:
                    for token in inner.split("|"):
                        token = token.strip()
                        if token:
                            annotations[token] += 1
                    return "annot_enum"            # 13377(O_DIRECTORY|...)
                return "annot_num"
    if "->" in v:
        return "quad" if _QUAD_RE.match(v) else "arrow_other"
    if c0 == "/":
        return "abs_path"
    if c0 == "." and len(v) > 1 and v[1] == "/":
        return "rel_path"
    if _FD_MASK_RE.match(v):
        return "fd_mask"                           # poll: 42:e1
    if v[:2] in ("0x", "0X") and _HEX_RE.match(v[2:]):
        return "hex"
    if 6 <= len(v) <= 32 and _HEX_RE.match(v):
        return "hex"                               # 内核地址/十六进制
    if "=" in v:
        return "embedded_eq"
    return "other"


def decompose_fd(value: str) -> Tuple[str, str, str]:
    """fd 取值拆成 (fd号, 类型符, 括号内形态)。

    `3(<u>ffff...->ffff... )` -> ("3", "u", "kernel_arrow")
    `16(<p>)`                 -> ("16", "p", "empty")
    `-100(AT_FDCWD)`          -> ("-100", "(annot)", "at_fdcwd")
    `16`                      -> ("16", "(no-paren)", "no_paren")
    """
    s = value.strip()
    m = _FD_VALUE_RE.match(s)
    if not m:
        return ("?", "(unparsed)", "unparsed")
    num = m.group(1)
    rest = m.group(2)
    if rest is None:
        return (num, "(no-paren)", "no_paren")
    rest = rest.strip()
    if rest == "":
        return (num, "(empty)", "empty")
    if rest[0] == "<":
        close = rest.find(">")
        if close > 0:
            ftype = rest[1:close]
            inner = rest[close + 1:]
            return (num, ftype, classify_fd_inner(inner))
        return (num, "(unterminated)", "unparsed")
    if _ERRNO_RE.match(rest):
        return (num, "(annot)", "annot:" + rest)
    return (num, rest[0], classify_fd_inner(rest[1:]))


def classify_fd_inner(inner: str) -> str:
    s = inner.strip()
    if s == "":
        return "empty"
    if "->" in s:
        head = s.split(" ", 1)[0]
        return "quad" if _QUAD_RE.match(head) else "kernel_arrow"
    if s.startswith("/"):
        return "path"
    if "(" in s:
        return "annotated"
    return "other"


class FdStats:
    def __init__(self) -> None:
        self.count = 0
        self.fd_numbers: Counter = Counter()
        self.types: Counter = Counter()
        self.inner_forms: Counter = Counter()
        self.combos: Counter = Counter()
        self.samples: Dict[str, str] = {}

    def add(self, value: str) -> Tuple[str, str]:
        self.count += 1
        num, ftype, form = decompose_fd(value)
        if ftype == "(unparsed)":
            self.inner_forms["unparsed"] += 1
            self.samples.setdefault("unparsed", _otrunc(value))
            return ftype, form
        self.fd_numbers[num] += 1
        self.types[ftype] += 1
        self.inner_forms[form] += 1
        self.combos[f"type={ftype}/form={form}"] += 1
        self.samples.setdefault(f"type={ftype}/form={form}", _otrunc(value))
        return ftype, form

    def to_json(self) -> dict:
        return {
            "count": self.count,
            "distinct_fd_numbers": len(self.fd_numbers),
            "types": _sorted_counter(self.types),
            "inner_forms": _sorted_counter(self.inner_forms),
            "type_form_combos": _sorted_counter(self.combos),
            "fd_numbers_top": _sorted_counter(self.fd_numbers, limit=50),
            "samples": dict(sorted(self.samples.items())),
        }


# ---------------------------------------------------------------- args 扫描
class ArgsScanner:
    """把 evt.args 切成 (key, value) + 续接 token + data 载荷，并自证无遗漏。"""

    def __init__(self) -> None:
        self.tokens = 0
        self.pairs = 0
        self.continuations = 0
        self.data_payloads = 0
        self.unclassified = 0
        self.unclassified_samples: List[str] = []
        self.continuation_by_key: Counter = Counter()
        self.continuation_with_eq: Counter = Counter()
        self.continuation_values: Dict[str, ValueStats] = {}

    def continuation_stats(self, key: str) -> ValueStats:
        vs = self.continuation_values.get(key)
        if vs is None:
            vs = ValueStats(cap=5_000, list_cap=2_000)
            self.continuation_values[key] = vs
        return vs

    def scan(self, args: str, on_pair, on_data) -> None:
        a = args
        n = len(a)
        i = 0
        prev: Optional[str] = None
        while i < n:
            if a[i] == " ":
                i += 1
                continue
            if a.startswith("data=", i):
                # data 是终止符：剩余整段是载荷；recvmsg/sendmsg 会追加
                # " tuple=<no-space-token>"
                self.tokens += 1
                self.data_payloads += 1
                payload, tuple_val = _split_data_tail(a[i + 5:])
                on_data(payload, tuple_val)
                return
            sp = _token_end(a, i)
            tok = a[i:sp]
            self.tokens += 1
            m = _PAIR_RE.match(tok)
            if m:
                self.pairs += 1
                prev = m.group(1)
                on_pair(prev, m.group(2))
            elif prev is None:
                self.unclassified += 1
                if len(self.unclassified_samples) < 10:
                    self.unclassified_samples.append(_otrunc(a))
            else:
                self.continuations += 1
                self.continuation_by_key[prev] += 1
                if "=" in tok:
                    self.continuation_with_eq[prev] += 1
                self.continuation_stats(prev).add(tok)
            i = sp

    def to_json(self) -> dict:
        return {
            "tokens_seen": self.tokens,
            "pairs": self.pairs,
            "continuations": self.continuations,
            "data_payloads": self.data_payloads,
            "accounted": self.pairs + self.continuations + self.data_payloads,
            "unclassified": self.unclassified,
            "unclassified_samples": self.unclassified_samples,
            "continuation_by_key": _sorted_counter(self.continuation_by_key),
            "continuation_with_eq_by_key": _sorted_counter(self.continuation_with_eq),
            "continuation_values": {
                k: self.continuation_values[k].to_json()
                for k in sorted(self.continuation_values)},
            "note": "unclassified 必须为 0；continuation 是多 token 取值的续接段",
        }


def _token_end(a: str, i: int) -> int:
    """从 token 起点 i 找 token 结束位置。

    括号配平优先：内核对 fd 的注记可含空格（`fd=3(<u>ffff...->ffff... )`、
    `fd=124(<f>/memfd:mozilla-ipc (deleted))`），按空格截断会把值拦腰切断。
    若括号不配平（值里有孤立 `(` 或多余 `)`），回落到第一个空格，避免吞掉
    后续字段。`data=` 由调用方在此之前单独处理。
    """
    n = len(a)
    depth = 0
    j = i
    while j < n:
        c = a[j]
        if c == "(":
            depth += 1
        elif c == ")":
            if depth > 0:
                depth -= 1
            else:
                k = a.find(" ", i)
                return n if k < 0 else k
        elif c == " " and depth == 0:
            return j
        j += 1
    if depth > 0:
        k = a.find(" ", i)
        return n if k < 0 else k
    return n


def _res_form(value: str) -> Tuple[str, Optional[str]]:
    """res= 的成功/失败形态 + errno 名（非 errno 注解返回 None）。"""
    m = _ANNOT_RE.match(value)
    if m:
        num, name = int(m.group(1)), m.group(2)
        if num >= 0:
            return "ok_annot", None
        return "err_annot", (name if _ERRNO_RE.match(name) else None)
    if value.lstrip("-").isdigit():
        return ("err_int" if value.startswith("-") else "ok_int"), None
    if _HEX_ANY_RE.match(value):
        return "ok_hex", None          # mmap/brk 的返回地址
    return "other", None


def _split_data_tail(rest: str) -> Tuple[str, Optional[str]]:
    k = rest.rfind(" tuple=")
    if k >= 0:
        tail = rest[k + len(" tuple="):]
        if " " not in tail.strip():
            return rest[:k], tail.strip()
    return rest, None


class DataPayloadStats:
    def __init__(self) -> None:
        self.lines = 0
        self.total_bytes = 0
        self.max_bytes = 0
        self.hist: Counter = Counter()
        self.with_space = 0
        self.with_eq = 0
        self.tuple_after = 0
        self.samples: List[str] = []

    def add(self, payload: str, tuple_val: Optional[str]) -> None:
        self.lines += 1
        n = len(payload)
        self.total_bytes += n
        if n > self.max_bytes:
            self.max_bytes = n
        for b in _LEN_HIST_BUCKETS:
            if n <= b:
                self.hist[f"<={b}"] += 1
                break
        else:
            self.hist[f">{_LEN_HIST_BUCKETS[-1]}"] += 1
        if " " in payload:
            self.with_space += 1
        if "=" in payload:
            self.with_eq += 1
        if tuple_val is not None:
            self.tuple_after += 1
        if len(self.samples) < 5:
            self.samples.append(_otrunc(payload.replace("\n", "\\n")))

    def to_json(self) -> dict:
        return {
            "lines": self.lines,
            "total_bytes": self.total_bytes,
            "max_bytes": self.max_bytes,
            "length_hist": _sorted_counter(self.hist),
            "with_space": self.with_space,
            "with_eq": self.with_eq,
            "tuple_appended": self.tuple_after,
            "note": "data= 载荷按不透明值处理，不解析内部伪 k=v",
            "samples": self.samples,
        }


# ---------------------------------------------------------------- 主扫描
class Inventory:
    def __init__(self, path: str, cap: int, list_cap: int,
                 sample_per_event: int, progress_every: int) -> None:
        self.path = path
        self.cap = cap
        self.list_cap = list_cap
        self.sample_per_event = sample_per_event
        self.progress_every = progress_every

        self.lines_total = 0
        self.empty = 0
        self.invalid = 0
        self.valid = 0
        self.invalid_samples: List[str] = []

        self.json_keys: Dict[str, ValueStats] = {}
        self.json_key_present: Counter = Counter()

        self.event_enter: Counter = Counter()
        self.event_exit: Counter = Counter()
        self.event_errno: Dict[str, Counter] = defaultdict(Counter)
        self.event_res_form: Dict[str, Counter] = defaultdict(Counter)
        self.event_fd_types: Dict[str, Counter] = defaultdict(Counter)
        self.event_fd_forms: Dict[str, Counter] = defaultdict(Counter)
        self.event_argkey: Dict[str, Counter] = defaultdict(Counter)
        self.samples_by_event: Dict[str, Dict[str, List[str]]] = defaultdict(
            lambda: {"enter": [], "exit": []})

        self.arg_keys: Dict[str, ValueStats] = {}
        self.arg_key_freq: Counter = Counter()
        self.arg_key_enter: Counter = Counter()
        self.arg_key_exit: Counter = Counter()
        self.fd_keys: Dict[str, FdStats] = {}

        self.scanner = ArgsScanner()
        self.data_stats = DataPayloadStats()

        self.num_first: Optional[int] = None
        self.num_last: Optional[int] = None
        self.num_min: Optional[int] = None
        self.num_max: Optional[int] = None
        self.num_gaps: List[List[int]] = []
        self.num_gap_segments = 0
        self.num_max_gap = 0
        self.num_missing_total = 0
        self.num_non_integer = 0
        self.num_out_of_order = 0
        self.time_first: Optional[int] = None
        self.time_last: Optional[int] = None
        self.time_backwards = 0

    def _json_key(self, key: str) -> ValueStats:
        vs = self.json_keys.get(key)
        if vs is None:
            vs = ValueStats(self.cap, self.list_cap)
            self.json_keys[key] = vs
        return vs

    def _arg_key(self, key: str) -> ValueStats:
        vs = self.arg_keys.get(key)
        if vs is None:
            vs = ValueStats(self.cap, self.list_cap)
            self.arg_keys[key] = vs
        return vs

    def _fd_stats(self, key: str) -> FdStats:
        st = self.fd_keys.get(key)
        if st is None:
            st = FdStats()
            self.fd_keys[key] = st
        return st

    def run(self, max_lines: Optional[int]) -> dict:
        t0 = time.time()
        loads = orjson.loads if orjson is not None else json.loads
        scanned = 0
        with open(self.path, "rb", buffering=1 << 20) as fh:
            for raw in fh:
                scanned += 1
                if max_lines is not None and scanned > max_lines:
                    scanned -= 1
                    break
                raw = raw.rstrip(b"\n").rstrip(b"\r")
                if not raw:
                    self.empty += 1
                    continue
                try:
                    o = loads(raw)
                except Exception:
                    self.invalid += 1
                    if len(self.invalid_samples) < 5:
                        self.invalid_samples.append(
                            raw[:200].decode("utf-8", "replace"))
                    continue
                if type(o) is not dict:
                    self.invalid += 1
                    continue
                self.valid += 1
                self._consume(o)
                if self.progress_every and self.valid % self.progress_every == 0:
                    rate = self.valid / max(time.time() - t0, 1e-9)
                    print(f"[inventory] {self.valid:,} lines  {rate:,.0f} lines/s",
                          file=sys.stderr, flush=True)
        self.lines_total = scanned
        return self._to_json(time.time() - t0)

    def _consume(self, o: dict) -> None:
        num = o.get("evt.num")
        if type(num) is int:
            if self.num_min is None or num < self.num_min:
                self.num_min = num
            if self.num_max is None or num > self.num_max:
                self.num_max = num
            if self.num_first is None:
                self.num_first = num
            if self.num_last is not None:
                if num < self.num_last:
                    self.num_out_of_order += 1
                elif num > self.num_last + 1:
                    miss = num - self.num_last - 1
                    self.num_missing_total += miss
                    self.num_gap_segments += 1
                    if miss > self.num_max_gap:
                        self.num_max_gap = miss
                    if len(self.num_gaps) < 20:
                        self.num_gaps.append([self.num_last + 1, num - 1, miss])
            self.num_last = num
        else:
            self.num_non_integer += 1
        ts = o.get("evt.rawtime")
        if type(ts) is int:
            if self.time_first is None:
                self.time_first = ts
            if self.time_last is not None and ts < self.time_last:
                self.time_backwards += 1
            self.time_last = ts

        for key, val in o.items():
            self.json_key_present[key] += 1
            vs = self._json_key(key)
            if key in _NO_ENUM_JSON_KEYS:
                # 不枚举值集合、不做形态分类（evt.args 已结构化拆解；
                # 高基数整数只需计数/长度），避免 distinct 集合撑爆内存
                vs.add(val, track=False, classify=False)
            else:
                vs.add(val)

        etype = o.get("evt.type")
        is_enter = o.get("evt.dir") == ">"
        etype_str = etype if type(etype) is str else None
        if etype_str is not None:
            (self.event_enter if is_enter else self.event_exit)[etype_str] += 1
            smp = self.samples_by_event[etype_str]
            bucket = "enter" if is_enter else "exit"
            if len(smp[bucket]) < self.sample_per_event:
                args0 = o.get("evt.args")
                smp[bucket].append(_otrunc(args0 if type(args0) is str else ""))

        args = o.get("evt.args")
        if type(args) is not str or not args:
            return

        arg_keys = self.arg_keys
        arg_key_freq = self.arg_key_freq
        arg_key_enter = self.arg_key_enter
        arg_key_exit = self.arg_key_exit
        fd_keys = self.fd_keys
        event_argkey = self.event_argkey
        event_fd_types = self.event_fd_types
        event_fd_forms = self.event_fd_forms
        event_res_form = self.event_res_form
        event_errno = self.event_errno
        is_enter_flag = is_enter
        cap = self.cap
        list_cap = self.list_cap

        def on_pair(key: str, value: str) -> None:
            if etype_str is not None:
                event_argkey[etype_str][key] += 1
            arg_key_freq[key] += 1
            vs = arg_keys.get(key)
            if vs is None:
                vs = ValueStats(cap, list_cap)
                arg_keys[key] = vs
            vs.add(value)
            if is_enter_flag:
                arg_key_enter[key] += 1
            else:
                arg_key_exit[key] += 1
            if _FD_KEY_RE.match(key):
                st = fd_keys.get(key)
                if st is None:
                    st = FdStats()
                    fd_keys[key] = st
                ftype, _form = st.add(value)
                if etype_str is not None:
                    event_fd_types[etype_str][ftype] += 1
                    event_fd_forms[etype_str][f"{ftype}/{_form}"] += 1
            elif key == "res":
                form, errno_name = _res_form(value)
                if etype_str is not None:
                    event_res_form[etype_str][form] += 1
                    if errno_name is not None:
                        event_errno[etype_str][errno_name] += 1

        def on_data(payload: str, tuple_val: Optional[str]) -> None:
            if etype_str is not None:
                event_argkey[etype_str]["data"] += 1
            arg_key_freq["data"] += 1
            (arg_key_enter if is_enter_flag else arg_key_exit)["data"] += 1
            self.data_stats.add(payload, tuple_val)
            if tuple_val is not None:
                if etype_str is not None:
                    event_argkey[etype_str]["tuple"] += 1
                arg_key_freq["tuple"] += 1
                (arg_key_enter if is_enter_flag else arg_key_exit)["tuple"] += 1
                vs = arg_keys.get("tuple")
                if vs is None:
                    vs = ValueStats(cap, list_cap)
                    arg_keys["tuple"] = vs
                vs.add(tuple_val)

        self.scanner.scan(args, on_pair, on_data)

    def _to_json(self, elapsed: float) -> dict:
        json_keys = {}
        for k in sorted(self.json_keys):
            vs = self.json_keys[k]
            d = vs.to_json()
            if k in _NO_ENUM_JSON_KEYS:
                d["values"] = None
                d["distinct"] = None
                d["note"] = "高基数/已结构化：不枚举值集合"
            json_keys[k] = d
        arg_keys = {}
        for k in sorted(self.arg_keys):
            d = self.arg_keys[k].to_json()
            d["freq"] = self.arg_key_freq.get(k, 0)
            d["enter"] = self.arg_key_enter.get(k, 0)
            d["exit"] = self.arg_key_exit.get(k, 0)
            arg_keys[k] = d
        for k, freq in self.arg_key_freq.items():
            if k not in arg_keys:
                arg_keys[k] = {"freq": freq, "enter": self.arg_key_enter.get(k, 0),
                               "exit": self.arg_key_exit.get(k, 0), "values": None,
                               "note": "无 ValueStats（仅频次）"}

        events = {}
        for et in sorted(set(self.event_enter) | set(self.event_exit)):
            events[et] = {
                "enter": self.event_enter.get(et, 0),
                "exit": self.event_exit.get(et, 0),
                "res_forms": _sorted_counter(self.event_res_form.get(et, Counter())),
                "errno": _sorted_counter(self.event_errno.get(et, Counter())),
                "arg_keys": _sorted_counter(self.event_argkey.get(et, Counter())),
                "fd_types": _sorted_counter(self.event_fd_types.get(et, Counter())),
                "fd_forms": _sorted_counter(self.event_fd_forms.get(et, Counter())),
            }

        acc = self.scanner.to_json()
        acc["tokens_ok"] = acc["accounted"] == acc["tokens_seen"]
        missing = {}
        for key in _EXPECTED_JSONL_KEYS:
            present = self.json_key_present.get(key, 0)
            if present < self.valid:
                missing[key] = self.valid - present

        return {
            "meta": {
                "tool": "log_inventory",
                "tool_version": TOOL_VERSION,
                "file": self.path,
                "valid_lines": self.valid,
                "value_cap": self.cap,
                "value_list_cap": self.list_cap,
                "scan_seconds": round(elapsed, 1),
                "lines_per_second": round(self.valid / max(elapsed, 1e-9)),
            },
            "completeness": {
                "lines_total": self.lines_total,
                "valid": self.valid,
                "empty": self.empty,
                "invalid_json": self.invalid,
                "sum_check": self.valid + self.empty + self.invalid,
                "invalid_samples": self.invalid_samples,
                "expected_jsonl_keys_missing": missing,
            },
            "evt_num": {
                "first": self.num_first,
                "last": self.num_last,
                "min": self.num_min,
                "max": self.num_max,
                "span": (self.num_max - self.num_min + 1)
                if (self.num_max is not None and self.num_min is not None) else None,
                "missing_total": self.num_missing_total,
                "gap_segments": self.num_gap_segments,
                "max_gap": self.num_max_gap,
                "gap_count": len(self.num_gaps),
                "gaps_first_20": self.num_gaps,
                "out_of_order": self.num_out_of_order,
                "non_integer": self.num_non_integer,
            },
            "time": {
                "first_ns": self.time_first,
                "last_ns": self.time_last,
                "span_s": round((self.time_last - self.time_first) / 1e9, 3)
                if (self.time_first is not None and self.time_last is not None) else None,
                "backwards": self.time_backwards,
            },
            "jsonl_keys": json_keys,
            "events": events,
            "arg_keys": arg_keys,
            "fd_keys": {k: self.fd_keys[k].to_json() for k in sorted(self.fd_keys)},
            "data_payload": self.data_stats.to_json(),
            "accounting": acc,
            "samples_by_event": {k: v for k, v in sorted(self.samples_by_event.items())},
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="Sysdig JSONL file")
    ap.add_argument("-o", "--out", required=True, help="output JSON path")
    ap.add_argument("--max-lines", type=int, default=None, help="只扫前 N 行（试跑）")
    ap.add_argument("--value-cap", type=int, default=500_000,
                    help="单键值集合全枚举上限，超过则只留 TopN")
    ap.add_argument("--value-list-cap", type=int, default=50_000,
                    help="输出里完整值列表的条数上限")
    ap.add_argument("--sample-per-event", type=int, default=3,
                    help="每个 evt.type 保留的进/退原始 args 样本数")
    ap.add_argument("--progress-every", type=int, default=2_000_000)
    args = ap.parse_args()

    if orjson is None:
        print("warning: orjson 未安装，退回标准 json（更慢）", file=sys.stderr)

    inv = Inventory(args.file, args.value_cap, args.value_list_cap,
                    args.sample_per_event, args.progress_every)
    result = inv.run(args.max_lines)
    result["meta"]["max_lines_applied"] = args.max_lines

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True),
                   encoding="utf-8")

    c = result["completeness"]
    acc = result["accounting"]
    print(f"lines={c['valid']:,} empty={c['empty']:,} invalid={c['invalid_json']:,} "
          f"events={len(result['events'])} arg_keys={len(result['arg_keys'])} "
          f"fd_keys={len(result['fd_keys'])} unclassified={acc['unclassified']} "
          f"({result['meta']['scan_seconds']}s) -> {out}")
    if acc["unclassified"] or c["invalid_json"]:
        print("WARNING: 存在未归类 token 或非法 JSON 行，见 JSON 内 samples",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
