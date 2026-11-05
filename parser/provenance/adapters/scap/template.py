"""主趟与容器模板：解码、`<NA>` 处理、续行判断。

主趟使用 ``*`` 前缀：条件字段缺失时输出 ``<NA>``，不会整行消失。
当前主趟 16 列：在 13 列基础上加 ``%proc.exepath``、``%evt.rawres``、
``%evt.latency``、``%evt.buffer``。
容器预扫使用带序号的挂载字段，复合串 ``%container.mounts`` 只做兜底。
"""

from __future__ import annotations

from ...core import args as A
from ...core.events import BadRow, EventRow

FIELDS = (
    "%evt.num",
    "%evt.rawtime",
    "%evt.dir",
    "%evt.type",
    "%proc.pid",
    "%thread.tid",
    "%container.id",
    "%proc.exepath",
    "%proc.cwd",
    "%proc.ppid",
    "%user.uid",
    "%evt.args",
    "%proc.args",
    "%evt.rawres",
    "%evt.latency",
    "%evt.buffer",
)
TEMPLATE = "\t".join(FIELDS)
STAR_TEMPLATE = "*" + TEMPLATE
COLUMNS = len(FIELDS)
NA = "<NA>"
FIELD_NAMES = tuple(field.lstrip("%") for field in FIELDS)

# ------------------------------------------------------------------ 容器元数据

MOUNT_SLOTS = 16
CONTAINER_HEADER = (
    "%evt.num",
    "%container.id",
    "%container.name",
    "%container.image",
    "%container.privileged",
)
CONTAINER_MOUNT_ATTRS = ("source", "dest", "rdwr", "mode", "propagation")
CONTAINER_MOUNT_FIELDS = tuple(
    f"%container.mount.{attr}[{i}]"
    for i in range(MOUNT_SLOTS)
    for attr in CONTAINER_MOUNT_ATTRS
)
CONTAINER_TEMPLATE = "*" + "\t".join(
    CONTAINER_HEADER + CONTAINER_MOUNT_FIELDS + ("%container.mounts",)
)
CONTAINER_MOUNT_START = len(CONTAINER_HEADER)
CONTAINER_MOUNT_STRIDE = len(CONTAINER_MOUNT_ATTRS)
CONTAINER_MOUNTS_INDEX = CONTAINER_MOUNT_START + MOUNT_SLOTS * CONTAINER_MOUNT_STRIDE


def ns_of(raw: str) -> int:
    """`%evt.rawtime` 是 秒.纳秒 或纯纳秒，两种都吃。"""
    text = raw.strip()
    if not text:
        return 0
    if "." in text:
        sec, frac = text.split(".", 1)
        frac = (frac + "000000000")[:9]
        return int(sec) * 1_000_000_000 + int(frac)
    return int(text)


def _na_fields(parts: list[str]) -> frozenset[str]:
    """只有真的出现 <NA> 时才建集合（整行解码只做一次，多数行无需组装）。"""
    if NA not in parts:
        return frozenset()
    return frozenset(FIELD_NAMES[i] for i, value in enumerate(parts) if value == NA)


def decode(line: bytes, host_id: str = "") -> EventRow:
    """整行只解码一次，再按 \\t 切列。

    旧实现对 16 个字段各调一次 ``txt()``（每行 16 次 bytes.decode + 16 次函数
    调用）；现在换成 1 次整行 decode + 1 次 str.split，字段语义与 <NA> 口径不变。
    """
    text = line.decode("utf-8", "replace")
    if text.endswith("\n"):
        text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
    parts = text.split("\t")
    if len(parts) < COLUMNS:
        raise ValueError(f"列数不足：{len(parts)} < {COLUMNS}")
    if len(parts) > COLUMNS:
        parts = parts[: COLUMNS - 1] + ["\t".join(parts[COLUMNS - 1 :])]

    num_text = parts[0]
    rawtime_text = parts[1]
    direction = parts[2]
    call = parts[3]
    if not num_text or num_text == NA:
        raise ValueError("事件号缺失")
    if not rawtime_text or rawtime_text == NA:
        raise ValueError("事件时间缺失")
    if direction not in (">", "<"):
        raise ValueError(f"方向非法：{direction!r}")
    if not call or call == NA:
        raise ValueError("调用名为空")

    pid_text = parts[4]
    pid = 0 if pid_text == NA or not pid_text else int(pid_text)
    container_id = parts[6]
    if container_id == NA or not container_id:
        # pid 缺失的 switch 行没有容器，归 host 即可（随后会进 NO_OWNER）。
        # 有 pid 却没有容器，说明这一行无法可靠归属，计异常行而不是猜 host。
        if pid > 0:
            raise ValueError("container.id 缺失")
        container_id = "host"

    tid_text = parts[5]
    ppid_text = parts[9]
    ruid_text = parts[10]
    args_text = parts[11]
    proc_args_text = parts[12]
    rawres_text = parts[13]
    latency_text = parts[14]
    exe_text = parts[7]
    cwd_text = parts[8]
    buffer_text = parts[15]
    return EventRow(
        num=int(num_text),
        ns=ns_of(rawtime_text),
        direction=direction,
        call=call,
        pid=pid,
        tid=0 if tid_text == NA or not tid_text else int(tid_text),
        container_id=container_id,
        exe="" if exe_text == NA else exe_text,
        cwd="" if cwd_text == NA else cwd_text,
        ppid=0 if ppid_text == NA or not ppid_text else int(ppid_text),
        ruid="" if ruid_text == NA else ruid_text,
        proc_args="" if proc_args_text == NA else proc_args_text,
        args=A.parse("" if args_text == NA else args_text),
        rawres=A.int_of(rawres_text) if rawres_text and rawres_text != NA else None,
        latency_ns=A.int_of(latency_text) if latency_text and latency_text != NA else None,
        buffer_b64="" if buffer_text == NA else buffer_text,
        na_fields=_na_fields(parts),
    )


def is_record_start(line: bytes) -> bool:
    """续行（字段内含换行被 
sysdig 折行）不以"纯数字 + \\t"开头。"""
    tab = line.find(b"\t")
    if tab <= 0:
        return False
    return line[:tab].isdigit()


def decode_one(line: bytes, host_id: str = "") -> EventRow | BadRow:
    try:
        return decode(line, host_id)
    except Exception as exc:
        return BadRow(0, type(exc).__name__, line[:200].decode("utf-8", "replace"))


def as_bytes(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        return raw
    return raw.encode("utf-8", "replace")


def container_na(value: str) -> str:
    return "" if value == NA else value
