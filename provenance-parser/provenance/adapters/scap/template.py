"""主趟与容器模板：解码、`<NA>` 处理、续行判断。

主趟使用 ``*`` 前缀：条件字段缺失时输出 ``<NA>``，不会整行消失。
当前主趟 15 列：在 13 列基础上加 ``%proc.exepath``、``%evt.rawres``、``%evt.buffer``。
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
    "%evt.buffer",
)
TEMPLATE = "\t".join(FIELDS)
STAR_TEMPLATE = "*" + TEMPLATE
COLUMNS = len(FIELDS)
NA = "<NA>"
FIELD_NAMES = tuple(field.lstrip("%") for field in FIELDS)

AUDIT_ALL_TEMPLATE = "%evt.num\t%evt.type"
AUDIT_PID_TEMPLATE = "%evt.num\t%evt.type\t%proc.pid"

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


def decode(line: bytes, host_id: str = "") -> EventRow:
    parts = line.rstrip(b"\r\n").split(b"\t")
    if len(parts) < COLUMNS:
        raise ValueError(f"列数不足：{len(parts)} < {COLUMNS}")
    if len(parts) > COLUMNS:
        parts = parts[: COLUMNS - 1] + [b"\t".join(parts[COLUMNS - 1 :])]

    na: set[str] = set()

    def txt(idx: int) -> str:
        value = parts[idx].decode("utf-8", "replace")
        if value == NA:
            na.add(FIELD_NAMES[idx])
            return ""
        return value

    def integer(idx: int) -> int:
        value = txt(idx)
        return int(value) if value else 0

    num_text = txt(0)
    rawtime_text = txt(1)
    direction = txt(2)
    call = txt(3)
    if not num_text:
        raise ValueError("事件号缺失")
    if not rawtime_text:
        raise ValueError("事件时间缺失")
    if direction not in (">", "<"):
        raise ValueError(f"方向非法：{direction!r}")
    if not call:
        raise ValueError("调用名为空")

    pid = integer(4)
    container_id = txt(6)
    if not container_id:
        # pid 缺失的 switch 行没有容器，归 host 即可（随后会进 NO_OWNER）。
        # 有 pid 却没有容器，说明这一行无法可靠归属，计异常行而不是猜 host。
        if pid > 0:
            raise ValueError("container.id 缺失")
        container_id = "host"

    rawres_text = txt(13)
    return EventRow(
        num=int(num_text),
        ns=ns_of(rawtime_text),
        direction=direction,
        call=call,
        pid=pid,
        tid=integer(5),
        container_id=container_id,
        exe=txt(7),
        cwd=txt(8),
        ppid=integer(9),
        ruid=txt(10),
        proc_args=txt(12),
        args=A.parse(txt(11)),
        rawres=A.int_of(rawres_text) if rawres_text else None,
        buffer_b64=txt(14),
        na_fields=frozenset(na),
    )


def is_record_start(line: bytes) -> bool:
    head = line.split(b"\t", 1)
    return len(head) == 2 and head[0].isdigit()


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
