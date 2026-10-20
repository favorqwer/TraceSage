"""13 列模板解码：一行 sysdig 输出 -> EventRow / BadRow。"""

from __future__ import annotations

from ...core import args as A
from ...core.events import BadRow, EventRow

# 13 列（含 %container.id）。最后一列 proc.args 吸收制表符。
FIELDS = (
    "%evt.num",
    "%evt.rawtime",
    "%evt.dir",
    "%evt.type",
    "%proc.pid",
    "%thread.tid",
    "%container.id",
    "%proc.exe",
    "%proc.cwd",
    "%proc.ppid",
    "%user.uid",
    "%evt.args",
    "%proc.args",
)
TEMPLATE = "\t".join(FIELDS)
COLUMNS = len(FIELDS)

AUDIT_ALL_TEMPLATE = "%evt.num\t%evt.type"
AUDIT_PID_TEMPLATE = "%evt.num\t%evt.type\t%proc.pid"
CONTAINER_TEMPLATE = (
    "%container.id\t%container.name\t%container.image\t"
    "%container.privileged\t%container.mounts"
)


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

    def txt(idx: int) -> str:
        return parts[idx].decode("utf-8", "replace")

    num = int(parts[0])
    ns = ns_of(txt(1))
    direction = txt(2)
    call = txt(3)
    if direction not in (">", "<"):
        raise ValueError(f"方向非法：{direction!r}")
    if not call:
        raise ValueError("调用名为空")

    return EventRow(
        num=num,
        ns=ns,
        direction=direction,
        call=call,
        pid=int(parts[4]) if parts[4] else 0,
        tid=int(parts[5]) if parts[5] else 0,
        container_id=txt(6) or "host",
        exe=txt(7),
        cwd=txt(8),
        ppid=int(parts[9]) if parts[9] else 0,
        ruid=txt(10),
        cmdline=txt(12),
        args=A.parse(txt(11)),
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
