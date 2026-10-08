"""顶点表（第 1 层唯一一份顶点判据，内容在 `rules/vertices.json`）。

分两段，共用一张表、一个加载器：

- **文件段**：每个文件顶点三种角色之一——`deliver`（普通交付对象）、`system`（系统提供的文件与
  程序）、`nondelivery`（非交付通道）。闭包、范围过滤、例行剔除都读这一段。
- **进程段**：每个进程三类之一——`resident`（常驻系统进程）、`shell`、`command`（其余）。
  子进程把关的写读配对、范围过滤的会话边界、例行剔除的属主类别共用这一段。

进程标识 = 进程号 + 进程名（`process_name` 取名，`num_prefix` 取号）。
"""

from __future__ import annotations

import re
from typing import NamedTuple

from . import rules

_TABLE = rules.load("vertices.json")
_FILES = _TABLE["files"]
_PROCESSES = _TABLE["processes"]


class Role(NamedTuple):
    """一个文件键的角色判定结果：角色、类别名（非交付通道用于计数）、读边是否收、对象类别。"""

    role: str
    label: str
    drop_reads: bool
    cls: str


_ENTRIES: list[tuple[str, str, bool, str, tuple[re.Pattern[str], ...], tuple[str, ...]]] = []
for _item in _FILES["roles"]:
    _ENTRIES.append((
        str(_item["role"]), str(_item.get("label") or ""), bool(_item.get("drop_reads")),
        str(_item.get("class") or ""),
        tuple(re.compile(str(pattern)) for pattern in _item.get("regexes") or ()),
        tuple(str(prefix) for prefix in _item.get("prefixes") or ()),
    ))

_DEFAULT = Role(str(_FILES.get("default_role") or "deliver"), "", False, "")

_RESIDENT = frozenset(str(name) for name in _PROCESSES["resident"])
_SHELL = frozenset(str(name) for name in _PROCESSES["shell"])


# --------------------------------------------------------------------------- #
# 文件段
# --------------------------------------------------------------------------- #

def file_role(key: str) -> Role:
    """这个文件键的角色判定（按表顺序取第一个命中）。"""
    for role, label, drop_reads, cls, regexes, prefixes in _ENTRIES:
        if prefixes and key.startswith(prefixes):
            return Role(role, label, drop_reads, cls)
        for pattern in regexes:
            if pattern.match(key):
                return Role(role, label, drop_reads, cls)
    return _DEFAULT


def is_nondelivery(key: str) -> bool:
    """是不是非交付通道（写边不收、不展开、不算配对）。"""
    return file_role(key).role == "nondelivery"


def nondelivery_label(key: str) -> str:
    """非交付通道的类别名（只用于计数与报告）；不是非交付通道返回空串。"""
    record = file_role(key)
    return record.label if record.role == "nondelivery" else ""


def drops_reads(key: str) -> bool:
    """这个对象上的读边要不要连边都不收（只对"内核按进程号现生成的伪文件"为真）。"""
    return file_role(key).drop_reads


def no_handoff(key: str) -> bool:
    """范围过滤里不做"产物交接"追溯的对象（系统提供的文件、非交付通道）。"""
    return file_role(key).role != "deliver"


def object_class(key: str, label: str = "") -> str:
    """对象类别（输出期例行活动剔除用）：进程、网络端点、管道、设备、内核伪文件、系统运行目录、
    系统文件、系统级套接字、其它路径、其它。

    `label` 是另一端的顶点标签（`File` / `Network` / `Process`）：
    - `Process`：进程不是对象，返回 `process`——派生边不参与这张按对象类别写的表；
    - `Network`：直接认定为网络端点，不再看标识串里有没有箭头（文件路径里恰好带箭头时会被认错）；
    - `File` 或未给标签（旧调用方）：按路径查表；未给时退化为看箭头。
    管道是形状判据，先于查表。
    """
    if label == "Process":
        return "process"
    if label == "Network":
        return "network"
    if key.startswith("pipe:["):
        return "pipe"
    if not label and "->" in key:
        return "network"
    record = file_role(key)
    if record.cls:
        return record.cls
    return "other_path" if key.startswith("/") else "other"


# --------------------------------------------------------------------------- #
# 进程段
# --------------------------------------------------------------------------- #

def process_name(process_id: str) -> str:
    """进程标识 = 进程号 + 进程名；取名部分（进程号是前导数字）。"""
    return str(process_id).lstrip("0123456789")


def num_prefix(process_id: str) -> str:
    """取进程标识里的进程号部分。"""
    pid = str(process_id)
    return pid[: len(pid) - len(process_name(pid))]


def process_class(process_id: str) -> str:
    """属主类别：resident（常驻系统进程）/ shell / command。"""
    name = process_name(process_id)
    if name in _RESIDENT:
        return "resident"
    if name in _SHELL:
        return "shell"
    return "command"
