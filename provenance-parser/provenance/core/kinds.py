"""领域词汇：所有层共享的枚举、节点主键与序列化规则。

这一层不 import 任何其它项目模块，只依赖标准库。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class EdgeClass(str, Enum):
    """五类边，设计文档 §3.1。"""

    P2P = "p2p"
    P2F = "p2f"
    F2P = "f2p"
    P2N = "p2n"
    N2P = "n2p"


class Bucket(str, Enum):
    """行级账本的 12 个桶（§6-1），互斥且穷尽。"""

    COVERED = "边覆盖"
    ATTR = "属性更新"
    ATTEMPT = "尝试未成立"
    UNMAPPED = "未归类"
    HANDLE = "仅句柄"
    UNKNOWN_FD = "未知句柄"
    NO_OBJECT = "无客体"
    DROP = "显式丢弃"
    UNPAIRED = "未配对"
    NO_OWNER = "无进程归属"
    ABNORMAL = "异常行"
    OTHER = "其他"


class Verdict(str, Enum):
    """分类结论（§4.1）：调用名的去处。"""

    EMIT = "emit"
    OPS = "ops"
    DROP = "drop"
    HANDLE = "handle"
    ATTR = "attr"
    UNMAPPED = "unmapped"


class ObjSource(str, Enum):
    """客体从哪里取。"""

    FD = "fd"
    PATH = "path"
    PID = "pid"
    TUPLE = "tuple"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ProcKey:
    host_id: str
    container_id: str
    pid: int
    born_ns: int


@dataclass(frozen=True, slots=True)
class FileKey:
    host_id: str
    container_id: str
    path: str


@dataclass(frozen=True, slots=True)
class NetKey:
    host_id: str
    tuple: str


NodeKey = ProcKey | FileKey | NetKey


def label_of(key: NodeKey) -> str:
    if isinstance(key, ProcKey):
        return "Process"
    if isinstance(key, FileKey):
        return "File"
    return "Network"


def key_tuple(key: NodeKey) -> list[Any]:
    """Neo4j 参数里的主键形态（Process 4 段 / File 3 段 / Network 2 段）。"""
    if isinstance(key, ProcKey):
        return [key.host_id, key.container_id, key.pid, key.born_ns]
    if isinstance(key, FileKey):
        return [key.host_id, key.container_id, key.path]
    return [key.host_id, key.tuple]


def key_cells(key: NodeKey) -> list[str]:
    """CSV 里的主键列：label + 5 个占位。"""
    if isinstance(key, ProcKey):
        return ["Process", key.host_id, key.container_id, str(key.pid), str(key.born_ns), ""]
    if isinstance(key, FileKey):
        return ["File", key.host_id, key.container_id, "", "", key.path]
    return ["Network", key.host_id, "", "", "", key.tuple]
