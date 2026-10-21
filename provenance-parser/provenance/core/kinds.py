"""领域词汇：所有层共享的枚举、节点主键与序列化规则。

这一层不 import 任何其它项目模块，只依赖标准库。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class EdgeClass(str, Enum):
    """五类关系，设计文档 §3.1。

    关系类型只表达"两端是哪种顶点"，不表达数据流向（普通 IP 的 ``connect`` 落在
    ProcessToNetwork，unix 域套接字的同名 ``connect`` 落在 ProcessToFile）；
    具体动作由边属性 ``action`` 给出。名字里直接写两端顶点类型，读图时不必查表。
    """

    P2P = "ProcessToProcess"
    P2F = "ProcessToFile"
    F2P = "FileToProcess"
    P2N = "ProcessToNetwork"
    N2P = "NetworkToProcess"


class Bucket(str, Enum):
    """行级账本的 13 个桶，互斥且穷尽。

    ``COLLECTOR_BLIND`` 与 ``UNMAPPED`` 必须分开：前者是采集端不报事件名
    （无法处理，只能等升级），后者是采集端报了名字但账本表没登记（改代码
    就能修）。混在一起会让「该修代码」和「该换采集端」变成同一个数字。
    """

    COVERED = "边覆盖"
    ATTR = "属性更新"
    ATTEMPT = "尝试未成立"
    UNMAPPED = "未归类"
    COLLECTOR_BLIND = "采集端盲区"
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
    BLIND = "blind"
    UNMAPPED = "unmapped"


class ObjSource(str, Enum):
    """客体从哪里取。"""

    FD = "fd"
    PATH = "path"
    PID = "pid"
    TUPLE = "tuple"
    NONE = "none"


class FileKind(str, Enum):
    """``:File`` 节点的角色枚举。

    只保留图上真实存在的类型。匿名 IPC（``event`` / ``timerfd`` /
    ``signalfd`` / ``inotify`` / ``eventpoll`` / ``netlink`` / ``bpf``）没有可区分
    名字，按 R3 不建节点，因此**不设枚举值**——不设比折叠成一个 ``special``
    更诚实：后者会让人以为这些类型被处理了。

    ``MEMFD`` 单独保留：memfd 没有文件系统路径，但 ``memfd_create`` 的名字
    是调用者给的（``<m>payload``），是 fileless 载荷的唯一身份线索。
    """

    FILE = "file"
    DIRECTORY = "directory"
    PIPE = "pipe"
    UNIX = "unix"
    MEMFD = "memfd"
    UNKNOWN = "unknown"


#: 明确不建 :File 节点的 fd 类型（非网络，纯粹是无可区分名字）
NO_NODE_FD_KINDS = frozenset(
    {"event", "timerfd", "signalfd", "inotify", "eventpoll",
     "netlink", "bpf", "other"}
)


def file_kind_of(value: str | None) -> FileKind | None:
    """fd 类型 / 路径事件 -> File.kind。

    返回 ``None`` 表示「不建 :File 节点」：网络套接字，以及匿名 IPC。
    """
    if not value:
        return FileKind.UNKNOWN
    if value in ("ipv4", "ipv6"):
        return None
    try:
        return FileKind(value)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ProcKey:
    host_id: str
    container_id: str
    pid: int
    start_ns: int


@dataclass(frozen=True, slots=True)
class FileKey:
    host_id: str
    container_id: str
    path: str


@dataclass(frozen=True, slots=True)
class NetKey:
    host_id: str
    endpoints: str


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
        return [key.host_id, key.container_id, key.pid, key.start_ns]
    if isinstance(key, FileKey):
        return [key.host_id, key.container_id, key.path]
    return [key.host_id, key.endpoints]


def key_cells(key: NodeKey) -> list[str]:
    """CSV 里的主键列：label + 5 个占位。"""
    if isinstance(key, ProcKey):
        return ["Process", key.host_id, key.container_id, str(key.pid), str(key.start_ns), ""]
    if isinstance(key, FileKey):
        return ["File", key.host_id, key.container_id, "", "", key.path]
    return ["Network", key.host_id, "", "", "", key.endpoints]
