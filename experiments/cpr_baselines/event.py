"""统一事件数据模型与系统调用语义分类契约。

用于标准化各种输入源（Sysdig SCAP 二进制、JSONL 文本、Neo4j 导出数据）中的系统调用事件，
为所有基线图压缩算法提供严格一致的数据结构输入。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Set


class EntityKind(str, Enum):
    """图顶点实体类型定义。"""
    PROCESS = "Process"
    FILE = "File"
    NETWORK = "Network"


class ActionKind(str, Enum):
    """溯源图边的基础动作分类。"""
    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    FORK = "FORK"
    CONNECT = "CONNECT"
    OTHER = "OTHER"


# Linux 读取类系统调用集合 (CONSUME 语义：进程从实体输入信息)
READ_SYSCALLS: Set[str] = frozenset({
    "read", "pread", "pread64", "readv", "preadv",
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "open", "openat", "openat2",
    "mmap",
    "access", "faccessat", "faccessat2",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "getdents", "getdents64",
})

# Linux 写入类系统调用集合 (PRODUCE 语义：进程向实体输出/修改信息)
WRITE_SYSCALLS: Set[str] = frozenset({
    "write", "pwrite", "pwrite64", "writev", "pwritev",
    "send", "sendto", "sendmsg", "sendmmsg",
    "creat",
    "truncate", "ftruncate",
    "rename", "renameat", "renameat2",
    "unlink", "unlinkat",
    "rmdir",
    "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "fchownat",
})

# 进程生命周期与派生系统调用
PROCESS_LIFECYCLE_SYSCALLS: Set[str] = frozenset({
    "clone", "clone3", "fork", "vfork",
    "execve", "execveat",
    "exit", "exit_group",
    "wait4", "waitid",
})


@dataclass(frozen=True)
class TraceEvent:
    """标准系统调用因果事件。

    字段说明：
    - host_id: 宿主机标识，多主机命名空间前缀
    - ts_ns: 事件发生的时间戳，单位纳秒 (ns)
    - src_id: 源实体物理唯一标识（进程为 host_id:pid:start_ns，文件为 host_id:file_path）
    - src_kind: 源实体类型 (Process, File, Network)
    - syscall: 系统调用名称 (如 read, write, openat, execve 等)
    - dst_id: 目标实体物理唯一标识
    - dst_kind: 目标实体类型 (Process, File, Network)
    - result: 系统调用返回值，>= 0 表示成功，< 0 表示失败返回错误码
    - bytes_count: 读写传输字节数，默认为 0
    - event_id: 全局递增事件唯一序号
    - extra: 附加元数据字典 (如 exe 路径、cmdline 等)
    """
    host_id: str
    ts_ns: int
    src_id: str
    src_kind: EntityKind
    syscall: str
    dst_id: str
    dst_kind: EntityKind
    result: int = 0
    bytes_count: int = 0
    event_id: int = 0
    extra: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    @property
    def is_success(self) -> bool:
        """判定该系统调用是否成功执行。"""
        return self.result >= 0

    @property
    def is_read(self) -> bool:
        """判定该系统调用是否属于读取操作 (进程从外部实体读入数据)。"""
        return self.syscall.lower() in READ_SYSCALLS

    @property
    def is_write(self) -> bool:
        """判定该系统调用是否属于写入操作 (进程向外部实体写入数据)。"""
        return self.syscall.lower() in WRITE_SYSCALLS

    @property
    def is_process_creation(self) -> bool:
        """判定该系统调用是否属于进程衍生或执行。"""
        return self.syscall.lower() in PROCESS_LIFECYCLE_SYSCALLS

    @property
    def causal_src_id(self) -> str:
        """根据数据因果流动公理决定的真实源顶点 (读操作为客体，写操作为主体)。"""
        return self.dst_id if self.is_read else self.src_id

    @property
    def causal_src_kind(self) -> EntityKind:
        return self.dst_kind if self.is_read else self.src_kind

    @property
    def causal_dst_id(self) -> str:
        """根据数据因果流动公理决定的真实目标顶点 (读操作为主体，写操作为客体)。"""
        return self.src_id if self.is_read else self.dst_id

    @property
    def causal_dst_kind(self) -> EntityKind:
        return self.src_kind if self.is_read else self.dst_kind

    @property
    def action_kind(self) -> ActionKind:
        """映射得到统一动作类型。"""
        sc = self.syscall.lower()
        if sc in READ_SYSCALLS:
            return ActionKind.READ
        if sc in WRITE_SYSCALLS:
            return ActionKind.WRITE
        if sc in {"execve", "execveat"}:
            return ActionKind.EXEC
        if sc in {"clone", "clone3", "fork", "vfork"}:
            return ActionKind.FORK
        if sc in {"connect", "accept", "accept4"}:
            return ActionKind.CONNECT
        return ActionKind.OTHER


@dataclass
class CompressedEdge:
    """压缩后保留或聚合生成的因果图边。"""
    src_id: str
    src_kind: EntityKind
    syscall: str
    action: ActionKind
    dst_id: str
    dst_kind: EntityKind
    start_ns: int
    end_ns: int
    instances: int = 1
    total_bytes: int = 0
    success_count: int = 1
    fail_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def edge_key(self) -> str:
        """边的唯一标识主键。"""
        return f"{self.src_id}->[{self.action.value}:{self.syscall}]->{self.dst_id}"
