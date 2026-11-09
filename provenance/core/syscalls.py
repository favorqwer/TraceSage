"""系统调用家族名（canonical syscall）。

边的 ``syscall`` 属性使用家族基本名，便于跨同族变体查询/评分；
原始 ``evt.type`` 不落图，用 ``evt`` 回原始日志核对。

例如：
    pread/preadv/preadv2  -> read
    sendmsg/sendmmsg      -> sendto
    renameat/renameat2    -> rename
    mkdirat               -> mkdir
    openat/openat2/creat  -> open
    fork/vfork/clone3     -> clone

本模块是纯函数，不依赖其它项目模块。
"""

from __future__ import annotations

# open 家族必须走 O_CREAT/O_TRUNC/O_TMPFILE 分流，不允许在分类表里重复登记。
OPEN_FAMILY = frozenset({"open", "openat", "openat2", "open64", "openat64"})
# creat 天然等价 O_CREAT。
CREATE_ALWAYS = frozenset({"creat"})

CANONICAL_SYSCALLS: dict[str, str] = {
    # 读家族
    "readv": "read",
    "pread": "read",
    "pread64": "read",
    "preadv": "read",
    "preadv2": "read",
    # 写家族
    "writev": "write",
    "pwrite": "write",
    "pwrite64": "write",
    "pwritev": "write",
    "pwritev2": "write",
    # 网络收发家族
    "send": "sendto",
    "sendmsg": "sendto",
    "sendmmsg": "sendto",
    "recv": "recvfrom",
    "recvmsg": "recvfrom",
    "recvmmsg": "recvfrom",
    # 打开家族
    "openat": "open",
    "openat2": "open",
    "open64": "open",
    "openat64": "open",
    "creat": "open",
    # 文件生命周期家族
    "renameat": "rename",
    "renameat2": "rename",
    "unlinkat": "unlink",
    "mkdirat": "mkdir",
    "mknodat": "mknod",
    "linkat": "link",
    "symlinkat": "symlink",
    "fchmod": "chmod",
    "fchmodat": "chmod",
    "fchmodat2": "chmod",
    # 进程/网络/卸载家族
    "fork": "clone",
    "vfork": "clone",
    "clone3": "clone",
    "accept4": "accept",
    "execveat": "execve",
    "exit_group": "exit",
    "tgkill": "kill",
    "tkill": "kill",
    "pidfd_send_signal": "kill",
    "umount2": "umount",
    "sendfile64": "sendfile",
    "mmap2": "mmap",
}


def canonical_syscall(name: str) -> str:
    """原始 evt.type -> 边 syscall 属性用的家族基本名。"""
    return CANONICAL_SYSCALLS.get(name, name)
